package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/justusschock/go-auth/authentication"
	"golang.org/x/oauth2"
)

const defaultStateTTL = 10 * time.Minute

// Pending is caller-owned callback state. It intentionally stores only a
// SHA-256 digest of the raw callback state.
type Pending struct {
	Digest       [32]byte
	Provider     string
	RedirectURI  string
	Nonce        string
	PKCEVerifier string
	ExpiresAt    time.Time
}

// StateStore persists callback state and must consume it atomically.
type StateStore interface {
	Put(context.Context, Pending) error
	Consume(context.Context, string) (Pending, error)
}

// MemoryStateStore is a process-local StateStore for tests and single-process
// callers. Distributed deployments should provide their own durable store.
type MemoryStateStore struct {
	mu      sync.Mutex
	pending map[[32]byte]Pending
}

func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{pending: make(map[[32]byte]Pending)}
}

func (s *MemoryStateStore) Put(ctx context.Context, pending Pending) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pending.Digest == [32]byte{} {
		return authentication.ErrInvalidCallback
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[pending.Digest] = pending
	return nil
}

func (s *MemoryStateStore) Consume(ctx context.Context, state string) (Pending, error) {
	if err := ctx.Err(); err != nil {
		return Pending{}, err
	}
	digest := StateDigest(state)
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[digest]
	if !ok {
		return Pending{}, authentication.ErrReplay
	}
	delete(s.pending, digest)
	return pending, nil
}

func StateDigest(state string) [32]byte {
	return sha256.Sum256([]byte(state))
}

type Options struct {
	Name         string
	Issuer       string
	ClientID     string
	Config       oauth2.Config
	Verifier     *coreosoidc.IDTokenVerifier
	RedirectURIs []string
	State        StateStore
	Clock        func() time.Time
	Random       io.Reader
	StateTTL     time.Duration
}

type Provider struct {
	name         string
	issuer       string
	clientID     string
	config       oauth2.Config
	verifier     *coreosoidc.IDTokenVerifier
	redirectURIs map[string]struct{}
	state        StateStore
	clock        func() time.Time
	random       io.Reader
	stateTTL     time.Duration
}

var _ authentication.FederatedProvider = (*Provider)(nil)

func New(options Options) (*Provider, error) {
	name := strings.ToLower(strings.TrimSpace(options.Name))
	issuer := strings.TrimSpace(options.Issuer)
	config := options.Config
	clientID := strings.TrimSpace(options.ClientID)
	if clientID == "" {
		clientID = strings.TrimSpace(config.ClientID)
	}
	if config.ClientID == "" {
		config.ClientID = clientID
	}
	if issuer == "" {
		issuer = issuerFromEndpoint(config.Endpoint.AuthURL)
	}
	if config.Endpoint.AuthURL == "" && issuer != "" {
		config.Endpoint.AuthURL = strings.TrimRight(issuer, "/") + "/authorize"
	}
	if config.Endpoint.TokenURL == "" && issuer != "" {
		config.Endpoint.TokenURL = strings.TrimRight(issuer, "/") + "/token"
	}
	if invalidText(name) || invalidText(issuer) || invalidText(clientID) || options.State == nil || !isHTTPSURL(issuer) {
		return nil, authentication.ErrInvalidCredential
	}
	redirects, err := validateRedirects(options.RedirectURIs)
	if err != nil {
		return nil, err
	}
	if !validServiceURL(config.Endpoint.AuthURL) || !validServiceURL(config.Endpoint.TokenURL) {
		return nil, authentication.ErrInvalidCredential
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	stateTTL := options.StateTTL
	if stateTTL <= 0 {
		stateTTL = defaultStateTTL
	}
	return &Provider{
		name:         name,
		issuer:       issuer,
		clientID:     clientID,
		config:       config,
		verifier:     options.Verifier,
		redirectURIs: redirects,
		state:        options.State,
		clock:        clock,
		random:       random,
		stateTTL:     stateTTL,
	}, nil
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) Begin(ctx context.Context, request authentication.BeginRequest) (authentication.Redirect, error) {
	redirectURI, err := p.allowedRedirect(request.RedirectURI)
	if err != nil {
		return authentication.Redirect{}, err
	}
	state, err := randomSecret(p.random)
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	nonce, err := randomSecret(p.random)
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	verifier, err := randomSecret(p.random)
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	expiresAt := p.clock().UTC().Add(p.stateTTL)
	pending := Pending{
		Digest:       StateDigest(state),
		Provider:     p.name,
		RedirectURI:  redirectURI,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ExpiresAt:    expiresAt,
	}
	if err := p.state.Put(ctx, pending); err != nil {
		return authentication.Redirect{}, err
	}
	config := p.config
	config.RedirectURL = redirectURI
	config.Scopes = withOpenID(request.Scopes)
	rawURL := config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), coreosoidc.Nonce(nonce))
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	return authentication.Redirect{URL: parsed, StateID: state, ExpiresAt: expiresAt}.Clone(), nil
}

func (p *Provider) Complete(ctx context.Context, callback authentication.Callback) (authentication.Principal, error) {
	if callback.StateID == "" || callback.Code == "" {
		return authentication.Principal{}, authentication.ErrInvalidCallback
	}
	pending, err := p.state.Consume(ctx, callback.StateID)
	if err != nil {
		return authentication.Principal{}, err
	}
	if pending.Provider != p.name || pending.RedirectURI == "" {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if !p.clock().UTC().Before(pending.ExpiresAt) {
		return authentication.Principal{}, authentication.ErrExpired
	}
	if _, ok := p.redirectURIs[pending.RedirectURI]; !ok {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if p.verifier == nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	config := p.config
	config.RedirectURL = pending.RedirectURI
	token, err := config.Exchange(ctx, callback.Code, oauth2.VerifierOption(pending.PKCEVerifier))
	if err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if idToken.Issuer != p.issuer || idToken.Nonce != pending.Nonce || !slices.Contains(idToken.Audience, p.clientID) {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if len(idToken.Audience) > 1 && claims.AuthorizedParty != p.clientID {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	principal := authentication.Principal{
		ID:              p.issuer + "|" + idToken.Subject,
		Issuer:          p.issuer,
		Subject:         idToken.Subject,
		AuthenticatedAt: idToken.IssuedAt.UTC(),
		ExpiresAt:       idToken.Expiry.UTC(),
		Methods:         []string{"oidc"},
	}
	if err := authentication.ValidatePrincipal(principal, p.clock().UTC()); err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	return principal.Clone(), nil
}

func (p *Provider) allowedRedirect(redirectURI string) (string, error) {
	if _, ok := p.redirectURIs[redirectURI]; !ok {
		return "", authentication.ErrInvalidCallback
	}
	return redirectURI, nil
}

func randomSecret(reader io.Reader) (string, error) {
	data := make([]byte, 32)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func withOpenID(scopes []string) []string {
	out := make([]string, 0, len(scopes)+1)
	seenOpenID := false
	for _, scope := range scopes {
		if scope == "" {
			continue
		}
		if scope == "openid" {
			if seenOpenID {
				continue
			}
			seenOpenID = true
		}
		out = append(out, scope)
	}
	if !seenOpenID {
		out = append([]string{"openid"}, out...)
	}
	return out
}

func validateRedirects(values []string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, authentication.ErrInvalidCallback
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validRedirectURI(value) {
			return nil, authentication.ErrInvalidCallback
		}
		if _, exists := out[value]; exists {
			return nil, authentication.ErrInvalidCallback
		}
		out[value] = struct{}{}
	}
	return out, nil
}

func validRedirectURI(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return parsed.Scheme == "http" && isLoopback(parsed.Hostname())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func validServiceURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return parsed.Scheme == "http" && isLoopback(parsed.Hostname())
}

func issuerFromEndpoint(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func invalidText(value string) bool {
	return value == "" || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0
}
