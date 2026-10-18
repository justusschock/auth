// Package oidc implements the OpenID Connect authorization code flow with
// PKCE (S256) and nonce as an authentication.FederatedProvider.
//
// Begin generates independent 256-bit state, nonce and PKCE verifier values
// and stores them through a caller-owned StateStore, keyed by the SHA-256
// digest of the state so the raw state never reaches storage. Complete
// consumes that state atomically before exchanging the code, so a callback is
// accepted at most once, then verifies the ID token (signature through the
// configured go-oidc verifier, issuer, audience, authorized party and nonce)
// and builds a principal "<issuer>|<sub>". Only the ID token claims named in
// Options.TraitClaims are copied into Principal.Traits.
//
// The package also defines the state types shared with the oauth2 package:
// Secret, Pending, StateStore and MemoryStateStore.
package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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

const (
	defaultStateTTL        = 10 * time.Minute
	maxConfiguredClaims    = 128
	maxConfiguredClaimName = 256
)

// Secret holds sensitive callback material and redacts it when formatted.
// Bytes and binary marshaling provide explicit access for provider use and
// caller-owned durable stores.
type Secret struct {
	value string
}

// NewSecret wraps value.
func NewSecret(value string) Secret {
	return Secret{value: value}
}

// Bytes returns a copy of the secret value.
func (s Secret) Bytes() []byte {
	return []byte(s.value)
}

// MarshalBinary returns the secret value for caller-owned durable stores.
func (s Secret) MarshalBinary() ([]byte, error) {
	return s.Bytes(), nil
}

// UnmarshalBinary restores a secret produced by MarshalBinary.
func (s *Secret) UnmarshalBinary(value []byte) error {
	if s == nil {
		return authentication.ErrInvalidCredential
	}
	s.value = string(value)
	return nil
}

// String returns a redaction marker, never the secret.
func (Secret) String() string {
	return "[REDACTED]"
}

// GoString returns a redaction marker, never the secret.
func (Secret) GoString() string {
	return "[REDACTED]"
}

// Pending is caller-owned callback state. It intentionally stores only a
// SHA-256 digest of the raw callback state.
type Pending struct {
	Digest       [32]byte
	Provider     string
	RedirectURI  string
	Nonce        Secret
	PKCEVerifier Secret
	ExpiresAt    time.Time
}

// StateStore persists callback state. Put must fail with
// authentication.ErrReplay when the digest exists. Consume must atomically
// remove and return the state for a digest and return
// authentication.ErrReplay when none exists, so that concurrent callbacks
// cannot both consume it.
type StateStore interface {
	Put(context.Context, Pending) error
	Consume(context.Context, [32]byte) (Pending, error)
}

// MemoryStateStore is a process-local StateStore for tests and single-process
// callers. Distributed deployments should provide their own durable store.
type MemoryStateStore struct {
	mu      sync.Mutex
	pending map[[32]byte]Pending
}

// NewMemoryStateStore returns an empty memory-backed state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{pending: make(map[[32]byte]Pending)}
}

// Put stores pending unless its digest is already present.
func (s *MemoryStateStore) Put(ctx context.Context, pending Pending) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pending.Digest == [32]byte{} {
		return authentication.ErrInvalidCallback
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pending[pending.Digest]; exists {
		return authentication.ErrReplay
	}
	s.pending[pending.Digest] = pending
	return nil
}

// Consume atomically removes and returns the state for digest.
func (s *MemoryStateStore) Consume(ctx context.Context, digest [32]byte) (Pending, error) {
	if err := ctx.Err(); err != nil {
		return Pending{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[digest]
	if !ok {
		return Pending{}, authentication.ErrReplay
	}
	delete(s.pending, digest)
	return pending, nil
}

// StateDigest returns the SHA-256 digest under which the raw callback state
// is stored.
func StateDigest(state string) [32]byte {
	return sha256.Sum256([]byte(state))
}

// Options configures a Provider.
type Options struct {
	// Name identifies the provider (lower-cased and trimmed). Required.
	Name string
	// Issuer is the https issuer URL. Defaults to the origin of
	// Config.Endpoint.AuthURL.
	Issuer string
	// ClientID is the OAuth client ID; it may instead be set in Config and
	// must match it when both are set.
	ClientID string
	// TraitClaims names the verified ID token claims (string or string
	// array) copied into Principal.Traits. At most 128 unique names.
	TraitClaims []string
	// Config holds the client credentials and endpoints. Missing endpoints
	// default to "<issuer>/authorize" and "<issuer>/token". Endpoints must
	// use https, or http on a loopback host.
	Config oauth2.Config
	// Verifier verifies ID token signatures and standard claims. Complete
	// fails closed when it is nil.
	Verifier *coreosoidc.IDTokenVerifier
	// RedirectURIs lists the exact redirect URIs Begin accepts (https, or
	// http on a loopback host). Required, without duplicates.
	RedirectURIs []string
	// State persists pending callback state. Required.
	State StateStore
	// Clock returns the current time used for state expiry and principal
	// validation; its result is converted to UTC. Defaults to time.Now. ID
	// token expiry is checked by Verifier with its own clock
	// (coreosoidc.Config.Now).
	Clock func() time.Time
	// Random supplies state, nonce and PKCE entropy. Defaults to
	// crypto/rand.Reader; any replacement must be cryptographically secure.
	Random io.Reader
	// StateTTL bounds the time between Begin and Complete. Defaults to ten
	// minutes.
	StateTTL time.Duration
}

// Provider is an OpenID Connect authorization code flow provider. It is safe
// for concurrent use when its StateStore is.
type Provider struct {
	name         string
	issuer       string
	clientID     string
	traitClaims  []string
	config       oauth2.Config
	verifier     *coreosoidc.IDTokenVerifier
	redirectURIs map[string]struct{}
	state        StateStore
	clock        func() time.Time
	random       io.Reader
	stateTTL     time.Duration
}

var _ authentication.FederatedProvider = (*Provider)(nil)

// New validates options and returns a Provider. It returns
// authentication.ErrInvalidCredential or authentication.ErrInvalidCallback
// for invalid options.
func New(options Options) (*Provider, error) {
	name := strings.ToLower(strings.TrimSpace(options.Name))
	issuer := strings.TrimSpace(options.Issuer)
	config := options.Config
	optionClientID := strings.TrimSpace(options.ClientID)
	configClientID := strings.TrimSpace(config.ClientID)
	if optionClientID != "" && configClientID != "" && optionClientID != configClientID {
		return nil, authentication.ErrInvalidCredential
	}
	clientID := optionClientID
	if clientID == "" {
		clientID = configClientID
	}
	config.ClientID = clientID
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
	traitClaims, err := validateTraitClaims(options.TraitClaims)
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
		traitClaims:  traitClaims,
		config:       config,
		verifier:     options.Verifier,
		redirectURIs: redirects,
		state:        options.State,
		clock:        clock,
		random:       random,
		stateTTL:     stateTTL,
	}, nil
}

// Name returns the normalized provider name.
func (p *Provider) Name() string {
	return p.name
}

// Begin starts a login for a registered redirect URI and returns the
// authorization URL. "openid" is always requested.
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
		Nonce:        NewSecret(nonce),
		PKCEVerifier: NewSecret(verifier),
		ExpiresAt:    expiresAt,
	}
	if err := p.state.Put(ctx, pending); err != nil {
		return authentication.Redirect{}, sanitizeStateStoreError(ctx, err, authentication.ErrInvalidCallback)
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

// Complete consumes the callback state, exchanges the code and verifies the
// ID token. It returns authentication.ErrReplay for unknown or reused state,
// authentication.ErrExpired after Options.StateTTL, and
// authentication.ErrUnauthenticated for every other verification failure.
func (p *Provider) Complete(ctx context.Context, callback authentication.Callback) (authentication.Principal, error) {
	if callback.StateID == "" || callback.Code == "" {
		return authentication.Principal{}, authentication.ErrInvalidCallback
	}
	pending, err := p.state.Consume(ctx, StateDigest(callback.StateID))
	if err != nil {
		return authentication.Principal{}, sanitizeStateStoreError(ctx, err, authentication.ErrUnauthenticated)
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
	token, err := config.Exchange(ctx, callback.Code, oauth2.VerifierOption(string(pending.PKCEVerifier.Bytes())))
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
	if idToken.Issuer != p.issuer || idToken.Nonce != string(pending.Nonce.Bytes()) || !slices.Contains(idToken.Audience, p.clientID) {
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
	traits, err := configuredTraits(idToken, p.traitClaims)
	if err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	principal := authentication.Principal{
		ID:              p.issuer + "|" + idToken.Subject,
		Issuer:          p.issuer,
		Subject:         idToken.Subject,
		AuthenticatedAt: idToken.IssuedAt.UTC(),
		ExpiresAt:       idToken.Expiry.UTC(),
		Traits:          traits,
		Methods:         []string{"oidc"},
	}
	if err := authentication.ValidatePrincipal(principal, p.clock().UTC()); err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	return principal.Clone(), nil
}

func validateTraitClaims(values []string) ([]string, error) {
	if len(values) > maxConfiguredClaims {
		return nil, authentication.ErrInvalidCredential
	}
	out := slices.Clone(values)
	seen := make(map[string]struct{}, len(out))
	for _, value := range out {
		if invalidText(value) || len(value) > maxConfiguredClaimName || strings.TrimSpace(value) != value {
			return nil, authentication.ErrInvalidCredential
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, authentication.ErrInvalidCredential
		}
		seen[value] = struct{}{}
	}
	return out, nil
}

func configuredTraits(idToken *coreosoidc.IDToken, names []string) (map[string][]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	traits := make(map[string][]string, len(names))
	for _, name := range names {
		raw, ok := claims[name]
		if !ok {
			continue
		}
		raw = bytes.TrimSpace(raw)
		var values []string
		switch {
		case len(raw) > 0 && raw[0] == '"':
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, err
			}
			values = []string{value}
		case len(raw) > 0 && raw[0] == '[':
			if err := json.Unmarshal(raw, &values); err != nil {
				return nil, err
			}
		default:
			return nil, authentication.ErrInvalidPrincipal
		}
		traits[name] = values
	}
	if len(traits) == 0 {
		return nil, nil
	}
	return traits, nil
}

func (p *Provider) allowedRedirect(redirectURI string) (string, error) {
	if _, ok := p.redirectURIs[redirectURI]; !ok {
		return "", authentication.ErrInvalidCallback
	}
	return redirectURI, nil
}

func sanitizeStateStoreError(ctx context.Context, err, fallback error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, authentication.ErrReplay) {
		return authentication.ErrReplay
	}
	if errors.Is(err, authentication.ErrInvalidCallback) {
		return authentication.ErrInvalidCallback
	}
	return fallback
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
