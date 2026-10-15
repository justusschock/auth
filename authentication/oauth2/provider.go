package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/justusschock/go-auth/authentication"
	authoidc "github.com/justusschock/go-auth/authentication/oidc"
	xoauth2 "golang.org/x/oauth2"
)

type UserInfoMapper func(context.Context, *xoauth2.Token) (authentication.Principal, error)

type Options struct {
	Name         string
	Config       xoauth2.Config
	RedirectURIs []string
	State        authoidc.StateStore
	Mapper       UserInfoMapper
	Clock        func() time.Time
	Random       io.Reader
	StateTTL     time.Duration
}

type Provider struct {
	name         string
	config       xoauth2.Config
	redirectURIs map[string]struct{}
	state        authoidc.StateStore
	mapper       UserInfoMapper
	clock        func() time.Time
	random       io.Reader
	stateTTL     time.Duration
}

var _ authentication.FederatedProvider = (*Provider)(nil)

func New(options Options) (*Provider, error) {
	name := strings.ToLower(strings.TrimSpace(options.Name))
	if invalidText(name) || options.State == nil || options.Mapper == nil || invalidText(options.Config.ClientID) {
		return nil, authentication.ErrInvalidCredential
	}
	if !validServiceURL(options.Config.Endpoint.AuthURL) || !validServiceURL(options.Config.Endpoint.TokenURL) {
		return nil, authentication.ErrInvalidCredential
	}
	redirects, err := validateRedirects(options.RedirectURIs)
	if err != nil {
		return nil, err
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
		stateTTL = 10 * time.Minute
	}
	return &Provider{
		name:         name,
		config:       options.Config,
		redirectURIs: redirects,
		state:        options.State,
		mapper:       options.Mapper,
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
	state, err := authoidcRandomSecret(p.random)
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	nonce, err := authoidcRandomSecret(p.random)
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	verifier, err := authoidcRandomSecret(p.random)
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	expiresAt := p.clock().UTC().Add(p.stateTTL)
	pending := authoidc.Pending{
		Digest:       authoidc.StateDigest(state),
		Provider:     p.name,
		RedirectURI:  redirectURI,
		Nonce:        authoidc.NewSecret(nonce),
		PKCEVerifier: authoidc.NewSecret(verifier),
		ExpiresAt:    expiresAt,
	}
	if err := p.state.Put(ctx, pending); err != nil {
		return authentication.Redirect{}, sanitizeStateStoreError(ctx, err, authentication.ErrInvalidCallback)
	}
	config := p.config
	config.RedirectURL = redirectURI
	config.Scopes = cloneScopesWithoutOpenIDForce(request.Scopes)
	rawURL := config.AuthCodeURL(state, xoauth2.S256ChallengeOption(verifier))
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
	pending, err := p.state.Consume(ctx, authoidc.StateDigest(callback.StateID))
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
	config := p.config
	config.RedirectURL = pending.RedirectURI
	token, err := config.Exchange(ctx, callback.Code, xoauth2.VerifierOption(string(pending.PKCEVerifier.Bytes())))
	if err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	principal, err := p.mapper(ctx, token)
	if err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
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

func authoidcRandomSecret(reader io.Reader) (string, error) {
	data := make([]byte, 32)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func cloneScopesWithoutOpenIDForce(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope != "" {
			out = append(out, scope)
		}
	}
	return out
}

func validateRedirects(values []string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, authentication.ErrInvalidCallback
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !authoidcRedirectAllowed(value) {
			return nil, authentication.ErrInvalidCallback
		}
		if _, exists := out[value]; exists {
			return nil, authentication.ErrInvalidCallback
		}
		out[value] = struct{}{}
	}
	return out, nil
}

func authoidcRedirectAllowed(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return parsed.Scheme == "http" && isLoopback(parsed.Hostname())
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

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func invalidText(value string) bool {
	return value == "" || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0
}
