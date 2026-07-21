package magiclink

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"time"

	"github.com/justusschock/go-auth/authentication"
)

const (
	tokenBytes = 32
	tokenChars = 43
	maxTTL     = 15 * time.Minute
)

type Options struct {
	Store        Store
	BaseURL      string
	RedirectURIs []string
	TTL          time.Duration
	Random       io.Reader
	Clock        func() time.Time
	Purpose      string
}

type Link struct {
	URL       *url.URL
	Token     string
	ExpiresAt time.Time
}

type Service struct {
	store        Store
	baseURL      *url.URL
	redirectURIs map[string]struct{}
	ttl          time.Duration
	random       io.Reader
	clock        func() time.Time
	purpose      string
}

func NewService(options Options) (*Service, error) {
	if options.Store == nil {
		return nil, authentication.ErrInvalidCredential
	}
	if options.TTL <= 0 || options.TTL > maxTTL {
		return nil, authentication.ErrInvalidCredential
	}
	baseURL, err := parseHTTPSURL(options.BaseURL)
	if err != nil {
		return nil, authentication.ErrInvalidCredential
	}
	redirects, err := validateRedirects(options.RedirectURIs)
	if err != nil {
		return nil, err
	}
	if !validOptionalText(options.Purpose, maxPurposeBytes) {
		return nil, authentication.ErrInvalidCredential
	}
	randomReader := options.Random
	if randomReader == nil {
		randomReader = rand.Reader
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		store:        options.Store,
		baseURL:      baseURL,
		redirectURIs: redirects,
		ttl:          options.TTL,
		random:       randomReader,
		clock:        clock,
		purpose:      options.Purpose,
	}, nil
}

func (s *Service) Issue(ctx context.Context, principal authentication.Principal, redirectURI string) (Link, error) {
	if err := ctx.Err(); err != nil {
		return Link{}, err
	}
	now := s.clock().UTC()
	if _, ok := s.redirectURIs[redirectURI]; !ok {
		return Link{}, authentication.ErrInvalidCallback
	}
	if err := authentication.ValidatePrincipal(principal, now); err != nil {
		return Link{}, authentication.ErrInvalidPrincipal
	}
	raw := make([]byte, tokenBytes)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return Link{}, authentication.ErrInvalidCredential
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expiresAt := now.Add(s.ttl)
	record := Record{
		Digest:      tokenDigest(token),
		Principal:   principal.Clone(),
		RedirectURI: redirectURI,
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
		Purpose:     s.purpose,
	}
	if err := s.store.Create(ctx, record); err != nil {
		return Link{}, sanitizeStoreError(ctx, err, authentication.ErrInvalidCallback)
	}
	linkURL := cloneURL(s.baseURL)
	query := linkURL.Query()
	query.Set("token", token)
	linkURL.RawQuery = query.Encode()
	return Link{URL: linkURL, Token: token, ExpiresAt: expiresAt}.Clone(), nil
}

func (s *Service) Consume(ctx context.Context, token string) (authentication.Principal, error) {
	if err := ctx.Err(); err != nil {
		return authentication.Principal{}, err
	}
	if !validToken(token) {
		return authentication.Principal{}, authentication.ErrInvalidCredential
	}
	record, err := s.store.Consume(ctx, tokenDigest(token))
	if err != nil {
		return authentication.Principal{}, sanitizeStoreError(ctx, err, authentication.ErrUnauthenticated)
	}
	now := s.clock().UTC()
	if !validRecord(record) {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if _, ok := s.redirectURIs[record.RedirectURI]; !ok {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if !now.Before(record.ExpiresAt) {
		return authentication.Principal{}, authentication.ErrExpired
	}
	if err := authentication.ValidatePrincipal(record.Principal, now); err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	return record.Principal.Clone(), nil
}

func (l Link) Clone() Link {
	clone := l
	clone.URL = cloneURL(l.URL)
	return clone
}

func tokenDigest(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func validToken(token string) bool {
	if len(token) != tokenChars {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != tokenBytes {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(raw) == token
}

func sanitizeStoreError(ctx context.Context, err, fallback error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, authentication.ErrReplay) {
		return authentication.ErrReplay
	}
	if errors.Is(err, authentication.ErrInvalidCallback) {
		return authentication.ErrInvalidCallback
	}
	if errors.Is(err, authentication.ErrInvalidCredential) {
		return authentication.ErrInvalidCredential
	}
	return fallback
}

func parseHTTPSURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, authentication.ErrInvalidCredential
	}
	return cloneURL(parsed), nil
}

func validateRedirects(values []string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, authentication.ErrInvalidCallback
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		parsed, err := parseHTTPSURL(value)
		if err != nil || parsed.String() != value {
			return nil, authentication.ErrInvalidCallback
		}
		if _, exists := out[value]; exists {
			return nil, authentication.ErrInvalidCallback
		}
		out[value] = struct{}{}
	}
	return out, nil
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return nil
	}
	clone := *value
	if value.User != nil {
		if password, ok := value.User.Password(); ok {
			clone.User = url.UserPassword(value.User.Username(), password)
		} else {
			clone.User = url.User(value.User.Username())
		}
	}
	return &clone
}
