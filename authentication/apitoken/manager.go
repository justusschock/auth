// Package apitoken issues and authenticates long-lived personal and service
// API tokens of the form <prefix>_<id>_<secret>.
//
// The ID is 128 random bits and the secret 256 random bits, both lowercase
// base32 without padding. Only a digest of the full token is stored:
// HMAC-SHA256 keyed with Options.Pepper when configured, otherwise plain
// SHA-256. Because the secret carries 256 bits of entropy, an unpeppered
// digest cannot be brute-forced; a pepper held outside the token database
// additionally prevents a leaked database from being used to confirm guessed
// or leaked tokens. Digests are compared in constant time.
package apitoken

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/justusschock/go-auth/authentication"
)

const (
	// CredentialKind is the dedicated Credential kind for API tokens.
	// Manager also accepts authentication.CredentialKindBearer.
	CredentialKind = "apitoken"
	// Method is recorded in Principal.Methods for API token authentication.
	Method = "apitoken"
	// ScopeTrait holds the token scopes in Principal.Traits.
	ScopeTrait = "scope"
	// TokenIDTrait holds the token ID in Principal.Traits.
	TokenIDTrait = "apitoken_id"

	defaultMaxTTL           = 365 * 24 * time.Hour
	defaultLastUsedInterval = time.Minute
)

// Options configures a Manager.
type Options struct {
	// Store persists token records. Required.
	Store Store
	// Prefix identifies tokens of this Manager, for example "app". It must be
	// 2-16 characters of [a-z0-9] starting with a letter.
	Prefix string
	// Pepper optionally keys token digests with HMAC-SHA256. When set it must
	// be 32-1024 bytes and stay stable; rotating it invalidates every token.
	Pepper []byte
	// MaxTTL bounds IssueRequest.TTL. Defaults to 365 days.
	MaxTTL time.Duration
	// LastUsedInterval throttles TouchLastUsed writes per token. Defaults to
	// one minute; a negative value disables last-used tracking.
	LastUsedInterval time.Duration
	Random           io.Reader
	Clock            func() time.Time
}

// IssueRequest describes a new API token.
type IssueRequest struct {
	Principal Identity
	Name      string
	Scopes    []string
	TTL       time.Duration
}

// Manager issues, lists, revokes, and authenticates API tokens.
type Manager struct {
	store            Store
	prefix           string
	pepper           []byte
	maxTTL           time.Duration
	lastUsedInterval time.Duration
	random           io.Reader
	clock            func() time.Time
}

var _ authentication.Authenticator = (*Manager)(nil)

// NewManager validates options and returns a Manager.
func NewManager(options Options) (*Manager, error) {
	if options.Store == nil || !validPrefix(options.Prefix) {
		return nil, authentication.ErrInvalidCredential
	}
	if len(options.Pepper) > 0 && (len(options.Pepper) < minPepper || len(options.Pepper) > maxPepper) {
		return nil, authentication.ErrInvalidCredential
	}
	if options.MaxTTL < 0 {
		return nil, authentication.ErrInvalidCredential
	}
	maxTTL := options.MaxTTL
	if maxTTL == 0 {
		maxTTL = defaultMaxTTL
	}
	lastUsedInterval := options.LastUsedInterval
	if lastUsedInterval == 0 {
		lastUsedInterval = defaultLastUsedInterval
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Manager{
		store:            options.Store,
		prefix:           options.Prefix,
		pepper:           slices.Clone(options.Pepper),
		maxTTL:           maxTTL,
		lastUsedInterval: lastUsedInterval,
		random:           random,
		clock:            clock,
	}, nil
}

// Issue creates a token and returns it exactly once together with its record.
func (m *Manager) Issue(ctx context.Context, request IssueRequest) (string, Record, error) {
	if err := ctx.Err(); err != nil {
		return "", Record{}, err
	}
	if !validIdentity(request.Principal) {
		return "", Record{}, authentication.ErrInvalidPrincipal
	}
	if !validText(request.Name, maxNameBytes) || !validScopes(request.Scopes) {
		return "", Record{}, authentication.ErrInvalidCredential
	}
	if request.TTL <= 0 || request.TTL > m.maxTTL {
		return "", Record{}, authentication.ErrInvalidCredential
	}
	raw := make([]byte, idBytes+secretBytes)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return "", Record{}, authentication.ErrInvalidCredential
	}
	id := encoding.EncodeToString(raw[:idBytes])
	token := formatToken(m.prefix, id, raw[idBytes:])
	clear(raw)
	now := m.now()
	scopes := slices.Clone(request.Scopes)
	slices.Sort(scopes)
	record := Record{
		ID:        id,
		Digest:    digest(m.pepper, token),
		Principal: request.Principal.Clone(),
		Name:      request.Name,
		Scopes:    scopes,
		CreatedAt: now,
		ExpiresAt: now.Add(request.TTL),
	}
	if !ValidRecord(record) || authentication.ValidatePrincipal(principalFromRecord(record, now), now) != nil {
		return "", Record{}, authentication.ErrInvalidPrincipal
	}
	if err := m.store.Create(ctx, record); err != nil {
		return "", Record{}, sanitize(ctx, err, authentication.ErrInvalidCredential)
	}
	return token, redact(record), nil
}

// List returns the principal's tokens, including expired and revoked ones.
func (m *Manager) List(ctx context.Context, principalID string) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validText(principalID, maxIdentityBytes) {
		return nil, authentication.ErrInvalidPrincipal
	}
	records, err := m.store.ListByPrincipal(ctx, principalID)
	if err != nil {
		return nil, sanitize(ctx, err, authentication.ErrUnauthenticated)
	}
	out := make([]Record, 0, len(records))
	for _, record := range records {
		if record.Principal.ID != principalID || !ValidRecord(record) {
			return nil, authentication.ErrUnauthenticated
		}
		out = append(out, redact(record))
	}
	sortRecords(out)
	return out, nil
}

// Revoke revokes the principal's token with id. It returns ErrNotFound when
// the token does not exist or belongs to another principal. Revoking an
// already revoked token succeeds.
func (m *Manager) Revoke(ctx context.Context, principalID string, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validText(principalID, maxIdentityBytes) {
		return authentication.ErrInvalidPrincipal
	}
	if !ValidID(id) {
		return ErrNotFound
	}
	record, err := m.store.Get(ctx, id)
	if err != nil {
		return sanitize(ctx, err, authentication.ErrUnauthenticated)
	}
	if record.ID != id || record.Principal.ID != principalID {
		return ErrNotFound
	}
	if err := m.store.Revoke(ctx, id, m.now()); err != nil {
		return sanitize(ctx, err, authentication.ErrUnauthenticated)
	}
	return nil
}

// Authenticate validates an API token credential. Credentials of other kinds
// or without this Manager's prefix return
// authentication.ErrUnsupportedCredential so the Manager composes with
// authentication.Chain.
func (m *Manager) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Principal, error) {
	if err := ctx.Err(); err != nil {
		return authentication.Principal{}, err
	}
	if credential.Kind != CredentialKind && credential.Kind != authentication.CredentialKindBearer {
		return authentication.Principal{}, authentication.ErrUnsupportedCredential
	}
	if !hasPrefix(string(credential.Token), m.prefix) {
		return authentication.Principal{}, authentication.ErrUnsupportedCredential
	}
	if len(credential.Token) > maxTokenSize {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	token := string(credential.Token)
	id, ok := parseToken(token, m.prefix)
	if !ok {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	presented := digest(m.pepper, token)
	record, err := m.store.Get(ctx, id)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return authentication.Principal{}, ctxErr
		}
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	// Compare before inspecting state so callers without the secret learn
	// nothing about the record.
	if !digestsEqual(record.Digest, presented) || record.ID != id || !ValidRecord(record) {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	now := m.now()
	if record.Revoked() {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if !now.Before(record.ExpiresAt) {
		return authentication.Principal{}, authentication.ErrExpired
	}
	principal := principalFromRecord(record, now)
	if err := authentication.ValidatePrincipal(principal, now); err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if m.lastUsedInterval > 0 && (record.LastUsedAt.IsZero() || now.Sub(record.LastUsedAt) >= m.lastUsedInterval) {
		// Best effort: a failed last-used update must not fail authentication.
		_ = m.store.TouchLastUsed(ctx, id, now)
	}
	return principal, nil
}

func principalFromRecord(record Record, now time.Time) authentication.Principal {
	identity := record.Principal.Clone()
	traits := identity.Traits
	if traits == nil {
		traits = make(map[string][]string, 2)
	}
	traits[ScopeTrait] = slices.Clone(record.Scopes)
	if traits[ScopeTrait] == nil {
		traits[ScopeTrait] = []string{}
	}
	traits[TokenIDTrait] = []string{record.ID}
	return authentication.Principal{
		ID:              identity.ID,
		Issuer:          identity.Issuer,
		Subject:         identity.Subject,
		AuthenticatedAt: now,
		ExpiresAt:       record.ExpiresAt,
		Traits:          traits,
		Methods:         []string{Method},
	}
}

func redact(record Record) Record {
	clone := record.Clone()
	clone.Digest = [32]byte{}
	return clone
}

func (m *Manager) now() time.Time {
	return m.clock().UTC()
}

func sanitize(ctx context.Context, err, fallback error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, authentication.ErrReplay):
		return authentication.ErrReplay
	case errors.Is(err, authentication.ErrInvalidPrincipal):
		return authentication.ErrInvalidPrincipal
	case errors.Is(err, authentication.ErrInvalidCredential):
		return authentication.ErrInvalidCredential
	default:
		return fallback
	}
}
