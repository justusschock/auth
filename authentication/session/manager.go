// Package session manages durable, server-side login sessions with rotating
// refresh tokens.
//
// A session has a random 256-bit ID ("sess_" + base64url) and a separate
// random 256-bit refresh token that is returned exactly once; only its SHA-256
// digest is stored. Rotate compares the presented token's digest in constant
// time and replaces it under a go-distributed-coordination lease, writing
// with a compare-and-swap that is fenced by the lease token, so exactly one of
// several concurrent rotations with the same token succeeds and a reused
// (stolen) refresh token is detected as authentication.ErrReplay. Sessions
// and whole principals can be revoked through durable tombstones that
// Validate and Rotate always consult. Session lifetimes are bounded to 24
// hours, and a session stops validating once its principal has expired.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/justusschock/go-auth/authentication"
	coordination "github.com/justusschock/go-distributed-coordination"
)

const (
	refreshBytes = 32
	leaseTTL     = 10 * time.Second
	maxLifetime  = 24 * time.Hour
)

// Options configures a Manager.
type Options struct {
	// Store is the authoritative session store. Required.
	Store Store
	// Revocations persists session and principal tombstones. Required.
	Revocations RevocationStore
	// Coordinator provides the leases that serialize refresh-token
	// rotation per session. Required.
	Coordinator coordination.Backend
	// ManagerID identifies this manager as lease owner. Required.
	ManagerID string
	// Lifetime is the session lifetime: positive and at most 24 hours.
	Lifetime time.Duration
	// Random supplies session IDs and refresh tokens. Defaults to
	// crypto/rand.Reader; any replacement must be cryptographically secure.
	Random io.Reader
	// Clock returns the current time used for session issue, expiry,
	// rotation and revocation timestamps; its result is converted to UTC.
	// Defaults to time.Now. Lease timing is governed by Coordinator.
	Clock func() time.Time
}

// Manager creates, validates, rotates, and revokes durable sessions. It is
// safe for concurrent use when its stores and coordinator are.
type Manager struct {
	store       Store
	revocations RevocationStore
	coordinator coordination.Backend
	managerID   string
	lifetime    time.Duration
	random      io.Reader
	clock       func() time.Time
}

// NewManager validates options and returns a session manager. It returns
// authentication.ErrInvalidCredential for invalid options.
func NewManager(options Options) (*Manager, error) {
	if options.Store == nil || options.Revocations == nil || options.Coordinator == nil {
		return nil, authentication.ErrInvalidCredential
	}
	if invalidText(options.ManagerID, maxSessionIDBytes) || options.Lifetime <= 0 || options.Lifetime > maxLifetime {
		return nil, authentication.ErrInvalidCredential
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	clock := options.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Manager{
		store:       options.Store,
		revocations: options.Revocations,
		coordinator: options.Coordinator,
		managerID:   options.ManagerID,
		lifetime:    options.Lifetime,
		random:      random,
		clock:       clock,
	}, nil
}

// Create persists a new session and returns the refresh token exactly once.
func (m *Manager) Create(ctx context.Context, principal authentication.Principal, client ClientInfo) (Session, string, error) {
	now := m.now()
	if err := authentication.ValidatePrincipal(principal, now); err != nil {
		return Session{}, "", err
	}
	if !validClient(client) {
		return Session{}, "", authentication.ErrInvalidCredential
	}
	id, err := m.randomSessionID()
	if err != nil {
		return Session{}, "", authentication.ErrInvalidCredential
	}
	refresh, err := m.randomToken()
	if err != nil {
		return Session{}, "", authentication.ErrInvalidCredential
	}
	session := Session{
		ID:            id,
		Version:       1,
		Principal:     principal.Clone(),
		CreatedAt:     now,
		ExpiresAt:     now.Add(m.lifetime).UTC(),
		LastSeenAt:    now,
		RefreshDigest: sha256.Sum256([]byte(refresh)),
		Client:        client,
	}
	if err := m.store.Create(ctx, session); err != nil {
		return Session{}, "", sanitize(err)
	}
	return cloneSession(session), refresh, nil
}

// Validate returns the authoritative session if it remains valid and
// unrevoked. It returns authentication.ErrExpired once the session or its
// principal has expired and authentication.ErrUnauthenticated for unknown or
// revoked sessions.
func (m *Manager) Validate(ctx context.Context, id string) (Session, error) {
	session, err := m.loadValid(ctx, id)
	if err != nil {
		return Session{}, err
	}
	return cloneSession(session), nil
}

// Rotate verifies the presented refresh token and atomically replaces it under
// a coordination lease. It returns the updated session and the new refresh
// token. A token that does not match the current one returns
// authentication.ErrReplay; a lost lease returns coordination.ErrLeaseLost.
func (m *Manager) Rotate(ctx context.Context, id string, refresh string) (rotated Session, nextRefresh string, err error) {
	if invalidText(id, maxSessionIDBytes) {
		return Session{}, "", authentication.ErrInvalidCredential
	}
	digest, err := refreshDigest(refresh)
	if err != nil {
		return Session{}, "", err
	}
	lease, err := m.coordinator.Acquire(ctx, coordination.AcquireRequest{
		Key:   "auth/session/" + id,
		Owner: m.managerID,
		TTL:   leaseTTL,
		Wait:  true,
	})
	if err != nil {
		return Session{}, "", sanitize(err)
	}
	released := false
	defer func() {
		if released {
			return
		}
		if releaseErr := lease.Release(context.Background()); err == nil && releaseErr != nil {
			rotated = Session{}
			nextRefresh = ""
			err = sanitize(releaseErr)
		}
	}()

	session, err := m.loadValid(ctx, id)
	if err != nil {
		return Session{}, "", err
	}
	if subtle.ConstantTimeCompare(session.RefreshDigest[:], digest[:]) != 1 {
		return Session{}, "", authentication.ErrReplay
	}
	select {
	case <-lease.Done():
		return Session{}, "", coordination.ErrLeaseLost
	default:
	}
	nextRefresh, err = m.randomToken()
	if err != nil {
		return Session{}, "", authentication.ErrInvalidCredential
	}
	now := m.now()
	next := cloneSession(session)
	next.Version++
	next.Rotation++
	next.LastSeenAt = now
	next.RefreshDigest = sha256.Sum256([]byte(nextRefresh))
	if err := m.store.CompareAndSwap(ctx, id, session.Version, uint64(lease.Info().Token), next); err != nil {
		return Session{}, "", sanitize(err)
	}
	releaseErr := lease.Release(context.Background())
	released = true
	if releaseErr != nil {
		return Session{}, "", sanitize(releaseErr)
	}
	return cloneSession(next), nextRefresh, nil
}

// Revoke persists a session tombstone.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	if invalidText(id, maxSessionIDBytes) {
		return authentication.ErrInvalidCredential
	}
	if err := m.revocations.RevokeSession(ctx, id); err != nil {
		return sanitize(err)
	}
	return nil
}

// RevokePrincipal persists a principal tombstone and revokes known sessions.
func (m *Manager) RevokePrincipal(ctx context.Context, principalID string) error {
	if invalidText(principalID, maxSessionIDBytes) {
		return authentication.ErrInvalidPrincipal
	}
	if err := m.revocations.RevokePrincipal(ctx, principalID); err != nil {
		return sanitize(err)
	}
	sessions, err := m.store.ListByPrincipal(ctx, principalID)
	if err != nil {
		return sanitize(err)
	}
	for _, session := range sessions {
		if err := m.revocations.RevokeSession(ctx, session.ID); err != nil {
			return sanitize(err)
		}
	}
	return nil
}

func (m *Manager) loadValid(ctx context.Context, id string) (Session, error) {
	now := m.now()
	session, err := m.store.Get(ctx, id)
	if err != nil {
		return Session{}, sanitize(err)
	}
	if session.ID != id {
		return Session{}, authentication.ErrInvalidCredential
	}
	if err := validateSession(session); err != nil {
		return Session{}, err
	}
	lifetime := session.ExpiresAt.Sub(session.CreatedAt)
	if lifetime <= 0 || lifetime > m.lifetime {
		return Session{}, authentication.ErrInvalidCredential
	}
	if err := authentication.ValidatePrincipal(session.Principal, now); err != nil {
		return Session{}, err
	}
	if !now.Before(session.ExpiresAt) {
		return Session{}, authentication.ErrExpired
	}
	revoked, err := m.revocations.IsSessionRevoked(ctx, id)
	if err != nil {
		return Session{}, sanitize(err)
	}
	if revoked {
		return Session{}, authentication.ErrUnauthenticated
	}
	principalRevoked, err := m.revocations.IsPrincipalRevoked(ctx, session.Principal.ID)
	if err != nil {
		return Session{}, sanitize(err)
	}
	if principalRevoked {
		return Session{}, authentication.ErrUnauthenticated
	}
	return cloneSession(session), nil
}

func (m *Manager) randomSessionID() (string, error) {
	encoded, err := m.randomToken()
	if err != nil {
		return "", err
	}
	return "sess_" + encoded, nil
}

func (m *Manager) randomToken() (string, error) {
	var raw [refreshBytes]byte
	if _, err := io.ReadFull(m.random, raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (m *Manager) now() time.Time {
	return m.clock().UTC()
}

func refreshDigest(token string) ([32]byte, error) {
	var zero [32]byte
	if len(token) != 43 {
		return zero, authentication.ErrInvalidCredential
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != refreshBytes {
		return zero, authentication.ErrInvalidCredential
	}
	if base64.RawURLEncoding.EncodeToString(raw) != token {
		return zero, authentication.ErrInvalidCredential
	}
	return sha256.Sum256([]byte(token)), nil
}

func sanitize(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, coordination.ErrLeaseLost):
		return coordination.ErrLeaseLost
	case errors.Is(err, authentication.ErrExpired):
		return authentication.ErrExpired
	case errors.Is(err, authentication.ErrInvalidPrincipal):
		return authentication.ErrInvalidPrincipal
	case errors.Is(err, authentication.ErrInvalidCredential):
		return authentication.ErrInvalidCredential
	case errors.Is(err, authentication.ErrReplay):
		return authentication.ErrReplay
	default:
		return authentication.ErrUnauthenticated
	}
}
