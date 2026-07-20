package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
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
	Store       Store
	Revocations RevocationStore
	Coordinator coordination.Backend
	ManagerID   string
	Lifetime    time.Duration
	Random      io.Reader
	Clock       func() time.Time
}

// Manager creates, validates, rotates, and revokes durable sessions.
type Manager struct {
	store       Store
	revocations RevocationStore
	coordinator coordination.Backend
	managerID   string
	lifetime    time.Duration
	random      io.Reader
	clock       func() time.Time
	counter     atomic.Uint64
}

// NewManager validates options and returns a session manager.
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
	refresh, err := m.randomToken()
	if err != nil {
		return Session{}, "", authentication.ErrInvalidCredential
	}
	session := Session{
		ID:            m.nextSessionID(principal.ID, now),
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

// Validate returns the authoritative session if it remains valid and unrevoked.
func (m *Manager) Validate(ctx context.Context, id string) (Session, error) {
	session, err := m.loadValid(ctx, id)
	if err != nil {
		return Session{}, err
	}
	return cloneSession(session), nil
}

// Rotate verifies the presented refresh token and atomically replaces it under
// a coordination lease.
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

	leasedCtx := context.WithValue(ctx, leaseHeldContextKey{}, true)
	session, err := m.loadValid(leasedCtx, id)
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
	if err := lease.Release(context.Background()); err != nil {
		return Session{}, "", sanitize(err)
	}
	released = true
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
	session, err := m.store.Get(ctx, id)
	if err != nil {
		return Session{}, sanitize(err)
	}
	if err := authentication.ValidatePrincipal(session.Principal, m.now()); err != nil {
		return Session{}, err
	}
	if !m.now().Before(session.ExpiresAt) {
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

func (m *Manager) randomToken() (string, error) {
	var raw [refreshBytes]byte
	if _, err := io.ReadFull(m.random, raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (m *Manager) nextSessionID(principalID string, now time.Time) string {
	sequence := m.counter.Add(1)
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d", principalID, now.UnixNano(), sequence)))
	return "sess_" + base64.RawURLEncoding.EncodeToString(digest[:16])
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
