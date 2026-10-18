package session

import (
	"context"
	"reflect"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/justusschock/auth/authentication"
	coordination "github.com/justusschock/distributed-coordination"
)

const (
	maxSessionIDBytes = 128
	maxClientBytes    = 512
)

// ClientInfo is caller-supplied, bounded session client metadata.
type ClientInfo struct {
	UserAgent string
	IPAddress string
	DeviceID  string
}

// Session is the authoritative durable session record.
type Session struct {
	ID            string
	Version       uint64
	Principal     authentication.Principal
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastSeenAt    time.Time
	RefreshDigest [32]byte
	Rotation      uint64
	Client        ClientInfo
}

// Store is the durable, authoritative session store.
//
// Create must fail with authentication.ErrReplay for an existing ID.
// CompareAndSwap(ctx, id, expectedVersion, fence, next) must replace the
// session only when its current version equals expectedVersion (otherwise
// authentication.ErrReplay) and fence is greater than the fence of the last
// successful swap (otherwise coordination.ErrLeaseLost), atomically.
type Store interface {
	Create(context.Context, Session) error
	Get(context.Context, string) (Session, error)
	CompareAndSwap(context.Context, string, uint64, uint64, Session) error
	ListByPrincipal(context.Context, string) ([]Session, error)
}

// RevocationStore persists session and principal tombstones.
type RevocationStore interface {
	RevokeSession(context.Context, string) error
	RevokePrincipal(context.Context, string) error
	IsSessionRevoked(context.Context, string) (bool, error)
	IsPrincipalRevoked(context.Context, string) (bool, error)
}

type storedSession struct {
	session Session
	fence   uint64
}

// MemoryStore is a concurrency-safe, process-local Store for tests and
// single-process callers. Distributed deployments should provide a durable
// implementation.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]storedSession
}

// NewMemoryStore returns an empty memory-backed session store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: make(map[string]storedSession)}
}

// Create stores a new session if its identifier is unused.
func (s *MemoryStore) Create(ctx context.Context, session Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSession(session); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; ok {
		return authentication.ErrReplay
	}
	s.sessions[session.ID] = storedSession{session: cloneSession(session)}
	return nil
}

// Get returns the authoritative session by ID.
func (s *MemoryStore) Get(ctx context.Context, id string) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	if invalidText(id, maxSessionIDBytes) {
		return Session{}, authentication.ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.sessions[id]
	if !ok {
		return Session{}, authentication.ErrUnauthenticated
	}
	return cloneSession(stored.session), nil
}

// CompareAndSwap updates a session only when the expected version and fencing
// token are current.
func (s *MemoryStore) CompareAndSwap(ctx context.Context, id string, expectedVersion uint64, fence uint64, next Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if invalidText(id, maxSessionIDBytes) {
		return authentication.ErrInvalidCredential
	}
	if err := validateSession(next); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.sessions[id]
	if !ok {
		return authentication.ErrUnauthenticated
	}
	if stored.session.Version != expectedVersion {
		return authentication.ErrReplay
	}
	if fence <= stored.fence {
		return coordination.ErrLeaseLost
	}
	if err := validateTransition(stored.session, id, expectedVersion, next); err != nil {
		return err
	}
	s.sessions[id] = storedSession{session: cloneSession(next), fence: fence}
	return nil
}

// ListByPrincipal returns all sessions for a principal.
func (s *MemoryStore) ListByPrincipal(ctx context.Context, principalID string) ([]Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if invalidText(principalID, maxSessionIDBytes) {
		return nil, authentication.ErrInvalidPrincipal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, stored := range s.sessions {
		if stored.session.Principal.ID == principalID {
			out = append(out, cloneSession(stored.session))
		}
	}
	return out, nil
}

// MemoryRevocationStore is a concurrency-safe revocation tombstone store.
type MemoryRevocationStore struct {
	mu         sync.Mutex
	sessions   map[string]struct{}
	principals map[string]struct{}
}

// NewMemoryRevocationStore returns an empty memory-backed revocation store.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{
		sessions:   make(map[string]struct{}),
		principals: make(map[string]struct{}),
	}
}

// RevokeSession persists a session tombstone.
func (s *MemoryRevocationStore) RevokeSession(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if invalidText(id, maxSessionIDBytes) {
		return authentication.ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = struct{}{}
	return nil
}

// RevokePrincipal persists a principal tombstone.
func (s *MemoryRevocationStore) RevokePrincipal(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if invalidText(id, maxSessionIDBytes) {
		return authentication.ErrInvalidPrincipal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[id] = struct{}{}
	return nil
}

// IsSessionRevoked checks a session tombstone.
func (s *MemoryRevocationStore) IsSessionRevoked(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if invalidText(id, maxSessionIDBytes) {
		return false, authentication.ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[id]
	return ok, nil
}

// IsPrincipalRevoked checks a principal tombstone.
func (s *MemoryRevocationStore) IsPrincipalRevoked(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if invalidText(id, maxSessionIDBytes) {
		return false, authentication.ErrInvalidPrincipal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.principals[id]
	return ok, nil
}

func validateSession(session Session) error {
	if invalidText(session.ID, maxSessionIDBytes) || session.Version == 0 {
		return authentication.ErrInvalidCredential
	}
	if err := authentication.ValidatePrincipal(session.Principal, session.CreatedAt); err != nil {
		return err
	}
	if session.CreatedAt.IsZero() || session.ExpiresAt.IsZero() || session.LastSeenAt.IsZero() {
		return authentication.ErrInvalidCredential
	}
	if session.CreatedAt.Location() != time.UTC || session.ExpiresAt.Location() != time.UTC || session.LastSeenAt.Location() != time.UTC {
		return authentication.ErrInvalidCredential
	}
	if session.CreatedAt.After(session.LastSeenAt) || session.LastSeenAt.After(session.ExpiresAt) || !session.CreatedAt.Before(session.ExpiresAt) {
		return authentication.ErrInvalidCredential
	}
	if session.RefreshDigest == ([32]byte{}) {
		return authentication.ErrInvalidCredential
	}
	if !validClient(session.Client) {
		return authentication.ErrInvalidCredential
	}
	return nil
}

func validateTransition(current Session, id string, expectedVersion uint64, next Session) error {
	if next.ID != id || next.ID != current.ID {
		return authentication.ErrInvalidCredential
	}
	if current.Version != expectedVersion || next.Version != current.Version+1 || next.Rotation != current.Rotation+1 {
		return authentication.ErrInvalidCredential
	}
	if !reflect.DeepEqual(next.Principal.Clone(), current.Principal.Clone()) {
		return authentication.ErrInvalidCredential
	}
	if next.CreatedAt != current.CreatedAt || next.ExpiresAt != current.ExpiresAt || next.Client != current.Client {
		return authentication.ErrInvalidCredential
	}
	if next.LastSeenAt.Before(current.LastSeenAt) || next.RefreshDigest == current.RefreshDigest {
		return authentication.ErrInvalidCredential
	}
	return nil
}

func cloneSession(session Session) Session {
	clone := session
	clone.Principal = session.Principal.Clone()
	return clone
}

func validClient(client ClientInfo) bool {
	return validOptionalText(client.UserAgent, maxClientBytes) &&
		validOptionalText(client.IPAddress, maxClientBytes) &&
		validOptionalText(client.DeviceID, maxClientBytes)
}

func invalidText(value string, limit int) bool {
	return value == "" || !utf8.ValidString(value) || len(value) > limit || containsNUL(value)
}

func validOptionalText(value string, limit int) bool {
	return utf8.ValidString(value) && len(value) <= limit && !containsNUL(value)
}

func containsNUL(value string) bool {
	for i := range len(value) {
		if value[i] == 0 {
			return true
		}
	}
	return false
}
