package apitoken

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/justusschock/go-auth/authentication"
)

const (
	maxNameBytes     = 256
	maxScopes        = 64
	maxScopeBytes    = 256
	maxIdentityBytes = 1024
	// maxTraits leaves room for ScopeTrait and TokenIDTrait within the
	// authentication.Principal trait bound.
	maxTraits          = 126
	maxTraitNameBytes  = 256
	maxTraitValues     = 128
	maxTraitValueBytes = 4096
)

// ErrNotFound reports that no token record exists for the requested ID, or
// that it belongs to another principal.
var ErrNotFound = errors.New("apitoken: not found")

// Identity is the durable subset of an authentication.Principal that an API
// token acts for. Authentication rebuilds a Principal from it with fresh
// lifetime fields, the token scopes, and the token ID.
type Identity struct {
	ID      string
	Issuer  string
	Subject string
	Traits  map[string][]string
}

// Clone returns an independently owned identity.
func (i Identity) Clone() Identity {
	clone := i
	if i.Traits != nil {
		clone.Traits = make(map[string][]string, len(i.Traits))
		for name, values := range i.Traits {
			clone.Traits[name] = slices.Clone(values)
		}
	}
	return clone
}

// IdentityFromPrincipal extracts the durable identity of principal.
func IdentityFromPrincipal(principal authentication.Principal) Identity {
	clone := principal.Clone()
	return Identity{ID: clone.ID, Issuer: clone.Issuer, Subject: clone.Subject, Traits: clone.Traits}
}

// Record is the durable state of one API token. Digest is the keyed hash of
// the full token (see Options.Pepper); the raw token is never stored. Records
// returned by Manager have a zero Digest.
type Record struct {
	ID         string
	Digest     [32]byte
	Principal  Identity
	Name       string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
}

// Revoked reports whether the token has been revoked.
func (r Record) Revoked() bool {
	return !r.RevokedAt.IsZero()
}

// Clone returns an independently owned record.
func (r Record) Clone() Record {
	clone := r
	clone.Principal = r.Principal.Clone()
	clone.Scopes = slices.Clone(r.Scopes)
	return clone
}

// Store persists API token records. Implementations must return ErrNotFound
// for unknown IDs and authentication.ErrReplay when Create reuses an ID.
// Revoke must keep the first revocation time when called repeatedly.
type Store interface {
	Create(context.Context, Record) error
	Get(ctx context.Context, id string) (Record, error)
	ListByPrincipal(ctx context.Context, principalID string) ([]Record, error)
	Revoke(ctx context.Context, id string, at time.Time) error
	TouchLastUsed(ctx context.Context, id string, at time.Time) error
}

// MemoryStore is a process-local Store for tests and single-process callers.
// Distributed deployments should provide a durable implementation.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty memory-backed store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

// Create stores a new record if its ID is unused.
func (s *MemoryStore) Create(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ValidRecord(record) {
		return authentication.ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.ID]; exists {
		return authentication.ErrReplay
	}
	s.records[record.ID] = record.Clone()
	return nil
}

// Get returns the record with id.
func (s *MemoryStore) Get(ctx context.Context, id string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if !ValidID(id) {
		return Record{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return record.Clone(), nil
}

// ListByPrincipal returns the principal's records ordered by creation time
// and ID.
func (s *MemoryStore) ListByPrincipal(ctx context.Context, principalID string) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validText(principalID, maxIdentityBytes) {
		return nil, authentication.ErrInvalidPrincipal
	}
	s.mu.Lock()
	out := make([]Record, 0)
	for _, record := range s.records {
		if record.Principal.ID == principalID {
			out = append(out, record.Clone())
		}
	}
	s.mu.Unlock()
	sortRecords(out)
	return out, nil
}

// Revoke marks the record revoked at the given time unless already revoked.
func (s *MemoryStore) Revoke(ctx context.Context, id string, at time.Time) error {
	return s.update(ctx, id, at, func(record *Record) {
		if record.RevokedAt.IsZero() {
			record.RevokedAt = at
		}
	})
}

// TouchLastUsed advances the record's last-used time.
func (s *MemoryStore) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	return s.update(ctx, id, at, func(record *Record) {
		if at.After(record.LastUsedAt) {
			record.LastUsedAt = at
		}
	})
}

func (s *MemoryStore) update(ctx context.Context, id string, at time.Time, apply func(*Record)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ValidID(id) {
		return ErrNotFound
	}
	if !validTime(at) {
		return authentication.ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return ErrNotFound
	}
	apply(&record)
	s.records[id] = record
	return nil
}

func sortRecords(records []Record) {
	slices.SortFunc(records, func(a, b Record) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
}

// ValidRecord reports whether record is well formed. Store implementations
// may use it to reject corrupted input.
func ValidRecord(record Record) bool {
	if !ValidID(record.ID) || zeroDigest(record.Digest) || !validIdentity(record.Principal) {
		return false
	}
	if !validText(record.Name, maxNameBytes) || !validScopes(record.Scopes) {
		return false
	}
	if !validTime(record.CreatedAt) || !validTime(record.ExpiresAt) || !record.CreatedAt.Before(record.ExpiresAt) {
		return false
	}
	if !record.LastUsedAt.IsZero() && !validTime(record.LastUsedAt) {
		return false
	}
	return record.RevokedAt.IsZero() || validTime(record.RevokedAt)
}

func validIdentity(identity Identity) bool {
	if !validText(identity.ID, maxIdentityBytes) || !validText(identity.Issuer, maxIdentityBytes) || !validText(identity.Subject, maxIdentityBytes) {
		return false
	}
	if len(identity.Traits) > maxTraits {
		return false
	}
	for name, values := range identity.Traits {
		if !validText(name, maxTraitNameBytes) || len(values) > maxTraitValues || reservedTrait(name) {
			return false
		}
		for _, value := range values {
			if !validOptionalText(value, maxTraitValueBytes) {
				return false
			}
		}
	}
	return true
}

func reservedTrait(name string) bool {
	return name == ScopeTrait || name == TokenIDTrait
}

// validScopes requires bounded, unique scope tokens as in RFC 6749 section 3.3.
func validScopes(scopes []string) bool {
	if len(scopes) > maxScopes {
		return false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope == "" || len(scope) > maxScopeBytes {
			return false
		}
		for index := range len(scope) {
			c := scope[index]
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return false
			}
		}
		if _, dup := seen[scope]; dup {
			return false
		}
		seen[scope] = struct{}{}
	}
	return true
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func validText(value string, limit int) bool {
	return value != "" && validOptionalText(value, limit)
}

func validOptionalText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0
}
