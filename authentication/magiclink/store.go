package magiclink

import (
	"context"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/justusschock/auth/authentication"
)

const maxPurposeBytes = 256

// Record is the durable state for one magic link. Digest is SHA-256 over the
// returned base64url token; the raw token is never stored.
type Record struct {
	Digest      [32]byte
	Principal   authentication.Principal
	RedirectURI string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Purpose     string
}

// Store persists magic-link state.
//
// Create must fail with authentication.ErrReplay when the digest exists.
// Consume must atomically remove and return the record for a digest, and
// return authentication.ErrReplay when none exists, so that concurrent
// callers cannot both consume it.
type Store interface {
	Create(context.Context, Record) error
	Consume(context.Context, [32]byte) (Record, error)
}

// MemoryStore is a process-local Store for tests and single-process callers.
// Distributed deployments should provide a durable atomic implementation.
type MemoryStore struct {
	mu      sync.Mutex
	records map[[32]byte]Record
}

// NewMemoryStore returns an empty memory-backed store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[[32]byte]Record)}
}

// Create stores a valid record unless its digest is already present.
func (s *MemoryStore) Create(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validRecord(record) {
		return authentication.ErrInvalidCallback
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.Digest]; exists {
		return authentication.ErrReplay
	}
	s.records[record.Digest] = cloneRecord(record)
	return nil
}

// Consume atomically removes and returns the record for digest.
func (s *MemoryStore) Consume(ctx context.Context, digest [32]byte) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if digest == [32]byte{} {
		return Record{}, authentication.ErrInvalidCallback
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[digest]
	if !exists {
		return Record{}, authentication.ErrReplay
	}
	delete(s.records, digest)
	return cloneRecord(record), nil
}

func validRecord(record Record) bool {
	return record.Digest != [32]byte{} &&
		validText(record.RedirectURI) &&
		record.IssuedAt.Location() == time.UTC &&
		record.ExpiresAt.Location() == time.UTC &&
		!record.IssuedAt.IsZero() &&
		record.IssuedAt.Before(record.ExpiresAt) &&
		validOptionalText(record.Purpose, maxPurposeBytes)
}

func cloneRecord(record Record) Record {
	record.Principal = record.Principal.Clone()
	return record
}

func validText(value string) bool {
	return value != "" && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0
}

func validOptionalText(value string, limit int) bool {
	return utf8.ValidString(value) && strings.IndexByte(value, 0) < 0 && len(value) <= limit
}
