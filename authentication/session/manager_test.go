package session_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/justusschock/go-auth/authentication"
	"github.com/justusschock/go-auth/authentication/session"
	coordination "github.com/justusschock/go-distributed-coordination"
)

// FR-AUTH-21
func TestCreateStoresDigestOnlyAndReturnsCopiedData(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		sessionIDRaw := bytes.Repeat([]byte{6}, 32)
		refreshRaw := bytes.Repeat([]byte{7}, 32)
		store := session.NewMemoryStore()
		revocations := session.NewMemoryRevocationStore()
		manager := newTestManager(t, store, revocations, &recordingCoordinator{}, session.Options{
			Random: bytes.NewReader(append(sessionIDRaw, refreshRaw...)),
		})
		principal := validPrincipal(now)
		client := session.ClientInfo{UserAgent: "browser", IPAddress: "203.0.113.10", DeviceID: "device-1"}

		created, token, err := manager.Create(context.Background(), principal, client)
		if err != nil {
			t.Fatal(err)
		}

		wantID := "sess_" + base64.RawURLEncoding.EncodeToString(sessionIDRaw)
		if created.ID != wantID {
			t.Fatalf("session ID = %q, want independent 32-byte random ID %q", created.ID, wantID)
		}
		wantToken := base64.RawURLEncoding.EncodeToString(refreshRaw)
		if token != wantToken || len(token) != 43 {
			t.Fatalf("token = %q length %d, want exact base64url token", token, len(token))
		}
		stored, err := store.Get(context.Background(), created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.RefreshDigest != sha256.Sum256([]byte(wantToken)) {
			t.Fatalf("stored digest = %x", stored.RefreshDigest)
		}
		if bytes.Contains([]byte(sessionSummary(stored)), []byte(wantToken)) {
			t.Fatalf("stored session exposed raw refresh token: %#v", stored)
		}
		if stored.CreatedAt != now || stored.LastSeenAt != now || stored.ExpiresAt != now.Add(time.Hour) {
			t.Fatalf("stored timestamps = %#v", stored)
		}
		if stored.Version != 1 || stored.Rotation != 0 {
			t.Fatalf("version=%d rotation=%d", stored.Version, stored.Rotation)
		}
		principal.Traits["role"][0] = "mutated"
		client.UserAgent = "mutated"
		if created.Principal.Traits["role"][0] != "admin" || created.Client.UserAgent != "browser" {
			t.Fatalf("Create returned aliased data: %#v %#v", created.Principal, created.Client)
		}
		stored.Principal.Traits["role"][0] = "mutated again"
		again, err := store.Get(context.Background(), created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if again.Principal.Traits["role"][0] != "admin" {
			t.Fatalf("store returned aliased principal: %#v", again.Principal)
		}
	})
}

// FR-AUTH-21
func TestCreateRejectsInvalidBoundsAndRandomFailure(t *testing.T) {
	now := time.Now().UTC()
	for name, options := range map[string]session.Options{
		"missing store":       {Revocations: session.NewMemoryRevocationStore(), Coordinator: &recordingCoordinator{}, ManagerID: "manager", Lifetime: time.Hour},
		"missing revocations": {Store: session.NewMemoryStore(), Coordinator: &recordingCoordinator{}, ManagerID: "manager", Lifetime: time.Hour},
		"missing coordinator": {Store: session.NewMemoryStore(), Revocations: session.NewMemoryRevocationStore(), ManagerID: "manager", Lifetime: time.Hour},
		"missing manager":     {Store: session.NewMemoryStore(), Revocations: session.NewMemoryRevocationStore(), Coordinator: &recordingCoordinator{}, Lifetime: time.Hour},
		"zero lifetime":       {Store: session.NewMemoryStore(), Revocations: session.NewMemoryRevocationStore(), Coordinator: &recordingCoordinator{}, ManagerID: "manager"},
		"too large lifetime":  {Store: session.NewMemoryStore(), Revocations: session.NewMemoryRevocationStore(), Coordinator: &recordingCoordinator{}, ManagerID: "manager", Lifetime: 25 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := session.NewManager(options); !errors.Is(err, authentication.ErrInvalidCredential) {
				t.Fatalf("NewManager() error = %v, want ErrInvalidCredential", err)
			}
		})
	}

	manager := newTestManager(t, session.NewMemoryStore(), session.NewMemoryRevocationStore(), &recordingCoordinator{}, session.Options{
		Random: bytes.NewReader([]byte("short")),
	})
	if _, _, err := manager.Create(context.Background(), validPrincipal(now), session.ClientInfo{}); !errors.Is(err, authentication.ErrInvalidCredential) {
		t.Fatalf("Create() error = %v, want ErrInvalidCredential", err)
	}
	if _, _, err := manager.Create(context.Background(), authentication.Principal{ID: "bad"}, session.ClientInfo{}); !errors.Is(err, authentication.ErrInvalidPrincipal) {
		t.Fatalf("Create(invalid principal) error = %v, want ErrInvalidPrincipal", err)
	}
	longClient := session.ClientInfo{UserAgent: string(bytes.Repeat([]byte{'a'}, 513))}
	if _, _, err := newTestManager(t, session.NewMemoryStore(), session.NewMemoryRevocationStore(), &recordingCoordinator{}, session.Options{
		Random: bytes.NewReader(bytes.Repeat([]byte{1}, 32)),
	}).Create(context.Background(), validPrincipal(now), longClient); !errors.Is(err, authentication.ErrInvalidCredential) {
		t.Fatalf("Create(long client) error = %v, want ErrInvalidCredential", err)
	}
}

// FR-AUTH-22
func TestRotateUsesLeaseAndHasExactlyOneConcurrentWinner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		revocations := session.NewMemoryRevocationStore()
		coordinator := &recordingCoordinator{}
		store := newObservingStore(coordinator)
		random := &lockedReader{chunks: [][]byte{
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 32),
			bytes.Repeat([]byte{3}, 32),
			bytes.Repeat([]byte{4}, 32),
			bytes.Repeat([]byte{5}, 32),
			bytes.Repeat([]byte{6}, 32),
			bytes.Repeat([]byte{7}, 32),
			bytes.Repeat([]byte{8}, 32),
			bytes.Repeat([]byte{9}, 32),
		}}
		manager := newTestManager(t, store, revocations, coordinator, session.Options{
			Random: random,
		})
		created, token, err := manager.Create(context.Background(), validPrincipal(now), session.ClientInfo{UserAgent: "browser"})
		if err != nil {
			t.Fatal(err)
		}

		var wins atomic.Int32
		var replays atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rotated, _, err := manager.Rotate(context.Background(), created.ID, token)
				switch {
				case err == nil:
					wins.Add(1)
					if rotated.Version != 2 || rotated.Rotation != 1 || rotated.RefreshDigest == created.RefreshDigest {
						t.Errorf("rotated session = %#v", rotated)
					}
				case errors.Is(err, authentication.ErrReplay), errors.Is(err, authentication.ErrUnauthenticated):
					replays.Add(1)
				default:
					t.Errorf("Rotate() error = %v", err)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 || replays.Load() != 7 {
			t.Fatalf("wins=%d replays=%d", wins.Load(), replays.Load())
		}
		requests := coordinator.requests()
		if len(requests) != 8 {
			t.Fatalf("acquire calls = %d, want 8", len(requests))
		}
		for _, request := range requests {
			if request.Key != "auth/session/"+created.ID || request.Owner != "manager-a" || request.TTL != 10*time.Second || !request.Wait {
				t.Fatalf("Acquire request = %#v", request)
			}
		}
		if store.getsWithLease.Load() != 8 || store.getsWithoutLock.Load() != 0 {
			t.Fatalf("Get calls with lease = %d, without = %d; want every rotation to load the session under its lease",
				store.getsWithLease.Load(), store.getsWithoutLock.Load())
		}
	})
}

// FR-AUTH-22
func TestRotateFailsClosedOnLeaseAndStoreAmbiguity(t *testing.T) {
	for name, setup := range map[string]func(*recordingCoordinator, *observingStore){
		"canceled acquire": func(c *recordingCoordinator, _ *observingStore) {
			c.acquireErr = context.Canceled
		},
		"lease lost before cas": func(c *recordingCoordinator, _ *observingStore) {
			c.lostBeforeRelease = true
		},
		"release failure": func(c *recordingCoordinator, _ *observingStore) {
			c.releaseErr = errors.New("backend release details")
		},
		"cas conflict": func(_ *recordingCoordinator, store *observingStore) {
			store.failNextCompareAndSwap(authentication.ErrReplay)
		},
		"backend ambiguity": func(_ *recordingCoordinator, store *observingStore) {
			store.failNextCompareAndSwap(errors.New("storage backend leaked detail"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now().UTC()
				coordinator := &recordingCoordinator{}
				store := newObservingStore(coordinator)
				revocations := session.NewMemoryRevocationStore()
				manager := newTestManager(t, store, revocations, coordinator, session.Options{
					Random: &lockedReader{chunks: [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)}},
				})
				created, token, err := manager.Create(context.Background(), validPrincipal(now), session.ClientInfo{})
				if err != nil {
					t.Fatal(err)
				}
				setup(coordinator, store)
				_, _, err = manager.Rotate(context.Background(), created.ID, token)
				if err == nil {
					t.Fatal("Rotate() succeeded, want fail closed")
				}
				if errors.Is(err, coordination.ErrLeaseLost) || errors.Is(err, context.Canceled) || errors.Is(err, authentication.ErrReplay) {
					if name == "release failure" && coordinator.releaseCount("auth/session/"+created.ID) != 1 {
						t.Fatalf("Release called %d times, want exactly once", coordinator.releaseCount("auth/session/"+created.ID))
					}
					return
				}
				if !errors.Is(err, authentication.ErrUnauthenticated) {
					t.Fatalf("Rotate() error = %v, want sanitized fail-closed error", err)
				}
				if name == "release failure" && coordinator.releaseCount("auth/session/"+created.ID) != 1 {
					t.Fatalf("Release called %d times, want exactly once", coordinator.releaseCount("auth/session/"+created.ID))
				}
			})
		})
	}
}

// FR-AUTH-21
func TestValidateAndRotateRejectCorruptDurableRecords(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	baseAt := func(now time.Time) session.Session {
		return session.Session{
			ID:            "sess_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
			Version:       1,
			Principal:     validPrincipal(now),
			CreatedAt:     now,
			ExpiresAt:     now.Add(time.Hour),
			LastSeenAt:    now,
			RefreshDigest: sha256.Sum256([]byte(token)),
			Rotation:      0,
			Client:        session.ClientInfo{UserAgent: "browser"},
		}
	}
	cases := map[string]func(session.Session) session.Session{
		"id mismatch": func(s session.Session) session.Session {
			s.ID = "sess_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
			return s
		},
		"zero version": func(s session.Session) session.Session {
			s.Version = 0
			return s
		},
		"changed client bound": func(s session.Session) session.Session {
			s.Client.UserAgent = string(bytes.Repeat([]byte{'a'}, 513))
			return s
		},
		"non utc created": func(s session.Session) session.Session {
			s.CreatedAt = s.CreatedAt.In(time.FixedZone("offset", 3600))
			return s
		},
		"last seen before created": func(s session.Session) session.Session {
			s.LastSeenAt = s.CreatedAt.Add(-time.Second)
			return s
		},
		"zero refresh digest": func(s session.Session) session.Session {
			s.RefreshDigest = [32]byte{}
			return s
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now().UTC()
				base := baseAt(now)
				store := &corruptStore{session: mutate(base)}
				coordinator := &recordingCoordinator{}
				manager := newTestManager(t, store, session.NewMemoryRevocationStore(), coordinator, session.Options{
					Random: &lockedReader{chunks: [][]byte{bytes.Repeat([]byte{5}, 32)}},
				})
				if _, err := manager.Validate(context.Background(), base.ID); !errors.Is(err, authentication.ErrInvalidCredential) {
					t.Fatalf("Validate() error = %v, want ErrInvalidCredential", err)
				}
				if _, _, err := manager.Rotate(context.Background(), base.ID, token); !errors.Is(err, authentication.ErrInvalidCredential) {
					t.Fatalf("Rotate() error = %v, want ErrInvalidCredential", err)
				}
			})
		})
	}
}

// FR-AUTH-21
func TestValidateAndRotateCheckDurableRevocationAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		store := session.NewMemoryStore()
		revocations := session.NewMemoryRevocationStore()
		manager := newTestManager(t, store, revocations, &recordingCoordinator{}, session.Options{
			Random: &lockedReader{chunks: [][]byte{
				bytes.Repeat([]byte{1}, 32),
				bytes.Repeat([]byte{2}, 32),
				bytes.Repeat([]byte{3}, 32),
				bytes.Repeat([]byte{4}, 32),
				bytes.Repeat([]byte{5}, 32),
				bytes.Repeat([]byte{6}, 32),
			}},
		})
		created, token, err := manager.Create(context.Background(), validPrincipal(now), session.ClientInfo{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Validate(context.Background(), created.ID); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if err := manager.Revoke(context.Background(), created.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Validate(context.Background(), created.ID); !errors.Is(err, authentication.ErrUnauthenticated) {
			t.Fatalf("Validate(revoked) error = %v", err)
		}
		if _, _, err := manager.Rotate(context.Background(), created.ID, token); !errors.Is(err, authentication.ErrUnauthenticated) {
			t.Fatalf("Rotate(revoked) error = %v", err)
		}

		created, token, err = manager.Create(context.Background(), validPrincipal(now), session.ClientInfo{})
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.RevokePrincipal(context.Background(), created.Principal.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Validate(context.Background(), created.ID); !errors.Is(err, authentication.ErrUnauthenticated) {
			t.Fatalf("Validate(principal revoked) error = %v", err)
		}
		if _, _, err := manager.Rotate(context.Background(), created.ID, token); !errors.Is(err, authentication.ErrUnauthenticated) {
			t.Fatalf("Rotate(principal revoked) error = %v", err)
		}

		// A principal that is not revoked, so only the session lifetime applies.
		other := validPrincipal(now)
		other.ID = "principal-2"
		created, _, err = manager.Create(context.Background(), other, session.ClientInfo{})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Hour - time.Nanosecond)
		if _, err := manager.Validate(context.Background(), created.ID); err != nil {
			t.Fatalf("Validate(last valid instant) error = %v", err)
		}
		time.Sleep(time.Nanosecond)
		if _, err := manager.Validate(context.Background(), created.ID); !errors.Is(err, authentication.ErrExpired) {
			t.Fatalf("Validate(expired) error = %v", err)
		}
	})
}

// FR-AUTH-22
func TestSessionStoresAreConcurrencySafeAndFenced(t *testing.T) {
	now := time.Unix(1500, 0).UTC()
	store := session.NewMemoryStore()
	initial := session.Session{
		ID:            "sess_123",
		Version:       1,
		Principal:     validPrincipal(now),
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
		LastSeenAt:    now,
		RefreshDigest: sha256.Sum256([]byte("one")),
		Client:        session.ClientInfo{UserAgent: "browser"},
	}
	if err := store.Create(context.Background(), initial); err != nil {
		t.Fatal(err)
	}

	next := initial
	next.Version = 2
	next.Rotation = 1
	next.RefreshDigest = sha256.Sum256([]byte("two"))
	if err := store.CompareAndSwap(context.Background(), initial.ID, 1, 2, next); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	if err := store.CompareAndSwap(context.Background(), initial.ID, 1, 1, next); !errors.Is(err, authentication.ErrReplay) {
		t.Fatalf("stale version CAS error = %v, want ErrReplay", err)
	}
	if err := store.CompareAndSwap(context.Background(), initial.ID, 2, 1, next); !errors.Is(err, coordination.ErrLeaseLost) {
		t.Fatalf("stale fence CAS error = %v, want ErrLeaseLost", err)
	}
	results, err := store.ListByPrincipal(context.Background(), initial.Principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Version != 2 {
		t.Fatalf("ListByPrincipal() = %#v", results)
	}
}

// FR-AUTH-22
func TestMemoryStoreCompareAndSwapRejectsInvalidTransitions(t *testing.T) {
	now := time.Unix(1510, 0).UTC()
	initial := session.Session{
		ID:            "sess_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		Version:       3,
		Principal:     validPrincipal(now),
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
		LastSeenAt:    now,
		RefreshDigest: sha256.Sum256([]byte("one")),
		Rotation:      2,
		Client:        session.ClientInfo{UserAgent: "browser"},
	}
	cases := map[string]func(session.Session) session.Session{
		"id changes": func(s session.Session) session.Session {
			s.ID = "sess_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
			return s
		},
		"version skips": func(s session.Session) session.Session {
			s.Version = 5
			s.Rotation = 3
			return s
		},
		"rotation skips": func(s session.Session) session.Session {
			s.Version = 4
			s.Rotation = 4
			return s
		},
		"principal changes": func(s session.Session) session.Session {
			s.Version = 4
			s.Rotation = 3
			s.Principal.ID = "principal-2"
			return s
		},
		"created changes": func(s session.Session) session.Session {
			s.Version = 4
			s.Rotation = 3
			s.CreatedAt = s.CreatedAt.Add(time.Second)
			return s
		},
		"expiry changes": func(s session.Session) session.Session {
			s.Version = 4
			s.Rotation = 3
			s.ExpiresAt = s.ExpiresAt.Add(time.Second)
			return s
		},
		"client changes": func(s session.Session) session.Session {
			s.Version = 4
			s.Rotation = 3
			s.Client.DeviceID = "new-device"
			return s
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			store := session.NewMemoryStore()
			if err := store.Create(context.Background(), initial); err != nil {
				t.Fatal(err)
			}
			next := mutate(initial)
			next.RefreshDigest = sha256.Sum256([]byte(name))
			if err := store.CompareAndSwap(context.Background(), initial.ID, initial.Version, 4, next); !errors.Is(err, authentication.ErrInvalidCredential) {
				t.Fatalf("CompareAndSwap() error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

func TestRecordingCoordinatorEnforcesExclusiveMonotonicLeases(t *testing.T) {
	coordinator := &recordingCoordinator{}
	first, err := coordinator.Acquire(context.Background(), coordination.AcquireRequest{
		Key:   "auth/session/a",
		Owner: "manager-a",
		TTL:   10 * time.Second,
		Wait:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Acquire(context.Background(), coordination.AcquireRequest{
		Key:   "auth/session/a",
		Owner: "manager-b",
		TTL:   10 * time.Second,
		Wait:  false,
	}); !errors.Is(err, coordination.ErrLeaseLost) {
		t.Fatalf("second Acquire() error = %v, want ErrLeaseLost", err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := coordinator.Acquire(context.Background(), coordination.AcquireRequest{
		Key:   "auth/session/a",
		Owner: "manager-b",
		TTL:   10 * time.Second,
		Wait:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Info().Token >= second.Info().Token {
		t.Fatalf("tokens not monotonic: first=%d second=%d", first.Info().Token, second.Info().Token)
	}
}

func newTestManager(t *testing.T, store session.Store, revocations session.RevocationStore, coordinator coordination.Backend, overrides session.Options) *session.Manager {
	t.Helper()
	options := session.Options{
		Store:       store,
		Revocations: revocations,
		Coordinator: coordinator,
		ManagerID:   "manager-a",
		Lifetime:    time.Hour,
	}
	if overrides.Random != nil {
		options.Random = overrides.Random
	}
	if overrides.ManagerID != "" {
		options.ManagerID = overrides.ManagerID
	}
	if overrides.Lifetime != 0 {
		options.Lifetime = overrides.Lifetime
	}
	if overrides.Clock != nil {
		options.Clock = overrides.Clock
	}
	manager, err := session.NewManager(options)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func validPrincipal(now time.Time) authentication.Principal {
	return authentication.Principal{
		ID:              "principal-1",
		Issuer:          "issuer",
		Subject:         "subject",
		AuthenticatedAt: now.Add(-time.Minute),
		ExpiresAt:       now.Add(2 * time.Hour),
		Traits:          map[string][]string{"role": {"admin"}},
		Methods:         []string{"password"},
	}
}

func sessionSummary(value session.Session) string {
	return value.ID + value.Principal.ID + value.Client.UserAgent
}

type lockedReader struct {
	mu     sync.Mutex
	chunks [][]byte
}

func (r *lockedReader) Read(out []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	copy(out, chunk)
	return len(chunk), nil
}

type corruptStore struct {
	session session.Session
}

func (s *corruptStore) Create(context.Context, session.Session) error {
	return errors.New("not used")
}

func (s *corruptStore) Get(ctx context.Context, id string) (session.Session, error) {
	if err := ctx.Err(); err != nil {
		return session.Session{}, err
	}
	return s.session, nil
}

func (s *corruptStore) CompareAndSwap(context.Context, string, uint64, uint64, session.Session) error {
	return nil
}

func (s *corruptStore) ListByPrincipal(context.Context, string) ([]session.Session, error) {
	return nil, errors.New("not used")
}

// TestSuppliedClockIsHonoured runs on the wall clock with a principal that is
// valid only years from now, so only Options.Clock can accept it; moving that
// clock drives rotation timestamps and session expiry.
// FR-AUTH-27
func TestSuppliedClockIsHonoured(t *testing.T) {
	now := time.Date(2031, 3, 4, 5, 6, 7, 0, time.FixedZone("UTC+2", 2*60*60))
	store := session.NewMemoryStore()
	manager := newTestManager(t, store, session.NewMemoryRevocationStore(), &recordingCoordinator{}, session.Options{
		Clock: func() time.Time { return now },
	})
	created, token, err := manager.Create(context.Background(), validPrincipal(now.UTC()), session.ClientInfo{})
	if err != nil {
		t.Fatalf("Create() at supplied time error = %v", err)
	}
	if !created.CreatedAt.Equal(now) || created.CreatedAt.Location() != time.UTC || !created.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("timestamps = %v..%v, want %v..%v in UTC", created.CreatedAt, created.ExpiresAt, now.UTC(), now.Add(time.Hour).UTC())
	}

	now = now.Add(30 * time.Minute)
	rotated, _, err := manager.Rotate(context.Background(), created.ID, token)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if !rotated.LastSeenAt.Equal(now) {
		t.Fatalf("LastSeenAt = %v, want %v", rotated.LastSeenAt, now.UTC())
	}

	now = now.Add(30 * time.Minute)
	if _, err := manager.Validate(context.Background(), created.ID); !errors.Is(err, authentication.ErrExpired) {
		t.Fatalf("Validate() at supplied expiry error = %v, want ErrExpired", err)
	}
}
