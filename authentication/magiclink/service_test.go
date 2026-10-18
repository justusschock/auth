package magiclink_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/justusschock/auth/authentication"
	"github.com/justusschock/auth/authentication/magiclink"
)

// FR-AUTH-17
func TestMagicLinkHasExactlyOneConcurrentWinner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		service := newTestService(t, magiclink.Options{
			Store:        magiclink.NewMemoryStore(),
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          5 * time.Minute,
			Random:       bytes.NewReader(bytes.Repeat([]byte{2}, 32)),
		})

		link, err := service.Issue(context.Background(), validPrincipal(now), "https://app.example/after")
		if err != nil {
			t.Fatal(err)
		}

		var wins atomic.Int32
		var replays atomic.Int32
		var wg sync.WaitGroup
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := service.Consume(context.Background(), link.Token)
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, authentication.ErrReplay):
					replays.Add(1)
				default:
					t.Errorf("Consume() error = %v", err)
				}
			}()
		}
		wg.Wait()

		if wins.Load() != 1 || replays.Load() != 31 {
			t.Fatalf("wins=%d replays=%d", wins.Load(), replays.Load())
		}
	})
}

// FR-AUTH-17
func TestIssueStoresOnlyDigestAndReturnsExactBase64URLToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		rawToken := bytes.Repeat([]byte{7}, 32)
		store := &recordingStore{}
		service := newTestService(t, magiclink.Options{
			Store:        store,
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          10 * time.Minute,
			Random:       bytes.NewReader(rawToken),
			Purpose:      "login",
		})

		link, err := service.Issue(context.Background(), validPrincipal(now), "https://app.example/after")
		if err != nil {
			t.Fatal(err)
		}

		wantToken := base64.RawURLEncoding.EncodeToString(rawToken)
		if link.Token != wantToken || len(link.Token) != 43 {
			t.Fatalf("Token = %q length %d, want exact 32-byte base64url token", link.Token, len(link.Token))
		}
		if link.URL == nil || link.URL.Query().Get("token") != wantToken {
			t.Fatalf("URL = %v, want token query", link.URL)
		}
		if got := link.URL.String(); got != "https://app.example/magic?token="+wantToken {
			t.Fatalf("URL = %q", got)
		}
		if store.created == nil {
			t.Fatal("store was not called")
		}
		if store.created.Digest != sha256.Sum256([]byte(wantToken)) {
			t.Fatalf("stored digest = %x", store.created.Digest)
		}
		if store.created.IssuedAt != now || store.created.ExpiresAt != now.Add(10*time.Minute) || store.created.Purpose != "login" {
			t.Fatalf("stored timing/purpose = %#v", store.created)
		}
		if store.created.RedirectURI != "https://app.example/after" {
			t.Fatalf("stored redirect = %q", store.created.RedirectURI)
		}
		if strings.Contains(recordSummary(*store.created), wantToken) || strings.Contains(recordSummary(*store.created), string(rawToken)) {
			t.Fatalf("record exposes raw token: %#v", store.created)
		}
	})
}

// FR-AUTH-18
func TestIssueRejectsNonExactOrInsecureRedirectsAndBoundsTTL(t *testing.T) {
	now := time.Now().UTC()
	for name, ttl := range map[string]time.Duration{
		"zero":      0,
		"negative":  -time.Second,
		"too large": 15*time.Minute + time.Nanosecond,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := magiclink.NewService(magiclink.Options{
				Store:        magiclink.NewMemoryStore(),
				BaseURL:      "https://app.example/magic",
				RedirectURIs: []string{"https://app.example/after"},
				TTL:          ttl,
			})
			if !errors.Is(err, authentication.ErrInvalidCredential) {
				t.Fatalf("NewService() error = %v, want ErrInvalidCredential", err)
			}
		})
	}

	for name, options := range map[string]magiclink.Options{
		"insecure base URL": {
			Store: magiclink.NewMemoryStore(), BaseURL: "http://app.example/magic", RedirectURIs: []string{"https://app.example/after"}, TTL: time.Minute,
		},
		"insecure redirect": {
			Store: magiclink.NewMemoryStore(), BaseURL: "https://app.example/magic", RedirectURIs: []string{"http://app.example/after"}, TTL: time.Minute,
		},
		"redirect with fragment": {
			Store: magiclink.NewMemoryStore(), BaseURL: "https://app.example/magic", RedirectURIs: []string{"https://app.example/after#fragment"}, TTL: time.Minute,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := magiclink.NewService(options)
			if !errors.Is(err, authentication.ErrInvalidCallback) && !errors.Is(err, authentication.ErrInvalidCredential) {
				t.Fatalf("NewService() error = %v", err)
			}
		})
	}

	service := newTestService(t, magiclink.Options{
		Store:        magiclink.NewMemoryStore(),
		BaseURL:      "https://app.example/magic",
		RedirectURIs: []string{"https://app.example/after"},
		TTL:          time.Minute,
		Random:       bytes.NewReader(bytes.Repeat([]byte{1}, 32)),
	})
	for _, redirectURI := range []string{"", "https://app.example/after/", "https://evil.example/after"} {
		if _, err := service.Issue(context.Background(), validPrincipal(now), redirectURI); !errors.Is(err, authentication.ErrInvalidCallback) {
			t.Fatalf("Issue(%q) error = %v, want ErrInvalidCallback", redirectURI, err)
		}
	}
}

// NFR-AUTH-04
func TestIssueHandlesRandomFailureAndContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		store := &recordingStore{}
		service := newTestService(t, magiclink.Options{
			Store:        store,
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          time.Minute,
			Random:       bytes.NewReader([]byte("short")),
		})
		if _, err := service.Issue(context.Background(), validPrincipal(now), "https://app.example/after"); !errors.Is(err, authentication.ErrInvalidCredential) {
			t.Fatalf("Issue() error = %v, want ErrInvalidCredential", err)
		}
		if store.created != nil {
			t.Fatal("store was called after random failure")
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		service = newTestService(t, magiclink.Options{
			Store:        magiclink.NewMemoryStore(),
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          time.Minute,
			Random:       bytes.NewReader(bytes.Repeat([]byte{3}, 32)),
		})
		if _, err := service.Issue(ctx, validPrincipal(now), "https://app.example/after"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Issue(canceled) error = %v, want context.Canceled", err)
		}
		if _, err := service.Consume(ctx, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))); !errors.Is(err, context.Canceled) {
			t.Fatalf("Consume(canceled) error = %v, want context.Canceled", err)
		}
	})
}

// FR-AUTH-17
func TestConsumeRejectsMalformedTokenBeforeStoreAccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		service := newTestService(t, magiclink.Options{
			Store:        &panicStore{},
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          time.Minute,
			Random:       bytes.NewReader(bytes.Repeat([]byte{4}, 32)),
		})

		for _, token := range []string{"", "not-base64url-token!", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33))} {
			if _, err := service.Consume(context.Background(), token); !errors.Is(err, authentication.ErrInvalidCredential) {
				t.Fatalf("Consume(%q) error = %v, want ErrInvalidCredential", token, err)
			}
		}
	})
}

// FR-AUTH-17
func TestConsumeAtomicallyConsumesBeforeExpiryAndPrincipalValidation(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))

	t.Run("expired record is consumed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			now := time.Now().UTC()
			store := magiclink.NewMemoryStore()
			digest := sha256.Sum256([]byte(token))
			if err := store.Create(context.Background(), magiclink.Record{
				Digest:      digest,
				Principal:   validPrincipal(now.Add(-time.Hour)),
				RedirectURI: "https://app.example/after",
				IssuedAt:    now.Add(-2 * time.Hour),
				ExpiresAt:   now.Add(-time.Minute),
				Purpose:     "login",
			}); err != nil {
				t.Fatal(err)
			}
			service := newTestService(t, magiclink.Options{
				Store:        store,
				BaseURL:      "https://app.example/magic",
				RedirectURIs: []string{"https://app.example/after"},
				TTL:          time.Minute,
			})
			if _, err := service.Consume(context.Background(), token); !errors.Is(err, authentication.ErrExpired) {
				t.Fatalf("Consume() error = %v, want ErrExpired", err)
			}
			if _, err := store.Consume(context.Background(), digest); !errors.Is(err, authentication.ErrReplay) {
				t.Fatalf("record was not consumed before expiry validation: %v", err)
			}
		})
	})

	t.Run("invalid principal is consumed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			now := time.Now().UTC()
			store := magiclink.NewMemoryStore()
			digest := sha256.Sum256([]byte(token))
			if err := store.Create(context.Background(), magiclink.Record{
				Digest:      digest,
				Principal:   authentication.Principal{ID: "bad"},
				RedirectURI: "https://app.example/after",
				IssuedAt:    now,
				ExpiresAt:   now.Add(time.Minute),
				Purpose:     "login",
			}); err != nil {
				t.Fatal(err)
			}
			service := newTestService(t, magiclink.Options{
				Store:        store,
				BaseURL:      "https://app.example/magic",
				RedirectURIs: []string{"https://app.example/after"},
				TTL:          time.Minute,
			})
			if _, err := service.Consume(context.Background(), token); !errors.Is(err, authentication.ErrUnauthenticated) {
				t.Fatalf("Consume() error = %v, want ErrUnauthenticated", err)
			}
			if _, err := store.Consume(context.Background(), digest); !errors.Is(err, authentication.ErrReplay) {
				t.Fatalf("record was not consumed before principal validation: %v", err)
			}
		})
	})
}

// NFR-AUTH-07
func TestPrincipalAndLinkCopyIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		store := magiclink.NewMemoryStore()
		principal := validPrincipal(now)
		principal.Traits = map[string][]string{"groups": {"admin"}}
		principal.Methods = []string{"magiclink", "saml"}
		service := newTestService(t, magiclink.Options{
			Store:        store,
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          time.Minute,
			Random:       bytes.NewReader(bytes.Repeat([]byte{6}, 32)),
		})

		link, err := service.Issue(context.Background(), principal, "https://app.example/after")
		if err != nil {
			t.Fatal(err)
		}
		principal.Traits["groups"][0] = "mutated"
		principal.Methods[0] = "mutated"
		link.URL.Host = "mutated.example"

		got, err := service.Consume(context.Background(), link.Token)
		if err != nil {
			t.Fatal(err)
		}
		if got.Traits["groups"][0] != "admin" || got.Methods[1] != "saml" {
			t.Fatalf("principal aliases caller state: %#v", got)
		}
		got.Traits["groups"][0] = "changed"
		got.Methods[0] = "changed"
		if got.Traits["groups"][0] != "changed" {
			t.Fatal("test mutation failed")
		}
	})
}

// NFR-AUTH-01
func TestStoreContractValidationAndSanitizedErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		store := magiclink.NewMemoryStore()
		if err := store.Create(context.Background(), magiclink.Record{}); !errors.Is(err, authentication.ErrInvalidCallback) {
			t.Fatalf("Create(empty) error = %v, want ErrInvalidCallback", err)
		}

		rawStoreError := errors.New("database leaked token secret-token-value")
		service := newTestService(t, magiclink.Options{
			Store:        &recordingStore{createErr: rawStoreError},
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          time.Minute,
			Random:       bytes.NewReader(bytes.Repeat([]byte{8}, 32)),
		})
		_, err := service.Issue(context.Background(), validPrincipal(now), "https://app.example/after")
		assertSanitized(t, err, authentication.ErrInvalidCallback, "secret-token-value")

		token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
		service = newTestService(t, magiclink.Options{
			Store:        &recordingStore{consumeErr: rawStoreError},
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          time.Minute,
		})
		_, err = service.Consume(context.Background(), token)
		assertSanitized(t, err, authentication.ErrUnauthenticated, "secret-token-value")
	})
}

func newTestService(t testing.TB, options magiclink.Options) *magiclink.Service {
	t.Helper()
	service, err := magiclink.NewService(options)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validPrincipal(now time.Time) authentication.Principal {
	return authentication.Principal{
		ID:              "issuer|user",
		Issuer:          "issuer",
		Subject:         "user",
		AuthenticatedAt: now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
		Methods:         []string{"magiclink"},
	}
}

func recordSummary(record magiclink.Record) string {
	return record.RedirectURI + record.Purpose + record.Principal.ID + record.Principal.Issuer + record.Principal.Subject
}

func assertSanitized(t testing.TB, err, want error, secret string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error %q contains secret %q", err, secret)
	}
}

type recordingStore struct {
	created    *magiclink.Record
	createErr  error
	consumeErr error
	record     magiclink.Record
}

func (s *recordingStore) Create(ctx context.Context, record magiclink.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cloned := cloneRecord(record)
	s.created = &cloned
	if s.createErr != nil {
		return s.createErr
	}
	return nil
}

func (s *recordingStore) Consume(ctx context.Context, digest [32]byte) (magiclink.Record, error) {
	if err := ctx.Err(); err != nil {
		return magiclink.Record{}, err
	}
	if s.consumeErr != nil {
		return magiclink.Record{}, s.consumeErr
	}
	if s.record.Digest != digest {
		return magiclink.Record{}, authentication.ErrReplay
	}
	return cloneRecord(s.record), nil
}

type panicStore struct{}

func (panicStore) Create(context.Context, magiclink.Record) error {
	panic("Create must not be called")
}

func (panicStore) Consume(context.Context, [32]byte) (magiclink.Record, error) {
	panic("Consume must not be called")
}

func cloneRecord(record magiclink.Record) magiclink.Record {
	record.Principal = record.Principal.Clone()
	return record
}

var _ magiclink.Store = (*recordingStore)(nil)
var _ magiclink.Store = panicStore{}
var _ io.Reader = (*bytes.Reader)(nil)
var _ *url.URL

// TestConsumeHonorsTTLBoundary advances virtual time to the last valid instant
// and to the expiry instant of two links issued together.
// FR-AUTH-18
func TestConsumeHonorsTTLBoundary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const ttl = 5 * time.Minute
		service := newTestService(t, magiclink.Options{
			Store:        magiclink.NewMemoryStore(),
			BaseURL:      "https://app.example/magic",
			RedirectURIs: []string{"https://app.example/after"},
			TTL:          ttl,
		})
		now := time.Now().UTC()
		principal := validPrincipal(now)
		first, err := service.Issue(context.Background(), principal, "https://app.example/after")
		if err != nil {
			t.Fatal(err)
		}
		second, err := service.Issue(context.Background(), principal, "https://app.example/after")
		if err != nil {
			t.Fatal(err)
		}
		if !first.ExpiresAt.Equal(now.Add(ttl)) {
			t.Fatalf("ExpiresAt = %v, want %v", first.ExpiresAt, now.Add(ttl))
		}

		time.Sleep(ttl - time.Nanosecond)
		if _, err := service.Consume(context.Background(), first.Token); err != nil {
			t.Fatalf("Consume() before expiry error = %v", err)
		}
		time.Sleep(time.Nanosecond)
		if _, err := service.Consume(context.Background(), second.Token); !errors.Is(err, authentication.ErrExpired) {
			t.Fatalf("Consume() at expiry error = %v, want ErrExpired", err)
		}
		if _, err := service.Consume(context.Background(), second.Token); !errors.Is(err, authentication.ErrReplay) {
			t.Fatalf("Consume() after expired consume error = %v, want ErrReplay", err)
		}
	})
}

// TestSuppliedClockIsHonoured runs on the wall clock with a principal that is
// valid only years from now, so only Options.Clock can accept it.
// FR-AUTH-27
func TestSuppliedClockIsHonoured(t *testing.T) {
	const ttl = 5 * time.Minute
	now := time.Date(2031, 3, 4, 5, 6, 7, 0, time.FixedZone("UTC+2", 2*60*60))
	service := newTestService(t, magiclink.Options{
		Store:        magiclink.NewMemoryStore(),
		BaseURL:      "https://app.example/magic",
		RedirectURIs: []string{"https://app.example/after"},
		TTL:          ttl,
		Clock:        func() time.Time { return now },
	})
	principal := validPrincipal(now.UTC())
	first, err := service.Issue(context.Background(), principal, "https://app.example/after")
	if err != nil {
		t.Fatalf("Issue() at supplied time error = %v", err)
	}
	if !first.ExpiresAt.Equal(now.Add(ttl)) || first.ExpiresAt.Location() != time.UTC {
		t.Fatalf("ExpiresAt = %v, want %v in UTC", first.ExpiresAt, now.Add(ttl).UTC())
	}
	second, err := service.Issue(context.Background(), principal, "https://app.example/after")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Consume(context.Background(), first.Token); err != nil {
		t.Fatalf("Consume() before supplied expiry error = %v", err)
	}
	now = now.Add(ttl)
	if _, err := service.Consume(context.Background(), second.Token); !errors.Is(err, authentication.ErrExpired) {
		t.Fatalf("Consume() at supplied expiry error = %v, want ErrExpired", err)
	}
}
