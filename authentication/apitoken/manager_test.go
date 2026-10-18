package apitoken_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/justusschock/auth/authentication"
	"github.com/justusschock/auth/authentication/apitoken"
)

var tokenPattern = regexp.MustCompile(`^dtc_[a-z2-7]{26}_[a-z2-7]{52}$`)

func testIdentity() apitoken.Identity {
	return apitoken.Identity{
		ID:      "https://id.example|alice",
		Issuer:  "https://id.example",
		Subject: "alice",
		Traits:  map[string][]string{"email": {"alice@example.com"}},
	}
}

func newManager(t *testing.T, store apitoken.Store, mutate func(*apitoken.Options)) *apitoken.Manager {
	t.Helper()
	options := apitoken.Options{Store: store, Prefix: "dtc", Pepper: bytes.Repeat([]byte("p"), 32)}
	if mutate != nil {
		mutate(&options)
	}
	manager, err := apitoken.NewManager(options)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager
}

func issue(t *testing.T, manager *apitoken.Manager, request apitoken.IssueRequest) (string, apitoken.Record) {
	t.Helper()
	token, record, err := manager.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	return token, record
}

func defaultRequest() apitoken.IssueRequest {
	return apitoken.IssueRequest{Principal: testIdentity(), Name: "ci", Scopes: []string{"runs:write", "runs:read"}, TTL: time.Hour}
}

func bearer(token string) authentication.Credential {
	return authentication.Credential{Kind: authentication.CredentialKindBearer, Token: []byte(token)}
}

// FR-AUTH-05
func TestIssueAndAuthenticateRoundTrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := apitoken.NewMemoryStore()
		manager := newManager(t, store, nil)
		token, record := issue(t, manager, defaultRequest())

		if !tokenPattern.MatchString(token) {
			t.Fatalf("token %q does not match format", token)
		}
		if !strings.Contains(token, "_"+record.ID+"_") || !apitoken.ValidID(record.ID) {
			t.Fatalf("record ID %q not embedded in token", record.ID)
		}
		if record.Digest != [32]byte{} {
			t.Fatal("Issue returned record digest")
		}
		if !slices.Equal(record.Scopes, []string{"runs:read", "runs:write"}) {
			t.Fatalf("scopes = %v, want sorted", record.Scopes)
		}
		if got := record.ExpiresAt.Sub(record.CreatedAt); got != time.Hour {
			t.Fatalf("lifetime = %v", got)
		}

		time.Sleep(10 * time.Minute)
		for _, kind := range []string{authentication.CredentialKindBearer, apitoken.CredentialKind} {
			principal, err := manager.Authenticate(context.Background(), authentication.Credential{Kind: kind, Token: []byte(token)})
			if err != nil {
				t.Fatalf("Authenticate(%s) error = %v", kind, err)
			}
			want := testIdentity()
			if principal.ID != want.ID || principal.Issuer != want.Issuer || principal.Subject != want.Subject {
				t.Fatalf("principal identity = %#v", principal)
			}
			if !principal.AuthenticatedAt.Equal(time.Now().UTC()) || !principal.ExpiresAt.Equal(record.ExpiresAt) {
				t.Fatalf("principal lifetime = %v..%v", principal.AuthenticatedAt, principal.ExpiresAt)
			}
			if !slices.Equal(principal.Traits[apitoken.ScopeTrait], record.Scopes) ||
				!slices.Equal(principal.Traits[apitoken.TokenIDTrait], []string{record.ID}) ||
				!slices.Equal(principal.Traits["email"], []string{"alice@example.com"}) {
				t.Fatalf("principal traits = %v", principal.Traits)
			}
			if !slices.Equal(principal.Methods, []string{apitoken.Method}) {
				t.Fatalf("methods = %v", principal.Methods)
			}
			if err := authentication.ValidatePrincipal(principal, time.Now().UTC()); err != nil {
				t.Fatalf("ValidatePrincipal() error = %v", err)
			}
		}
	})
}

// FR-AUTH-06
func TestAuthenticateWithoutScopesSetsEmptyScopeTrait(t *testing.T) {
	manager := newManager(t, apitoken.NewMemoryStore(), func(o *apitoken.Options) { o.Pepper = nil })
	request := defaultRequest()
	request.Scopes = nil
	request.Principal.Traits = nil
	token, _ := issue(t, manager, request)
	principal, err := manager.Authenticate(context.Background(), bearer(token))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	scopes, ok := principal.Traits[apitoken.ScopeTrait]
	if !ok || len(scopes) != 0 {
		t.Fatalf("scope trait = %v, %v", scopes, ok)
	}
}

// FR-AUTH-05, NFR-AUTH-02
func TestStoreNeverHoldsRawTokenAndPepperBindsDigest(t *testing.T) {
	store := apitoken.NewMemoryStore()
	manager := newManager(t, store, nil)
	token, record := issue(t, manager, defaultRequest())
	stored, err := store.Get(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Digest == [32]byte{} {
		t.Fatal("stored digest is zero")
	}
	secret := token[strings.LastIndexByte(token, '_')+1:]
	if dump := fmt.Sprintf("%#v %v", stored, stored); strings.Contains(dump, secret) {
		t.Fatal("stored record contains token secret")
	}

	otherPepper := newManager(t, store, func(o *apitoken.Options) { o.Pepper = bytes.Repeat([]byte("q"), 32) })
	if _, err := otherPepper.Authenticate(context.Background(), bearer(token)); !errors.Is(err, authentication.ErrUnauthenticated) {
		t.Fatalf("Authenticate() with other pepper error = %v", err)
	}
	unpeppered := newManager(t, store, func(o *apitoken.Options) { o.Pepper = nil })
	if _, err := unpeppered.Authenticate(context.Background(), bearer(token)); !errors.Is(err, authentication.ErrUnauthenticated) {
		t.Fatalf("Authenticate() without pepper error = %v", err)
	}
}

// FR-AUTH-05
func TestAuthenticateRejectsTamperedTokens(t *testing.T) {
	manager := newManager(t, apitoken.NewMemoryStore(), nil)
	token, _ := issue(t, manager, defaultRequest())
	other, _ := issue(t, manager, defaultRequest())
	last := token[len(token)-1]
	flipped := byte('a')
	if last == 'a' {
		flipped = 'b'
	}
	otherSecret := other[strings.LastIndexByte(other, '_'):]

	tests := map[string]string{
		"flipped secret":      token[:len(token)-1] + string(flipped),
		"swapped secret":      token[:strings.LastIndexByte(token, '_')] + otherSecret,
		"uppercase":           "dtc_" + strings.ToUpper(token[4:]),
		"truncated":           token[:len(token)-1],
		"extended":            token + "a",
		"missing separator":   strings.Replace(token[4:], "_", "", 1),
		"padding":             token[:len(token)-1] + "=",
		"whitespace":          token + " ",
		"unknown id":          "dtc_" + strings.Repeat("a", 26) + token[4+26:],
		"non canonical tail":  token[:len(token)-1] + "7",
		"non canonical id":    token[:4+25] + "7" + token[4+26:],
		"empty after prefix":  "dtc_",
		"double prefix":       "dtc_" + token,
		"nul byte":            token[:10] + "\x00" + token[11:],
		"non ascii":           token[:10] + "é" + token[12:],
		"oversized":           "dtc_" + strings.Repeat("a", 4096),
		"separator in secret": token[:len(token)-2] + "_a",
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if candidate == token {
				t.Skip("mutation produced original token")
			}
			_, err := manager.Authenticate(context.Background(), bearer(candidate))
			want := authentication.ErrUnauthenticated
			if !strings.HasPrefix(candidate, "dtc_") {
				want = authentication.ErrUnsupportedCredential
			}
			if err != want {
				t.Fatalf("Authenticate() error = %v, want %v", err, want)
			}
			if err != nil && strings.Contains(err.Error(), candidate) {
				t.Fatal("error leaked token")
			}
		})
	}
}

// FR-AUTH-07
func TestAuthenticateDeclinesForeignCredentials(t *testing.T) {
	manager := newManager(t, apitoken.NewMemoryStore(), nil)
	token, _ := issue(t, manager, defaultRequest())
	tests := map[string]authentication.Credential{
		"jwt kind":     {Kind: authentication.CredentialKindJWT, Token: []byte(token)},
		"session kind": {Kind: "session", Token: []byte(token)},
		"other prefix": bearer("ghp_" + token[4:]),
		"prefix only":  bearer("dtc"),
		"jwt":          bearer("eyJhbGciOiJFUzI1NiJ9.e30.sig"),
		"empty":        bearer(""),
	}
	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.Authenticate(context.Background(), credential); err != authentication.ErrUnsupportedCredential {
				t.Fatalf("Authenticate() error = %v, want ErrUnsupportedCredential", err)
			}
		})
	}
}

// FR-AUTH-06
func TestAuthenticateExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager := newManager(t, apitoken.NewMemoryStore(), nil)
		request := defaultRequest()
		request.TTL = time.Hour
		token, _ := issue(t, manager, request)

		time.Sleep(time.Hour - time.Nanosecond)
		if _, err := manager.Authenticate(context.Background(), bearer(token)); err != nil {
			t.Fatalf("Authenticate() before expiry error = %v", err)
		}
		time.Sleep(time.Nanosecond)
		if _, err := manager.Authenticate(context.Background(), bearer(token)); err != authentication.ErrExpired {
			t.Fatalf("Authenticate() at expiry error = %v, want ErrExpired", err)
		}
	})
}

// FR-AUTH-06
func TestLastUsedIsThrottled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := apitoken.NewMemoryStore()
		manager := newManager(t, store, func(o *apitoken.Options) { o.LastUsedInterval = time.Minute })
		token, record := issue(t, manager, defaultRequest())
		lastUsed := func() time.Time {
			stored, err := store.Get(context.Background(), record.ID)
			if err != nil {
				t.Fatal(err)
			}
			return stored.LastUsedAt
		}
		authenticate := func() {
			if _, err := manager.Authenticate(context.Background(), bearer(token)); err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
		}
		if !lastUsed().IsZero() {
			t.Fatal("new token has last-used time")
		}
		authenticate()
		first := lastUsed()
		if !first.Equal(time.Now().UTC()) {
			t.Fatalf("first last-used = %v", first)
		}
		time.Sleep(30 * time.Second)
		authenticate()
		if !lastUsed().Equal(first) {
			t.Fatal("last-used updated within throttle interval")
		}
		time.Sleep(30 * time.Second)
		authenticate()
		if !lastUsed().Equal(first.Add(time.Minute)) {
			t.Fatalf("last-used = %v, want %v", lastUsed(), first.Add(time.Minute))
		}
	})
}

// FR-AUTH-06
func TestLastUsedCanBeDisabled(t *testing.T) {
	store := apitoken.NewMemoryStore()
	manager := newManager(t, store, func(o *apitoken.Options) { o.LastUsedInterval = -1 })
	token, record := issue(t, manager, defaultRequest())
	if _, err := manager.Authenticate(context.Background(), bearer(token)); err != nil {
		t.Fatal(err)
	}
	stored, _ := store.Get(context.Background(), record.ID)
	if !stored.LastUsedAt.IsZero() {
		t.Fatal("last-used tracked while disabled")
	}
}

// FR-AUTH-06
func TestRevokeAndList(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := apitoken.NewMemoryStore()
		manager := newManager(t, store, nil)
		ctx := context.Background()
		alice := testIdentity()
		bob := apitoken.Identity{ID: "https://id.example|bob", Issuer: "https://id.example", Subject: "bob"}

		first, firstRecord := issue(t, manager, apitoken.IssueRequest{Principal: alice, Name: "one", TTL: time.Hour})
		time.Sleep(time.Second)
		_, secondRecord := issue(t, manager, apitoken.IssueRequest{Principal: alice, Name: "two", TTL: time.Hour})
		_, bobRecord := issue(t, manager, apitoken.IssueRequest{Principal: bob, Name: "bob", TTL: time.Hour})

		if err := manager.Revoke(ctx, bob.ID, firstRecord.ID); err != apitoken.ErrNotFound {
			t.Fatalf("Revoke() by other principal error = %v, want ErrNotFound", err)
		}
		if err := manager.Revoke(ctx, alice.ID, strings.Repeat("a", 26)); err != apitoken.ErrNotFound {
			t.Fatalf("Revoke() unknown error = %v, want ErrNotFound", err)
		}
		if err := manager.Revoke(ctx, alice.ID, "not-an-id"); err != apitoken.ErrNotFound {
			t.Fatalf("Revoke() malformed error = %v, want ErrNotFound", err)
		}
		if err := manager.Revoke(ctx, alice.ID, firstRecord.ID); err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
		revokedAt := time.Now().UTC()
		time.Sleep(time.Second)
		if err := manager.Revoke(ctx, alice.ID, firstRecord.ID); err != nil {
			t.Fatalf("second Revoke() error = %v", err)
		}
		if _, err := manager.Authenticate(ctx, bearer(first)); err != authentication.ErrUnauthenticated {
			t.Fatalf("Authenticate() revoked error = %v, want ErrUnauthenticated", err)
		}

		records, err := manager.List(ctx, alice.ID)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(records) != 2 || records[0].ID != firstRecord.ID || records[1].ID != secondRecord.ID {
			t.Fatalf("List() = %#v", records)
		}
		if !records[0].Revoked() || !records[0].RevokedAt.Equal(revokedAt) || records[1].Revoked() {
			t.Fatalf("revocation state = %v, %v", records[0].RevokedAt, records[1].RevokedAt)
		}
		for _, record := range records {
			if record.Digest != [32]byte{} {
				t.Fatal("List returned digest")
			}
			if record.ID == bobRecord.ID {
				t.Fatal("List returned other principal's token")
			}
		}
		if _, err := manager.List(ctx, ""); err != authentication.ErrInvalidPrincipal {
			t.Fatalf("List(empty) error = %v", err)
		}
	})
}

// FR-AUTH-05
func TestNewManagerValidatesOptions(t *testing.T) {
	store := apitoken.NewMemoryStore()
	tests := map[string]apitoken.Options{
		"missing store":   {Prefix: "dtc"},
		"missing prefix":  {Store: store},
		"short prefix":    {Store: store, Prefix: "d"},
		"long prefix":     {Store: store, Prefix: strings.Repeat("d", 17)},
		"uppercase":       {Store: store, Prefix: "DTC"},
		"underscore":      {Store: store, Prefix: "dtc_x"},
		"leading digit":   {Store: store, Prefix: "1dtc"},
		"short pepper":    {Store: store, Prefix: "dtc", Pepper: []byte("short")},
		"negative maxTTL": {Store: store, Prefix: "dtc", MaxTTL: -time.Second},
	}
	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := apitoken.NewManager(options); err == nil {
				t.Fatal("NewManager() succeeded")
			}
		})
	}
}

// FR-AUTH-05
func TestIssueValidatesRequest(t *testing.T) {
	manager := newManager(t, apitoken.NewMemoryStore(), func(o *apitoken.Options) { o.MaxTTL = 24 * time.Hour })
	tests := map[string]func(*apitoken.IssueRequest){
		"missing name":     func(r *apitoken.IssueRequest) { r.Name = "" },
		"oversized name":   func(r *apitoken.IssueRequest) { r.Name = strings.Repeat("n", 257) },
		"nul name":         func(r *apitoken.IssueRequest) { r.Name = "a\x00" },
		"duplicate scopes": func(r *apitoken.IssueRequest) { r.Scopes = []string{"a", "a"} },
		"empty scope":      func(r *apitoken.IssueRequest) { r.Scopes = []string{""} },
		"space in scope":   func(r *apitoken.IssueRequest) { r.Scopes = []string{"a b"} },
		"too many scopes":  func(r *apitoken.IssueRequest) { r.Scopes = make([]string, 65) },
		"zero ttl":         func(r *apitoken.IssueRequest) { r.TTL = 0 },
		"ttl above max":    func(r *apitoken.IssueRequest) { r.TTL = 25 * time.Hour },
		"missing subject":  func(r *apitoken.IssueRequest) { r.Principal.Subject = "" },
		"missing id":       func(r *apitoken.IssueRequest) { r.Principal.ID = "" },
		"reserved scope": func(r *apitoken.IssueRequest) {
			r.Principal.Traits = map[string][]string{apitoken.ScopeTrait: {"admin"}}
		},
		"reserved token id":  func(r *apitoken.IssueRequest) { r.Principal.Traits = map[string][]string{apitoken.TokenIDTrait: {"x"}} },
		"invalid trait text": func(r *apitoken.IssueRequest) { r.Principal.Traits = map[string][]string{"a": {"\xff"}} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := defaultRequest()
			mutate(&request)
			token, _, err := manager.Issue(context.Background(), request)
			if err == nil || token != "" {
				t.Fatalf("Issue() = %q, %v; want error", token, err)
			}
		})
	}
}

// NFR-AUTH-04
func TestIssueFailsClosedOnRandomnessFailure(t *testing.T) {
	manager := newManager(t, apitoken.NewMemoryStore(), func(o *apitoken.Options) { o.Random = io.LimitReader(bytes.NewReader(nil), 0) })
	if token, _, err := manager.Issue(context.Background(), defaultRequest()); err != authentication.ErrInvalidCredential || token != "" {
		t.Fatalf("Issue() = %q, %v", token, err)
	}
}

type failingStore struct {
	*apitoken.MemoryStore
	getErr   error
	touchErr error
}

func (s *failingStore) Get(ctx context.Context, id string) (apitoken.Record, error) {
	if s.getErr != nil {
		return apitoken.Record{}, s.getErr
	}
	return s.MemoryStore.Get(ctx, id)
}

func (s *failingStore) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	if s.touchErr != nil {
		return s.touchErr
	}
	return s.MemoryStore.TouchLastUsed(ctx, id, at)
}

// NFR-AUTH-01
func TestStoreErrorsAreSanitized(t *testing.T) {
	store := &failingStore{MemoryStore: apitoken.NewMemoryStore()}
	manager := newManager(t, store, nil)
	token, record := issue(t, manager, defaultRequest())

	store.touchErr = errors.New("backend down")
	if _, err := manager.Authenticate(context.Background(), bearer(token)); err != nil {
		t.Fatalf("Authenticate() with failing touch error = %v", err)
	}

	store.getErr = fmt.Errorf("backend failed for %s", token)
	_, err := manager.Authenticate(context.Background(), bearer(token))
	if err != authentication.ErrUnauthenticated {
		t.Fatalf("Authenticate() error = %v, want ErrUnauthenticated", err)
	}
	if err := manager.Revoke(context.Background(), testIdentity().ID, record.ID); err != authentication.ErrUnauthenticated {
		t.Fatalf("Revoke() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Authenticate(ctx, bearer(token)); err != context.Canceled {
		t.Fatalf("Authenticate(canceled) error = %v", err)
	}
}

// FR-AUTH-07
func TestAuthenticateIsCompatibleWithChain(t *testing.T) {
	manager := newManager(t, apitoken.NewMemoryStore(), nil)
	token, _ := issue(t, manager, defaultRequest())
	fallback := authenticatorFunc(func(context.Context, authentication.Credential) (authentication.Principal, error) {
		return authentication.Principal{ID: "fallback"}, nil
	})
	chain := authentication.Chain(manager, fallback)
	principal, err := chain.Authenticate(context.Background(), bearer(token))
	if err != nil || principal.ID != testIdentity().ID {
		t.Fatalf("Chain(apitoken) = %v, %v", principal.ID, err)
	}
	principal, err = chain.Authenticate(context.Background(), bearer("eyJ.e30.sig"))
	if err != nil || principal.ID != "fallback" {
		t.Fatalf("Chain(foreign) = %v, %v", principal.ID, err)
	}
	if _, err := chain.Authenticate(context.Background(), bearer(token[:len(token)-1]+"b")); !errors.Is(err, authentication.ErrUnauthenticated) {
		t.Fatalf("Chain(invalid apitoken) error = %v, want no fallback", err)
	}
}

type authenticatorFunc func(context.Context, authentication.Credential) (authentication.Principal, error)

func (f authenticatorFunc) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Principal, error) {
	return f(ctx, credential)
}

// FR-AUTH-27
func TestSuppliedClockIsHonoured(t *testing.T) {
	// Outside a synctest bubble and far from the wall clock, so only the
	// supplied Clock can explain the timestamps. The non-UTC zone checks
	// that its result is converted to UTC.
	now := time.Date(2031, 3, 4, 5, 6, 7, 0, time.FixedZone("UTC+2", 2*60*60))
	store := apitoken.NewMemoryStore()
	manager := newManager(t, store, func(options *apitoken.Options) {
		options.Clock = func() time.Time { return now }
	})
	token, record := issue(t, manager, defaultRequest())
	if !record.CreatedAt.Equal(now) || record.CreatedAt.Location() != time.UTC {
		t.Fatalf("CreatedAt = %v, want %v in UTC", record.CreatedAt, now.UTC())
	}
	if !record.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want %v", record.ExpiresAt, now.Add(time.Hour).UTC())
	}
	if _, err := manager.Authenticate(context.Background(), bearer(token)); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if err := manager.Revoke(context.Background(), testIdentity().ID, record.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	records, err := manager.List(context.Background(), testIdentity().ID)
	if err != nil || len(records) != 1 || !records[0].RevokedAt.Equal(now) {
		t.Fatalf("List() = %v, %v; want one record revoked at %v", records, err, now.UTC())
	}

	expiring, _ := issue(t, manager, defaultRequest())
	now = now.Add(time.Hour)
	if _, err := manager.Authenticate(context.Background(), bearer(expiring)); err != authentication.ErrExpired {
		t.Fatalf("Authenticate() at supplied expiry error = %v, want ErrExpired", err)
	}
}
