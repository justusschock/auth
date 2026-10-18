package oidc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/justusschock/go-auth/authentication"
	authoidc "github.com/justusschock/go-auth/authentication/oidc"
	"github.com/justusschock/go-auth/internal/authtest"
	"golang.org/x/oauth2"
)

// FR-AUTH-10
func TestBeginStoresHashedStateNonceAndPKCE(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := authoidc.NewMemoryStateStore()
		now := time.Now().UTC()
		p, err := authoidc.New(authoidc.Options{
			Name:         "work",
			Issuer:       "https://id.example",
			ClientID:     "client",
			RedirectURIs: []string{"https://app.example/callback"},
			State:        store,
			Random:       deterministicSecrets(1, 2, 3),
		})
		if err != nil {
			t.Fatal(err)
		}

		redirect, err := p.Begin(context.Background(), authentication.BeginRequest{
			RedirectURI: "https://app.example/callback",
			Scopes:      []string{"openid", "email"},
		})
		if err != nil {
			t.Fatal(err)
		}

		query := redirect.URL.Query()
		if query.Get("state") != redirect.StateID {
			t.Fatalf("redirect state = %q, StateID = %q", query.Get("state"), redirect.StateID)
		}
		if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("nonce") == "" {
			t.Fatalf("url=%s", redirect.URL)
		}
		if strings.Count(query.Get("scope"), "openid") != 1 {
			t.Fatalf("scope = %q, want exactly one openid", query.Get("scope"))
		}

		pending, err := store.Consume(context.Background(), authoidc.StateDigest(redirect.StateID))
		if err != nil {
			t.Fatal(err)
		}
		if pending.Provider != "work" || pending.RedirectURI != "https://app.example/callback" {
			t.Fatalf("pending = %#v", pending)
		}
		if want := now.Add(10 * time.Minute); !pending.ExpiresAt.Equal(want) || !redirect.ExpiresAt.Equal(want) {
			t.Fatalf("state expiry = %v / %v, want default TTL %v", pending.ExpiresAt, redirect.ExpiresAt, want)
		}
		nonce := string(pending.Nonce.Bytes())
		verifier := string(pending.PKCEVerifier.Bytes())
		if nonce == "" || verifier == "" || nonce == verifier || nonce == redirect.StateID {
			t.Fatalf("state, nonce, and verifier must be independent: %#v", pending)
		}
		if pending.Digest == [32]byte{} || bytes.Contains(pending.Digest[:], []byte(redirect.StateID)) {
			t.Fatalf("pending digest must not store raw state: %#v", pending.Digest)
		}
		if _, err := store.Consume(context.Background(), authoidc.StateDigest(redirect.StateID)); !errors.Is(err, authentication.ErrReplay) {
			t.Fatalf("second consume error = %v, want ErrReplay", err)
		}
	})
}

// FR-AUTH-10
func TestBeginRequiresExactRegisteredHTTPSRedirect(t *testing.T) {
	p, err := authoidc.New(authoidc.Options{
		Name:         "work",
		Issuer:       "https://id.example",
		ClientID:     "client",
		RedirectURIs: []string{"https://app.example/callback"},
		State:        authoidc.NewMemoryStateStore(),
		Random:       deterministicSecrets(4, 5, 6),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, redirectURI := range []string{
		"http://app.example/callback",
		"https://app.example/callback/",
		"https://app.example/callback?next=/home",
		"https://evil.example/callback",
	} {
		_, err := p.Begin(context.Background(), authentication.BeginRequest{RedirectURI: redirectURI})
		if !errors.Is(err, authentication.ErrInvalidCallback) {
			t.Fatalf("Begin(%q) error = %v, want ErrInvalidCallback", redirectURI, err)
		}
	}
}

// FR-AUTH-10
func TestCompleteConsumesBeforeExchangeAndAllowsOnlyOneCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		var tokenRequests int
		tokenEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenRequests++
			if got := r.FormValue("code_verifier"); got == "" {
				t.Fatalf("token request omitted PKCE verifier")
			}
			writeToken(w, unsignedIDToken(map[string]any{
				"iss":   "https://id.example",
				"sub":   "subject",
				"aud":   "client",
				"azp":   "client",
				"nonce": expectedNonce(t, r),
				"iat":   now.Unix(),
				"exp":   now.Add(time.Hour).Unix(),
			}))
		})

		store := authoidc.NewMemoryStateStore()
		p, err := authoidc.New(authoidc.Options{
			Name:   "work",
			Issuer: "https://id.example",
			Config: oauth2.Config{
				ClientID: "client",
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://id.example/authorize",
					TokenURL: "https://id.example/token",
				},
			},
			Verifier:     insecureVerifier("https://id.example", "client", now),
			RedirectURIs: []string{"https://app.example/callback"},
			State:        store,
			Random:       deterministicSecrets(7, 8, 9),
		})
		if err != nil {
			t.Fatal(err)
		}
		redirect, err := p.Begin(context.Background(), authentication.BeginRequest{RedirectURI: "https://app.example/callback"})
		if err != nil {
			t.Fatal(err)
		}
		pending, err := store.Consume(context.Background(), authoidc.StateDigest(redirect.StateID))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(context.Background(), pending); err != nil {
			t.Fatal(err)
		}
		nonceByVerifier.Store(string(pending.PKCEVerifier.Bytes()), string(pending.Nonce.Bytes()))

		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := p.Complete(tokenContext(tokenEndpoint), authentication.Callback{StateID: redirect.StateID, Code: "code"})
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)

		var successes, replays int
		for err := range errs {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, authentication.ErrReplay):
				replays++
			default:
				t.Fatalf("Complete error = %v", err)
			}
		}
		if successes != 1 || replays != 1 || tokenRequests != 1 {
			t.Fatalf("successes=%d replays=%d tokenRequests=%d", successes, replays, tokenRequests)
		}
	})
}

// FR-AUTH-10
func TestCompleteRejectsNonceProviderAndAuthorizedPartyMismatch(t *testing.T) {
	tests := map[string]struct {
		provider string
		claims   func(now time.Time) map[string]any
	}{
		"provider mismatch": {
			provider: "other",
			claims: func(now time.Time) map[string]any {
				return map[string]any{
					"iss": "https://id.example", "sub": "subject", "aud": "client", "azp": "client",
					"nonce": "nonce", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
				}
			},
		},
		"nonce mismatch": {
			provider: "work",
			claims: func(now time.Time) map[string]any {
				return map[string]any{
					"iss": "https://id.example", "sub": "subject", "aud": "client", "azp": "client",
					"nonce": "wrong", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
				}
			},
		},
		"azp mismatch with multiple audiences": {
			provider: "work",
			claims: func(now time.Time) map[string]any {
				return map[string]any{
					"iss": "https://id.example", "sub": "subject", "aud": []string{"client", "other"}, "azp": "other",
					"nonce": "nonce", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
				}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now().UTC()
				tokenEndpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					writeToken(w, unsignedIDToken(test.claims(now)))
				})
				store := authoidc.NewMemoryStateStore()
				p, err := authoidc.New(authoidc.Options{
					Name:   "work",
					Issuer: "https://id.example",
					Config: oauth2.Config{
						ClientID: "client",
						Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"},
					},
					Verifier:     insecureVerifier("https://id.example", "client", now),
					RedirectURIs: []string{"https://app.example/callback"},
					State:        store,
				})
				if err != nil {
					t.Fatal(err)
				}
				pending := authoidc.Pending{
					Digest:       authoidc.StateDigest("state"),
					Provider:     test.provider,
					RedirectURI:  "https://app.example/callback",
					Nonce:        authoidc.NewSecret("nonce"),
					PKCEVerifier: authoidc.NewSecret("verifier"),
					ExpiresAt:    now.Add(time.Minute),
				}
				if err := store.Put(context.Background(), pending); err != nil {
					t.Fatal(err)
				}
				_, err = p.Complete(tokenContext(tokenEndpoint), authentication.Callback{StateID: "state", Code: "code"})
				if !errors.Is(err, authentication.ErrUnauthenticated) {
					t.Fatalf("Complete error = %v, want ErrUnauthenticated", err)
				}
			})
		})
	}
}

// FR-AUTH-11
func TestCompleteCopiesOnlyConfiguredVerifiedClaims(t *testing.T) {
	tests := map[string]struct {
		traitClaims []string
		claims      map[string]any
		want        map[string][]string
	}{
		"none configured": {
			claims: map[string]any{"groups": []string{"admin"}},
		},
		"scalar": {
			traitClaims: []string{"department"},
			claims:      map[string]any{"department": "medicine", "ignored": "private"},
			want:        map[string][]string{"department": {"medicine"}},
		},
		"array": {
			traitClaims: []string{"groups"},
			claims:      map[string]any{"groups": []string{"students", "reviewers"}},
			want:        map[string][]string{"groups": {"students", "reviewers"}},
		},
		"missing": {
			traitClaims: []string{"groups"},
			claims:      map[string]any{"department": "medicine"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			principal, err := completePrincipal(t, test.traitClaims, test.claims, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(principal.Traits, test.want) {
				t.Fatalf("Traits = %#v, want %#v", principal.Traits, test.want)
			}
		})
	}
}

// FR-AUTH-11
func TestNewOwnsConfiguredTraitClaims(t *testing.T) {
	configured := []string{"groups"}
	principal, err := completePrincipal(t, configured, map[string]any{
		"groups": []string{"admin"},
		"roles":  []string{"ignored"},
	}, func() {
		configured[0] = "roles"
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"groups": {"admin"}}; !reflect.DeepEqual(principal.Traits, want) {
		t.Fatalf("Traits = %#v, want owned configured claims %#v", principal.Traits, want)
	}

	principal.Traits["groups"][0] = "mutated"
	if configured[0] != "roles" {
		t.Fatalf("principal traits alias options: configured = %#v", configured)
	}
}

// FR-AUTH-11
func TestNewRejectsMalformedConfiguredTraitClaims(t *testing.T) {
	tests := map[string][]string{
		"empty":      {""},
		"whitespace": {" groups"},
		"nul":        {"groups\x00private"},
		"duplicate":  {"groups", "groups"},
		"too long":   {strings.Repeat("g", 257)},
		"too many":   make([]string, 129),
	}
	for index := range tests["too many"] {
		tests["too many"][index] = fmt.Sprintf("claim-%d", index)
	}

	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := authoidc.New(authoidc.Options{
				Name:         "work",
				Issuer:       "https://id.example",
				ClientID:     "client",
				RedirectURIs: []string{"https://app.example/callback"},
				State:        authoidc.NewMemoryStateStore(),
				TraitClaims:  claims,
			})
			if !errors.Is(err, authentication.ErrInvalidCredential) {
				t.Fatalf("New error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

// FR-AUTH-11
func TestCompleteRejectsMalformedOrUnboundedConfiguredClaims(t *testing.T) {
	tests := map[string]any{
		"object":          map[string]any{"sensitive-group": true},
		"number":          42,
		"null":            nil,
		"too many values": make([]string, 129),
		"oversized value": strings.Repeat("sensitive-value", 300),
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := completePrincipal(t, []string{"groups"}, map[string]any{"groups": value}, nil)
			if err != authentication.ErrUnauthenticated {
				t.Fatalf("Complete error = %v, want exact ErrUnauthenticated", err)
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("Complete error leaked claim content: %v", err)
			}
		})
	}
}

func completePrincipal(t *testing.T, traitClaims []string, extraClaims map[string]any, afterNew func()) (principal authentication.Principal, err error) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		principal, err = completePrincipalInBubble(t, traitClaims, extraClaims, afterNew)
	})
	return principal, err
}

func completePrincipalInBubble(t *testing.T, traitClaims []string, extraClaims map[string]any, afterNew func()) (authentication.Principal, error) {
	t.Helper()
	now := time.Now().UTC()
	tokenEndpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		claims := map[string]any{
			"iss":   "https://id.example",
			"sub":   "subject",
			"aud":   "client",
			"azp":   "client",
			"nonce": "nonce",
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		}
		for name, value := range extraClaims {
			claims[name] = value
		}
		writeToken(w, unsignedIDToken(claims))
	})

	store := authoidc.NewMemoryStateStore()
	p, err := authoidc.New(authoidc.Options{
		Name:   "work",
		Issuer: "https://id.example",
		Config: oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"},
		},
		Verifier:     insecureVerifier("https://id.example", "client", now),
		RedirectURIs: []string{"https://app.example/callback"},
		State:        store,
		TraitClaims:  traitClaims,
	})
	if err != nil {
		t.Fatal(err)
	}
	if afterNew != nil {
		afterNew()
	}
	if err := store.Put(context.Background(), authoidc.Pending{
		Digest:       authoidc.StateDigest("state"),
		Provider:     "work",
		RedirectURI:  "https://app.example/callback",
		Nonce:        authoidc.NewSecret("nonce"),
		PKCEVerifier: authoidc.NewSecret("verifier"),
		ExpiresAt:    now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	return p.Complete(tokenContext(tokenEndpoint), authentication.Callback{StateID: "state", Code: "code"})
}

// tokenContext routes the provider's token request to handler in memory.
func tokenContext(handler http.Handler) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, authtest.Client(handler))
}

var nonceByVerifier sync.Map

func expectedNonce(t *testing.T, r *http.Request) string {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	nonce, ok := nonceByVerifier.Load(r.FormValue("code_verifier"))
	if !ok {
		t.Fatalf("unknown verifier %q", r.FormValue("code_verifier"))
	}
	return nonce.(string)
}

func insecureVerifier(issuer, clientID string, now time.Time) *coreosoidc.IDTokenVerifier {
	return coreosoidc.NewVerifier(issuer, nil, &coreosoidc.Config{
		ClientID:                   clientID,
		SupportedSigningAlgs:       []string{"none"},
		Now:                        func() time.Time { return now },
		InsecureSkipSignatureCheck: true,
	})
}

func unsignedIDToken(claims map[string]any) string {
	header := map[string]any{"alg": "none"}
	return encodeJSON(header) + "." + encodeJSON(claims) + "."
}

func encodeJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func writeToken(w http.ResponseWriter, idToken string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "redacted-access-token",
		"token_type":   "Bearer",
		"id_token":     idToken,
	})
}

func deterministicSecrets(values ...byte) *bytes.Reader {
	data := make([]byte, 0, len(values)*32)
	for _, value := range values {
		data = append(data, bytes.Repeat([]byte{value}, 32)...)
	}
	return bytes.NewReader(data)
}

// NFR-AUTH-02
func TestStateDigestUsesSHA256LookupOnly(t *testing.T) {
	raw := "raw-state"
	digest := authoidc.StateDigest(raw)
	if digest == [32]byte{} || bytes.Equal(digest[:], []byte(raw)) {
		t.Fatalf("digest = %#v", digest)
	}
	if escaped := url.QueryEscape(string(digest[:])); strings.Contains(escaped, raw) {
		t.Fatalf("digest leaks raw state")
	}
}

// FR-AUTH-10
func TestCompletePassesOnlyStateDigestToStore(t *testing.T) {
	store := &recordingStateStore{consumeErr: authentication.ErrReplay}
	p := newTestProvider(t, store)

	_, err := p.Complete(context.Background(), authentication.Callback{StateID: "raw-callback-state", Code: "code"})
	if !errors.Is(err, authentication.ErrReplay) {
		t.Fatalf("Complete error = %v, want ErrReplay", err)
	}
	if want := authoidc.StateDigest("raw-callback-state"); store.consumed != want {
		t.Fatalf("Consume lookup = %x, want SHA-256 digest %x", store.consumed, want)
	}
}

// NFR-AUTH-01
func TestProviderSanitizesStateStoreErrors(t *testing.T) {
	const raw = "raw-state nonce-secret verifier-secret"
	t.Run("put", func(t *testing.T) {
		store := &recordingStateStore{putErr: errors.New(raw)}
		p := newTestProvider(t, store)
		_, err := p.Begin(context.Background(), authentication.BeginRequest{RedirectURI: "https://app.example/callback"})
		assertSanitizedError(t, err, authentication.ErrInvalidCallback, raw)
	})
	t.Run("consume", func(t *testing.T) {
		store := &recordingStateStore{consumeErr: errors.New(raw)}
		p := newTestProvider(t, store)
		_, err := p.Complete(context.Background(), authentication.Callback{StateID: "raw-state", Code: "code"})
		assertSanitizedError(t, err, authentication.ErrUnauthenticated, raw)
	})
	t.Run("store context error with live context", func(t *testing.T) {
		store := &recordingStateStore{consumeErr: context.DeadlineExceeded}
		p := newTestProvider(t, store)
		_, err := p.Complete(context.Background(), authentication.Callback{StateID: "raw-state", Code: "code"})
		assertSanitizedError(t, err, authentication.ErrUnauthenticated, context.DeadlineExceeded.Error())
	})
	t.Run("caller cancellation", func(t *testing.T) {
		store := &recordingStateStore{consumeErr: errors.New(raw)}
		p := newTestProvider(t, store)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := p.Complete(ctx, authentication.Callback{StateID: "raw-state", Code: "code"})
		if err != context.Canceled {
			t.Fatalf("Complete error = %v, want context.Canceled", err)
		}
	})
}

// NFR-AUTH-02
func TestPendingSecretsAreOpaqueRedactingAndPersistable(t *testing.T) {
	pendingType := reflect.TypeOf(authoidc.Pending{})
	for _, name := range []string{"Nonce", "PKCEVerifier"} {
		field, ok := pendingType.FieldByName(name)
		if !ok {
			t.Fatalf("Pending.%s is missing", name)
		}
		if field.Type.Kind() == reflect.String {
			t.Fatalf("Pending.%s exposes a raw string", name)
		}
	}

	const nonce = "nonce-secret"
	const verifier = "verifier-secret"
	pending := authoidc.Pending{
		Digest:       authoidc.StateDigest("state"),
		Nonce:        authoidc.NewSecret(nonce),
		PKCEVerifier: authoidc.NewSecret(verifier),
	}
	formatted := fmt.Sprintf("%v %+v %#v", pending, pending, pending)
	if strings.Contains(formatted, nonce) || strings.Contains(formatted, verifier) {
		t.Fatalf("formatted Pending leaked secrets: %s", formatted)
	}

	encoded, err := pending.PKCEVerifier.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var restored authoidc.Secret
	if err := restored.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}
	if got := string(restored.Bytes()); got != verifier {
		t.Fatalf("restored secret = %q, want %q", got, verifier)
	}
	copied := pending
	if got := string(copied.Nonce.Bytes()); got != nonce {
		t.Fatalf("copied nonce = %q, want %q", got, nonce)
	}
}

// FR-AUTH-10
func TestNewRejectsConflictingClientIDs(t *testing.T) {
	_, err := authoidc.New(authoidc.Options{
		Name:     "work",
		Issuer:   "https://id.example",
		ClientID: "outer-client",
		Config: oauth2.Config{
			ClientID: "config-client",
			Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"},
		},
		RedirectURIs: []string{"https://app.example/callback"},
		State:        authoidc.NewMemoryStateStore(),
	})
	if !errors.Is(err, authentication.ErrInvalidCredential) {
		t.Fatalf("New error = %v, want ErrInvalidCredential", err)
	}
}

// FR-AUTH-10
func TestMemoryStateStorePutIsCreateOnly(t *testing.T) {
	store := authoidc.NewMemoryStateStore()
	digest := authoidc.StateDigest("state")
	first := authoidc.Pending{Digest: digest, Provider: "first"}
	second := authoidc.Pending{Digest: digest, Provider: "second"}
	if err := store.Put(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), second); !errors.Is(err, authentication.ErrReplay) {
		t.Fatalf("duplicate Put error = %v, want ErrReplay", err)
	}
	got, err := store.Consume(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Provider != first.Provider {
		t.Fatalf("consumed provider = %q, want original %q", got.Provider, first.Provider)
	}
}

type recordingStateStore struct {
	putErr     error
	consumeErr error
	consumed   [32]byte
}

func (s *recordingStateStore) Put(context.Context, authoidc.Pending) error {
	return s.putErr
}

func (s *recordingStateStore) Consume(_ context.Context, digest [32]byte) (authoidc.Pending, error) {
	s.consumed = digest
	return authoidc.Pending{}, s.consumeErr
}

func newTestProvider(t *testing.T, store authoidc.StateStore) *authoidc.Provider {
	t.Helper()
	p, err := authoidc.New(authoidc.Options{
		Name:         "work",
		Issuer:       "https://id.example",
		ClientID:     "client",
		RedirectURIs: []string{"https://app.example/callback"},
		State:        store,
		Random:       deterministicSecrets(10, 11, 12),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertSanitizedError(t *testing.T, got, want error, sensitive string) {
	t.Helper()
	if got != want {
		t.Fatalf("error = %v, want exact sentinel %v", got, want)
	}
	if strings.Contains(got.Error(), sensitive) {
		t.Fatalf("error leaked sensitive text %q: %v", sensitive, got)
	}
}

// TestCompleteRejectsStateAfterTTL advances virtual time past StateTTL. The
// state is consumed (and so burned) before the expiry check, and the code is
// never exchanged.
// FR-AUTH-13
func TestCompleteRejectsStateAfterTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := authoidc.NewMemoryStateStore()
		p, err := authoidc.New(authoidc.Options{
			Name:         "work",
			Issuer:       "https://id.example",
			ClientID:     "client",
			Verifier:     insecureVerifier("https://id.example", "client", time.Now()),
			RedirectURIs: []string{"https://app.example/callback"},
			State:        store,
			StateTTL:     time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		tokenEndpoint := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("code exchanged for expired state")
		})
		redirect, err := p.Begin(context.Background(), authentication.BeginRequest{RedirectURI: "https://app.example/callback"})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		_, err = p.Complete(tokenContext(tokenEndpoint), authentication.Callback{StateID: redirect.StateID, Code: "code"})
		if !errors.Is(err, authentication.ErrExpired) {
			t.Fatalf("Complete error = %v, want ErrExpired", err)
		}
		if _, err := store.Consume(context.Background(), authoidc.StateDigest(redirect.StateID)); !errors.Is(err, authentication.ErrReplay) {
			t.Fatalf("expired state was not consumed: %v", err)
		}
	})
}

// TestProviderHonorsSuppliedClock runs on the wall clock with an ID token
// issued years from now, so only Options.Clock (and the verifier's own
// clock) can accept it; moving Options.Clock to a pending state's expiry
// expires it.
// FR-AUTH-27
func TestProviderHonorsSuppliedClock(t *testing.T) {
	now := time.Date(2031, 3, 4, 5, 6, 7, 0, time.FixedZone("UTC+2", 2*60*60))
	issuedAt := now.UTC()
	tokenEndpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeToken(w, unsignedIDToken(map[string]any{
			"iss": "https://id.example", "sub": "subject", "aud": "client", "azp": "client",
			"nonce": "nonce", "iat": issuedAt.Unix(), "exp": issuedAt.Add(time.Hour).Unix(),
		}))
	})
	store := authoidc.NewMemoryStateStore()
	p, err := authoidc.New(authoidc.Options{
		Name:         "work",
		Issuer:       "https://id.example",
		ClientID:     "client",
		Verifier:     insecureVerifier("https://id.example", "client", issuedAt),
		RedirectURIs: []string{"https://app.example/callback"},
		State:        store,
		StateTTL:     time.Minute,
		Clock:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := p.Begin(context.Background(), authentication.BeginRequest{RedirectURI: "https://app.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(time.Minute); !redirect.ExpiresAt.Equal(want) || redirect.ExpiresAt.Location() != time.UTC {
		t.Fatalf("ExpiresAt = %v, want %v in UTC", redirect.ExpiresAt, want.UTC())
	}
	put := func(state string) {
		t.Helper()
		if err := store.Put(context.Background(), authoidc.Pending{
			Digest: authoidc.StateDigest(state), Provider: "work", RedirectURI: "https://app.example/callback",
			Nonce: authoidc.NewSecret("nonce"), PKCEVerifier: authoidc.NewSecret("verifier"),
			ExpiresAt: now.UTC().Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("first")
	principal, err := p.Complete(tokenContext(tokenEndpoint), authentication.Callback{StateID: "first", Code: "code"})
	if err != nil {
		t.Fatalf("Complete at supplied time error = %v", err)
	}
	if !principal.AuthenticatedAt.Equal(issuedAt) {
		t.Fatalf("AuthenticatedAt = %v, want %v", principal.AuthenticatedAt, issuedAt)
	}
	put("second")
	now = now.Add(time.Minute)
	if _, err := p.Complete(tokenContext(tokenEndpoint), authentication.Callback{StateID: "second", Code: "code"}); !errors.Is(err, authentication.ErrExpired) {
		t.Fatalf("Complete after supplied StateTTL error = %v, want ErrExpired", err)
	}
}
