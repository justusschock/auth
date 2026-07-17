package oidc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/justusschock/go-auth/authentication"
	authoidc "github.com/justusschock/go-auth/authentication/oidc"
	"golang.org/x/oauth2"
)

func TestBeginStoresHashedStateNonceAndPKCE(t *testing.T) {
	store := authoidc.NewMemoryStateStore()
	now := time.Unix(100, 0).UTC()
	p, err := authoidc.New(authoidc.Options{
		Name:         "work",
		Issuer:       "https://id.example",
		ClientID:     "client",
		RedirectURIs: []string{"https://app.example/callback"},
		State:        store,
		Clock:        func() time.Time { return now },
		Random:       bytes.NewReader(bytes.Repeat([]byte{1}, 96)),
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

	pending, err := store.Consume(context.Background(), redirect.StateID)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Provider != "work" || pending.RedirectURI != "https://app.example/callback" {
		t.Fatalf("pending = %#v", pending)
	}
	if pending.Nonce == "" || pending.PKCEVerifier == "" || pending.Nonce == pending.PKCEVerifier || pending.Nonce == redirect.StateID {
		t.Fatalf("state, nonce, and verifier must be independent: %#v", pending)
	}
	if pending.Digest == [32]byte{} || bytes.Contains(pending.Digest[:], []byte(redirect.StateID)) {
		t.Fatalf("pending digest must not store raw state: %#v", pending.Digest)
	}
	if _, err := store.Consume(context.Background(), redirect.StateID); !errors.Is(err, authentication.ErrReplay) {
		t.Fatalf("second consume error = %v, want ErrReplay", err)
	}
}

func TestBeginRequiresExactRegisteredHTTPSRedirect(t *testing.T) {
	p, err := authoidc.New(authoidc.Options{
		Name:         "work",
		Issuer:       "https://id.example",
		ClientID:     "client",
		RedirectURIs: []string{"https://app.example/callback"},
		State:        authoidc.NewMemoryStateStore(),
		Random:       bytes.NewReader(bytes.Repeat([]byte{2}, 96)),
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

func TestCompleteConsumesBeforeExchangeAndAllowsOnlyOneCallback(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	var tokenRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer server.Close()

	store := authoidc.NewMemoryStateStore()
	p, err := authoidc.New(authoidc.Options{
		Name:   "work",
		Issuer: "https://id.example",
		Config: oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://id.example/authorize",
				TokenURL: server.URL,
			},
		},
		Verifier:     insecureVerifier("https://id.example", "client", now),
		RedirectURIs: []string{"https://app.example/callback"},
		State:        store,
		Clock:        func() time.Time { return now },
		Random:       bytes.NewReader(bytes.Repeat([]byte{3}, 96)),
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := p.Begin(context.Background(), authentication.BeginRequest{RedirectURI: "https://app.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store.Consume(context.Background(), redirect.StateID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	nonceByVerifier.Store(pending.PKCEVerifier, pending.Nonce)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Complete(context.Background(), authentication.Callback{StateID: redirect.StateID, Code: "code"})
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
}

func TestCompleteRejectsNonceProviderAndAuthorizedPartyMismatch(t *testing.T) {
	now := time.Unix(300, 0).UTC()
	tests := map[string]struct {
		provider string
		claims   map[string]any
	}{
		"provider mismatch": {
			provider: "other",
			claims: map[string]any{
				"iss": "https://id.example", "sub": "subject", "aud": "client", "azp": "client",
				"nonce": "nonce", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			},
		},
		"nonce mismatch": {
			provider: "work",
			claims: map[string]any{
				"iss": "https://id.example", "sub": "subject", "aud": "client", "azp": "client",
				"nonce": "wrong", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			},
		},
		"azp mismatch with multiple audiences": {
			provider: "work",
			claims: map[string]any{
				"iss": "https://id.example", "sub": "subject", "aud": []string{"client", "other"}, "azp": "other",
				"nonce": "nonce", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeToken(w, unsignedIDToken(test.claims))
			}))
			defer server.Close()
			store := authoidc.NewMemoryStateStore()
			p, err := authoidc.New(authoidc.Options{
				Name:   "work",
				Issuer: "https://id.example",
				Config: oauth2.Config{
					ClientID: "client",
					Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: server.URL},
				},
				Verifier:     insecureVerifier("https://id.example", "client", now),
				RedirectURIs: []string{"https://app.example/callback"},
				State:        store,
				Clock:        func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			pending := authoidc.Pending{
				Digest:       authoidc.StateDigest("state"),
				Provider:     test.provider,
				RedirectURI:  "https://app.example/callback",
				Nonce:        "nonce",
				PKCEVerifier: "verifier",
				ExpiresAt:    now.Add(time.Minute),
			}
			if err := store.Put(context.Background(), pending); err != nil {
				t.Fatal(err)
			}
			_, err = p.Complete(context.Background(), authentication.Callback{StateID: "state", Code: "code"})
			if !errors.Is(err, authentication.ErrUnauthenticated) {
				t.Fatalf("Complete error = %v, want ErrUnauthenticated", err)
			}
		})
	}
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
