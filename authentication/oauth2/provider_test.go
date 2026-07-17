package oauth2_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/justusschock/go-auth/authentication"
	authoauth2 "github.com/justusschock/go-auth/authentication/oauth2"
	authoidc "github.com/justusschock/go-auth/authentication/oidc"
	"golang.org/x/oauth2"
)

func TestBeginUsesPKCEAndDoesNotForceOpenID(t *testing.T) {
	store := authoidc.NewMemoryStateStore()
	p, err := authoauth2.New(authoauth2.Options{
		Name: "github",
		Config: oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"},
		},
		RedirectURIs: []string{"https://app.example/oauth/callback"},
		State:        store,
		Random:       deterministicSecrets(4, 5, 6),
		Mapper: func(context.Context, *oauth2.Token) (authentication.Principal, error) {
			return authentication.Principal{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	redirect, err := p.Begin(context.Background(), authentication.BeginRequest{
		RedirectURI: "https://app.example/oauth/callback",
		Scopes:      []string{"profile", "email"},
	})
	if err != nil {
		t.Fatal(err)
	}

	query := redirect.URL.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("url=%s", redirect.URL)
	}
	if strings.Contains(query.Get("scope"), "openid") {
		t.Fatalf("OAuth2 scope forced openid: %q", query.Get("scope"))
	}
	if _, err := store.Consume(context.Background(), authoidc.StateDigest(redirect.StateID)); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteUsesRequiredMapperAsOnlyIdentitySource(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	var mapped bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.FormValue("code_verifier"); got == "" {
			t.Fatalf("token request omitted PKCE verifier")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "redacted-access-token",
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	store := authoidc.NewMemoryStateStore()
	p, err := authoauth2.New(authoauth2.Options{
		Name: "github",
		Config: oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: server.URL},
		},
		RedirectURIs: []string{"https://app.example/oauth/callback"},
		State:        store,
		Clock:        func() time.Time { return now },
		Random:       deterministicSecrets(7, 8, 9),
		Mapper: func(_ context.Context, token *oauth2.Token) (authentication.Principal, error) {
			mapped = true
			if token.AccessToken == "" {
				return authentication.Principal{}, errors.New("missing access token")
			}
			return authentication.Principal{
				ID:              "github|subject",
				Issuer:          "github",
				Subject:         "subject",
				AuthenticatedAt: now,
				ExpiresAt:       now.Add(time.Hour),
				Methods:         []string{"oauth2"},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := p.Begin(context.Background(), authentication.BeginRequest{RedirectURI: "https://app.example/oauth/callback"})
	if err != nil {
		t.Fatal(err)
	}

	principal, err := p.Complete(context.Background(), authentication.Callback{StateID: redirect.StateID, Code: "code"})
	if err != nil {
		t.Fatal(err)
	}
	if !mapped || principal.Subject != "subject" {
		t.Fatalf("mapped=%v principal=%#v", mapped, principal)
	}
	if _, err := p.Complete(context.Background(), authentication.Callback{StateID: redirect.StateID, Code: "code"}); !errors.Is(err, authentication.ErrReplay) {
		t.Fatalf("second Complete error = %v, want ErrReplay", err)
	}
}

func deterministicSecrets(values ...byte) *bytes.Reader {
	data := make([]byte, 0, len(values)*32)
	for _, value := range values {
		data = append(data, bytes.Repeat([]byte{value}, 32)...)
	}
	return bytes.NewReader(data)
}

func TestNewRequiresOAuth2Mapper(t *testing.T) {
	_, err := authoauth2.New(authoauth2.Options{
		Name: "github",
		Config: oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"},
		},
		RedirectURIs: []string{"https://app.example/oauth/callback"},
		State:        authoidc.NewMemoryStateStore(),
	})
	if !errors.Is(err, authentication.ErrInvalidCredential) {
		t.Fatalf("New error = %v, want ErrInvalidCredential", err)
	}
}

func TestNewRejectsNonLoopbackHTTPURLs(t *testing.T) {
	mapper := func(context.Context, *oauth2.Token) (authentication.Principal, error) {
		return authentication.Principal{}, nil
	}
	for name, test := range map[string]struct {
		options authoauth2.Options
		want    error
	}{
		"redirect": {
			want: authentication.ErrInvalidCallback,
			options: authoauth2.Options{
				Name: "github",
				Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{
					AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token",
				}},
				RedirectURIs: []string{"http://127.attacker.example/callback"}, State: authoidc.NewMemoryStateStore(), Mapper: mapper,
			},
		},
		"authorization endpoint": {
			want: authentication.ErrInvalidCredential,
			options: authoauth2.Options{
				Name: "github",
				Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{
					AuthURL: "http://127.attacker.example/authorize", TokenURL: "https://id.example/token",
				}},
				RedirectURIs: []string{"https://app.example/callback"}, State: authoidc.NewMemoryStateStore(), Mapper: mapper,
			},
		},
		"token endpoint": {
			want: authentication.ErrInvalidCredential,
			options: authoauth2.Options{
				Name: "github",
				Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{
					AuthURL: "https://id.example/authorize", TokenURL: "http://127.attacker.example/token",
				}},
				RedirectURIs: []string{"https://app.example/callback"}, State: authoidc.NewMemoryStateStore(), Mapper: mapper,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := authoauth2.New(test.options)
			if !errors.Is(err, test.want) {
				t.Fatalf("New error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewAcceptsActualHTTPIPv4AndIPv6Loopback(t *testing.T) {
	for _, redirectURI := range []string{"http://127.0.0.1/callback", "http://[::1]/callback", "http://localhost/callback"} {
		_, err := authoauth2.New(authoauth2.Options{
			Name: "github",
			Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{
				AuthURL: "http://127.0.0.1/authorize", TokenURL: "http://[::1]/token",
			}},
			RedirectURIs: []string{redirectURI},
			State:        authoidc.NewMemoryStateStore(),
			Mapper: func(context.Context, *oauth2.Token) (authentication.Principal, error) {
				return authentication.Principal{}, nil
			},
		})
		if err != nil {
			t.Fatalf("New with redirect %q error = %v", redirectURI, err)
		}
	}
}

func TestProviderSanitizesStateStoreErrors(t *testing.T) {
	const raw = "raw-state nonce-secret verifier-secret"
	store := &failingStateStore{consumeErr: errors.New(raw)}
	p := newOAuth2TestProvider(t, store)
	_, err := p.Complete(context.Background(), authentication.Callback{StateID: "raw-state", Code: "code"})
	if err != authentication.ErrUnauthenticated || strings.Contains(err.Error(), raw) {
		t.Fatalf("Complete error = %v, want exact sanitized ErrUnauthenticated", err)
	}
	if want := authoidc.StateDigest("raw-state"); store.consumed != want {
		t.Fatalf("Consume lookup = %x, want %x", store.consumed, want)
	}

	store.consumeErr = context.DeadlineExceeded
	_, err = p.Complete(context.Background(), authentication.Callback{StateID: "raw-state", Code: "code"})
	if err != authentication.ErrUnauthenticated {
		t.Fatalf("live-context Complete error = %v, want ErrUnauthenticated", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = p.Complete(ctx, authentication.Callback{StateID: "raw-state", Code: "code"})
	if err != context.Canceled {
		t.Fatalf("canceled Complete error = %v, want context.Canceled", err)
	}
}

type failingStateStore struct {
	putErr     error
	consumeErr error
	consumed   [32]byte
}

func (s *failingStateStore) Put(context.Context, authoidc.Pending) error { return s.putErr }

func (s *failingStateStore) Consume(_ context.Context, digest [32]byte) (authoidc.Pending, error) {
	s.consumed = digest
	return authoidc.Pending{}, s.consumeErr
}

func newOAuth2TestProvider(t *testing.T, store authoidc.StateStore) *authoauth2.Provider {
	t.Helper()
	p, err := authoauth2.New(authoauth2.Options{
		Name: "github",
		Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{
			AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token",
		}},
		RedirectURIs: []string{"https://app.example/callback"},
		State:        store,
		Mapper: func(context.Context, *oauth2.Token) (authentication.Principal, error) {
			return authentication.Principal{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
