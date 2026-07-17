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
		Random:       bytes.NewReader(bytes.Repeat([]byte{4}, 96)),
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
	if _, err := store.Consume(context.Background(), redirect.StateID); err != nil {
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
		Random:       bytes.NewReader(bytes.Repeat([]byte{5}, 96)),
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
