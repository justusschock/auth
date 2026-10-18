package authentication_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/justusschock/go-auth/authentication"
)

type authenticatorFunc func(context.Context, authentication.Credential) (authentication.Principal, error)

func (f authenticatorFunc) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Principal, error) {
	return f(ctx, credential)
}

// FR-AUTH-02, NFR-AUTH-07
func TestPrincipalContextRoundTripIsIsolated(t *testing.T) {
	t.Parallel()
	principal := authentication.Principal{
		ID: "id", Issuer: "iss", Subject: "sub",
		AuthenticatedAt: time.Unix(1, 0).UTC(), ExpiresAt: time.Unix(2, 0).UTC(),
		Traits: map[string][]string{"scope": {"read"}}, Methods: []string{"jwt"},
	}
	if _, ok := authentication.PrincipalFromContext(context.Background()); ok {
		t.Fatal("empty context returned principal")
	}
	ctx := authentication.ContextWithPrincipal(context.Background(), principal)
	principal.Traits["scope"][0] = "admin"

	got, ok := authentication.PrincipalFromContext(ctx)
	if !ok || got.ID != "id" || got.Traits["scope"][0] != "read" {
		t.Fatalf("PrincipalFromContext() = %#v, %v", got, ok)
	}
	got.Traits["scope"][0] = "admin"
	again, _ := authentication.PrincipalFromContext(ctx)
	if again.Traits["scope"][0] != "read" {
		t.Fatal("context principal was mutated through returned value")
	}
}

// FR-AUTH-02
func TestChainUsesFirstSupportingAuthenticator(t *testing.T) {
	t.Parallel()
	calls := []string{}
	unsupported := authenticatorFunc(func(_ context.Context, c authentication.Credential) (authentication.Principal, error) {
		calls = append(calls, "unsupported")
		c.Token[0] = 'X'
		return authentication.Principal{}, authentication.ErrUnsupportedCredential
	})
	rejecting := authenticatorFunc(func(_ context.Context, c authentication.Credential) (authentication.Principal, error) {
		calls = append(calls, "rejecting:"+string(c.Token))
		return authentication.Principal{}, authentication.ErrUnauthenticated
	})
	accepting := authenticatorFunc(func(context.Context, authentication.Credential) (authentication.Principal, error) {
		calls = append(calls, "accepting")
		return authentication.Principal{ID: "ok"}, nil
	})
	credential := authentication.Credential{Kind: authentication.CredentialKindBearer, Token: []byte("token")}

	if _, err := authentication.Chain(unsupported, rejecting, accepting).Authenticate(context.Background(), credential); err != authentication.ErrUnauthenticated {
		t.Fatalf("Chain() error = %v, want ErrUnauthenticated", err)
	}
	if len(calls) != 2 || calls[1] != "rejecting:token" {
		t.Fatalf("calls = %v; want rejection to stop chain with unmodified credential", calls)
	}
	if string(credential.Token) != "token" {
		t.Fatal("chain mutated caller credential")
	}

	principal, err := authentication.Chain(unsupported, accepting).Authenticate(context.Background(), credential)
	if err != nil || principal.ID != "ok" {
		t.Fatalf("Chain() = %#v, %v", principal, err)
	}
}

// FR-AUTH-02
func TestChainFailsClosed(t *testing.T) {
	t.Parallel()
	credential := authentication.Credential{Kind: authentication.CredentialKindBearer, Token: []byte("token")}
	unsupported := authenticatorFunc(func(context.Context, authentication.Credential) (authentication.Principal, error) {
		return authentication.Principal{}, authentication.ErrUnsupportedCredential
	})
	if _, err := authentication.Chain().Authenticate(context.Background(), credential); err != authentication.ErrUnsupportedCredential {
		t.Fatalf("empty Chain() error = %v", err)
	}
	if _, err := authentication.Chain(unsupported, unsupported).Authenticate(context.Background(), credential); err != authentication.ErrUnsupportedCredential {
		t.Fatalf("all unsupported error = %v", err)
	}
	if _, err := authentication.Chain(unsupported, nil).Authenticate(context.Background(), credential); err != authentication.ErrUnauthenticated {
		t.Fatalf("nil authenticator error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := authentication.Chain(unsupported).Authenticate(ctx, credential); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
}
