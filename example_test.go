package goauth_test

import (
	"context"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/justusschock/go-auth/authentication"
	authjwt "github.com/justusschock/go-auth/authentication/jwt"
	"github.com/justusschock/go-auth/authorization"
	authcedar "github.com/justusschock/go-auth/authorization/cedar"
)

type exampleKeys struct{ key []byte }

func (k exampleKeys) Key(context.Context, string) (any, error) { return k.key, nil }

func Example_authentication() {
	now := time.Unix(1_700_000_000, 0).UTC()
	key := []byte("example-key-with-at-least-32-bytes")
	verifier, _ := authjwt.NewVerifier(authjwt.Options{
		Issuer:      "https://issuer.example",
		Audiences:   []string{"example-api"},
		Algorithms:  []string{"HS256"},
		Keys:        exampleKeys{key: key},
		Clock:       func() time.Time { return now },
		MaxLifetime: 15 * time.Minute,
	})
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"iss": "https://issuer.example",
		"sub": "alice",
		"aud": []string{"example-api"},
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})
	token.Header["kid"] = "example-key"
	signed, _ := token.SignedString(key)
	principal, _ := verifier.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(signed)})
	fmt.Println(principal.ID)
	// Output: https://issuer.example|alice
}

type examplePolicies string

func (p examplePolicies) Policies(context.Context) ([]byte, error) { return []byte(p), nil }

type exampleEntities struct{}

func (exampleEntities) Entities(context.Context, authorization.Request) ([]byte, error) {
	return []byte("[]"), nil
}

func Example_authorization() {
	engine, _ := authcedar.New(authcedar.Options{
		Policies: examplePolicies(`permit(principal, action == Action::"read", resource);`),
		Entities: exampleEntities{},
	})
	decision, _ := engine.Authorize(context.Background(), authorization.Request{
		Principal: authorization.Entity{Type: "User", ID: "alice"},
		Action:    authorization.Entity{Type: "Action", ID: "read"},
		Resource:  authorization.Entity{Type: "Document", ID: "document-1"},
	})
	fmt.Println(decision.Allowed)
	// Output: true
}
