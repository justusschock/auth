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

// exampleKeys serves one HMAC key for every key ID.
type exampleKeys struct{ key []byte }

func (k exampleKeys) Key(context.Context, string) (any, error) { return k.key, nil }

// examplePolicies serves fixed Cedar policy text.
type examplePolicies string

func (p examplePolicies) Policies(context.Context) ([]byte, error) { return []byte(p), nil }

// exampleEntities serves an empty entity list for every request.
type exampleEntities struct{}

func (exampleEntities) Entities(context.Context, authorization.Request) ([]byte, error) {
	return []byte("[]"), nil
}

// Example authenticates a JWT bearer token and authorizes the resulting
// principal with a Cedar policy. Authentication and authorization are
// independent; the caller maps the principal to an authorization entity.
// FR-AUTH-25
func Example() {
	ctx := context.Background()
	key := []byte("example-key-with-at-least-32-bytes")

	// Authentication: a strict JWT verifier.
	verifier, err := authjwt.NewVerifier(authjwt.Options{
		Issuer:      "https://issuer.example",
		Audiences:   []string{"example-api"},
		Algorithms:  []string{"HS256"},
		Keys:        exampleKeys{key: key},
		ClockSkew:   time.Minute,
		MaxLifetime: 15 * time.Minute,
	})
	if err != nil {
		panic(err)
	}

	// A token as an identity provider would issue it.
	now := time.Now()
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"iss": "https://issuer.example",
		"sub": "alice",
		"aud": []string{"example-api"},
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})
	token.Header["kid"] = "example-key"
	signed, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}

	principal, err := verifier.Authenticate(ctx, authentication.Credential{
		Kind:  authentication.CredentialKindJWT,
		Token: []byte(signed),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("authenticated:", principal.ID)

	// Authorization: Cedar policies evaluated per request, default deny.
	engine, err := authcedar.New(authcedar.Options{
		Policies: examplePolicies(`permit(principal == User::"alice", action == Action::"read", resource);`),
		Entities: exampleEntities{},
	})
	if err != nil {
		panic(err)
	}
	for _, action := range []string{"read", "delete"} {
		decision, err := engine.Authorize(ctx, authorization.Request{
			Principal: authorization.Entity{Type: "User", ID: principal.Subject},
			Action:    authorization.Entity{Type: "Action", ID: action},
			Resource:  authorization.Entity{Type: "Document", ID: "report"},
		})
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s allowed: %v\n", action, decision.Allowed)
	}
	// Output:
	// authenticated: https://issuer.example|alice
	// read allowed: true
	// delete allowed: false
}
