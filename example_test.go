package goauth_test

import (
	"context"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/justusschock/auth/authentication"
	authjwt "github.com/justusschock/auth/authentication/jwt"
	"github.com/justusschock/auth/authorization"
	authcedar "github.com/justusschock/auth/authorization/cedar"
)

// exampleKeys serves one HMAC key for every key ID.
type exampleKeys struct{ key []byte }

func (k exampleKeys) Key(context.Context, string) (any, error) { return k.key, nil }

// exampleEntities serves an empty entity list for every request.
type exampleEntities struct{}

func (exampleEntities) Entities(context.Context, authorization.Request) ([]byte, error) {
	return []byte("[]"), nil
}

// Example authenticates a JWT bearer token and authorizes the resulting
// principal with a Cedar policy. Authentication and authorization are
// independent; the caller maps the principal to an authorization entity.
// FR-AUTH-25, FR-AUTH-28
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

	// Authorization: Cedar policies evaluated per request, default deny. The
	// policy is permit(principal == User::"alice", action == Action::"read", resource is Document);
	alice := authorization.Principal{Type: "User", ID: "alice"}
	read := authorization.Action{ID: "read"}
	documents := authorization.Resource{Type: "Document"}
	engine, err := authcedar.New(authcedar.Options{
		Policies: authcedar.Policies{
			{Effect: authcedar.Permit, Principal: &alice, Action: &read, Resource: documents},
		},
		Entities: exampleEntities{},
	})
	if err != nil {
		panic(err)
	}
	for _, action := range []string{"read", "delete"} {
		decision, err := engine.Authorize(ctx, authorization.Request{
			Principal: authorization.Principal{Type: "User", ID: principal.Subject},
			Action:    authorization.Action{ID: action},
			Resource:  authorization.Resource{Type: "Document", ID: "report"},
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
