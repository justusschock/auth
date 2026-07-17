package jwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/justusschock/go-auth/authentication"
	authjwt "github.com/justusschock/go-auth/authentication/jwt"
)

type staticKey struct {
	key any
	err error
	kid string
}

func (s *staticKey) Key(_ context.Context, kid string) (any, error) {
	s.kid = kid
	if s.err != nil {
		return nil, s.err
	}
	return s.key, nil
}

func TestVerifierAcceptsValidEdDSAToken(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	raw := signToken(t, jwt.SigningMethodEdDSA, priv, "k1", jwt.MapClaims{
		"iss": "issuer",
		"sub": "user",
		"aud": []string{"api"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	keys := &staticKey{key: pub}
	v := newTestVerifier(t, authjwt.Options{Keys: keys, Clock: func() time.Time { return now }})

	principal, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if keys.kid != "k1" {
		t.Fatalf("key source saw kid %q", keys.kid)
	}
	if principal.ID != "issuer|user" || principal.Issuer != "issuer" || principal.Subject != "user" {
		t.Fatalf("unexpected principal identity: %#v", principal)
	}
	if !principal.AuthenticatedAt.Equal(now) || !principal.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected principal lifetime: %#v", principal)
	}
	if got := strings.Join(principal.Methods, ","); got != "jwt" {
		t.Fatalf("unexpected methods: %q", got)
	}
}

func TestVerifierAcceptsValidRS256Token(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	raw := signToken(t, jwt.SigningMethodRS256, priv, "rsa1", jwt.MapClaims{
		"iss": "issuer",
		"sub": "user",
		"aud": []string{"api"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := newTestVerifier(t, authjwt.Options{
		Algorithms: []string{"RS256"},
		Keys:       &staticKey{key: &priv.PublicKey},
		Clock:      func() time.Time { return now },
	})

	if _, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)}); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
}

func TestVerifierRejectsUnconfiguredAlgorithm(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := signToken(t, jwt.SigningMethodEdDSA, priv, "k1", jwt.MapClaims{
		"iss": "issuer",
		"sub": "user",
		"aud": []string{"api"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := newTestVerifier(t, authjwt.Options{
		Algorithms: []string{"RS256"},
		Keys:       &staticKey{key: pub},
		Clock:      func() time.Time { return now },
	})

	assertUnauthenticated(t, v, raw)
}

func TestVerifierRejectsNoneAlgorithm(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": "issuer",
		"sub": "user",
		"aud": []string{"api"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	token.Header["kid"] = "k1"
	raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	v := newTestVerifier(t, authjwt.Options{
		Algorithms: []string{"none", "EdDSA"},
		Keys:       &staticKey{key: []byte("ignored")},
		Clock:      func() time.Time { return now },
	})

	assertUnauthenticated(t, v, raw)
}

func TestVerifierRejectsInvalidClaims(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]jwt.MapClaims{
		"wrong issuer": {
			"iss": "other", "sub": "user", "aud": []string{"api"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		},
		"wrong audience": {
			"iss": "issuer", "sub": "user", "aud": []string{"other"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		},
		"duplicate audiences": {
			"iss": "issuer", "sub": "user", "aud": []string{"api", "api"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		},
		"missing subject": {
			"iss": "issuer", "aud": []string{"api"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		},
		"expired": {
			"iss": "issuer", "sub": "user", "aud": []string{"api"}, "iat": now.Add(-2 * time.Minute).Unix(), "exp": now.Add(-time.Minute).Unix(),
		},
		"not yet valid": {
			"iss": "issuer", "sub": "user", "aud": []string{"api"}, "iat": now.Unix(), "nbf": now.Add(time.Minute).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		},
		"excessive lifetime": {
			"iss": "issuer", "sub": "user", "aud": []string{"api"}, "iat": now.Unix(), "exp": now.Add(2 * time.Hour).Unix(),
		},
	}

	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			raw := signToken(t, jwt.SigningMethodEdDSA, priv, "k1", claims)
			v := newTestVerifier(t, authjwt.Options{
				Keys:        &staticKey{key: pub},
				Clock:       func() time.Time { return now },
				MaxLifetime: time.Hour,
			})

			assertUnauthenticated(t, v, raw)
		})
	}
}

func TestVerifierRejectsBadCredentialAndTokenBounds(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validClaims := jwt.MapClaims{
		"iss": "issuer",
		"sub": "user",
		"aud": []string{"api"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	}

	tests := map[string]authentication.Credential{
		"wrong kind": {
			Kind:  "bearer",
			Token: []byte(signToken(t, jwt.SigningMethodEdDSA, priv, "k1", validClaims)),
		},
		"missing kid": {
			Kind:  "jwt",
			Token: []byte(signToken(t, jwt.SigningMethodEdDSA, priv, "", validClaims)),
		},
		"oversized kid": {
			Kind:  "jwt",
			Token: []byte(signToken(t, jwt.SigningMethodEdDSA, priv, strings.Repeat("k", 257), validClaims)),
		},
		"oversized token": {
			Kind:  "jwt",
			Token: []byte(signToken(t, jwt.SigningMethodEdDSA, priv, "k1", validClaims) + strings.Repeat("x", 1024)),
		},
	}

	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			v := newTestVerifier(t, authjwt.Options{
				Keys:          &staticKey{key: pub},
				Clock:         func() time.Time { return now },
				MaxTokenBytes: len(signToken(t, jwt.SigningMethodEdDSA, priv, "k1", validClaims)) + 1,
			})

			principal, err := v.Authenticate(context.Background(), credential)
			if err != authentication.ErrUnauthenticated {
				t.Fatalf("got principal %#v and err %v, want ErrUnauthenticated", principal, err)
			}
		})
	}
}

func TestVerifierRejectsUnknownKeyAndRedactsTokenFromErrors(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := signToken(t, jwt.SigningMethodEdDSA, priv, "k1", jwt.MapClaims{
		"iss": "issuer",
		"sub": "user",
		"aud": []string{"api"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	v := newTestVerifier(t, authjwt.Options{
		Keys:  &staticKey{err: errors.New("missing key for private-store-secret")},
		Clock: func() time.Time { return now },
	})

	principal, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)})
	if err != authentication.ErrUnauthenticated {
		t.Fatalf("got principal %#v and err %v, want ErrUnauthenticated", principal, err)
	}
	if err != nil && strings.Contains(err.Error(), raw) {
		t.Fatalf("error leaks token: %q", err)
	}
}

func newTestVerifier(t *testing.T, options authjwt.Options) *authjwt.Verifier {
	t.Helper()
	if options.Issuer == "" {
		options.Issuer = "issuer"
	}
	if len(options.Audiences) == 0 {
		options.Audiences = []string{"api"}
	}
	if len(options.Algorithms) == 0 {
		options.Algorithms = []string{"EdDSA"}
	}
	if options.MaxLifetime == 0 {
		options.MaxLifetime = time.Hour
	}
	v, err := authjwt.NewVerifier(options)
	if err != nil {
		t.Fatalf("NewVerifier returned error: %v", err)
	}
	return v
}

func signToken(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertUnauthenticated(t *testing.T, v *authjwt.Verifier, raw string) {
	t.Helper()
	principal, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)})
	if err != authentication.ErrUnauthenticated {
		t.Fatalf("got principal %#v and err %v, want ErrUnauthenticated", principal, err)
	}
}
