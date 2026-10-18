package jwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
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

// FR-AUTH-03
func TestVerifierAcceptsValidEdDSAToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
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
		v := newTestVerifier(t, authjwt.Options{Keys: keys})

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
	})
}

// FR-AUTH-03
func TestVerifierAcceptsValidRS256Token(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
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
		})

		if _, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)}); err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
	})
}

// FR-AUTH-03
func TestNewVerifierRejectsNonPositiveMaxLifetime(t *testing.T) {
	_, err := authjwt.NewVerifier(authjwt.Options{
		Issuer:      "issuer",
		Audiences:   []string{"api"},
		Algorithms:  []string{"EdDSA"},
		Keys:        &staticKey{key: ed25519.PublicKey{}},
		MaxLifetime: 0,
	})
	if err != authentication.ErrInvalidCredential {
		t.Fatalf("got %v, want ErrInvalidCredential", err)
	}
}

// FR-AUTH-04
func TestVerifierHonorsClockSkewForMappedPrincipalExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw := signToken(t, jwt.SigningMethodEdDSA, priv, "k1", jwt.MapClaims{
			"iss": "issuer",
			"sub": "user",
			"aud": []string{"api"},
			"iat": now.Add(-time.Minute).Unix(),
			"exp": now.Add(-10 * time.Second).Unix(),
		})
		v := newTestVerifier(t, authjwt.Options{
			Keys:      &staticKey{key: pub},
			ClockSkew: 30 * time.Second,
		})

		principal, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)})
		if err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
		if err := authentication.ValidatePrincipal(principal, now); err != nil {
			t.Fatalf("returned principal violates authTime invariant: %v", err)
		}
	})
}

// FR-AUTH-04
func TestVerifierHonorsClockSkewForMappedPrincipalIssuedAt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw := signToken(t, jwt.SigningMethodEdDSA, priv, "k1", jwt.MapClaims{
			"iss": "issuer",
			"sub": "user",
			"aud": []string{"api"},
			"iat": now.Add(10 * time.Second).Unix(),
			"exp": now.Add(time.Minute).Unix(),
		})
		v := newTestVerifier(t, authjwt.Options{
			Keys:      &staticKey{key: pub},
			ClockSkew: 30 * time.Second,
		})

		principal, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)})
		if err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
		if err := authentication.ValidatePrincipal(principal, now); err != nil {
			t.Fatalf("returned principal violates authTime invariant: %v", err)
		}
	})
}

// FR-AUTH-03
func TestVerifierRejectsUnconfiguredAlgorithm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
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
		})

		assertUnauthenticated(t, v, raw)
	})
}

// FR-AUTH-03
func TestVerifierRejectsNoneAlgorithm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
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
		})

		assertUnauthenticated(t, v, raw)
	})
}

// FR-AUTH-03
func TestVerifierRejectsInvalidClaims(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(now time.Time) jwt.MapClaims{
		"wrong issuer": func(now time.Time) jwt.MapClaims {
			return jwt.MapClaims{"iss": "other", "sub": "user", "aud": []string{"api"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		},
		"wrong audience": func(now time.Time) jwt.MapClaims {
			return jwt.MapClaims{"iss": "issuer", "sub": "user", "aud": []string{"other"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		},
		"duplicate audiences": func(now time.Time) jwt.MapClaims {
			return jwt.MapClaims{"iss": "issuer", "sub": "user", "aud": []string{"api", "api"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		},
		"missing subject": func(now time.Time) jwt.MapClaims {
			return jwt.MapClaims{"iss": "issuer", "aud": []string{"api"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		},
		"expired": func(now time.Time) jwt.MapClaims {
			return jwt.MapClaims{"iss": "issuer", "sub": "user", "aud": []string{"api"}, "iat": now.Add(-2 * time.Minute).Unix(), "exp": now.Add(-time.Minute).Unix()}
		},
		"not yet valid": func(now time.Time) jwt.MapClaims {
			return jwt.MapClaims{"iss": "issuer", "sub": "user", "aud": []string{"api"}, "iat": now.Unix(), "nbf": now.Add(time.Minute).Unix(), "exp": now.Add(2 * time.Minute).Unix()}
		},
		"excessive lifetime": func(now time.Time) jwt.MapClaims {
			return jwt.MapClaims{"iss": "issuer", "sub": "user", "aud": []string{"api"}, "iat": now.Unix(), "exp": now.Add(2 * time.Hour).Unix()}
		},
	}

	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				raw := signToken(t, jwt.SigningMethodEdDSA, priv, "k1", claims(time.Now().UTC()))
				v := newTestVerifier(t, authjwt.Options{
					Keys:        &staticKey{key: pub},
					MaxLifetime: time.Hour,
				})

				assertUnauthenticated(t, v, raw)
			})
		})
	}
}

// FR-AUTH-03
func TestVerifierRejectsBadCredentialAndTokenBounds(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validClaims := func() jwt.MapClaims {
		now := time.Now().UTC()
		return jwt.MapClaims{
			"iss": "issuer",
			"sub": "user",
			"aud": []string{"api"},
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(),
		}
	}

	tests := map[string]func(t *testing.T) authentication.Credential{
		"wrong kind": func(t *testing.T) authentication.Credential {
			return authentication.Credential{Kind: "bearer", Token: []byte(signToken(t, jwt.SigningMethodEdDSA, priv, "k1", validClaims()))}
		},
		"missing kid": func(t *testing.T) authentication.Credential {
			return authentication.Credential{Kind: "jwt", Token: []byte(signToken(t, jwt.SigningMethodEdDSA, priv, "", validClaims()))}
		},
		"oversized kid": func(t *testing.T) authentication.Credential {
			return authentication.Credential{Kind: "jwt", Token: []byte(signToken(t, jwt.SigningMethodEdDSA, priv, strings.Repeat("k", 257), validClaims()))}
		},
		"oversized token": func(t *testing.T) authentication.Credential {
			return authentication.Credential{Kind: "jwt", Token: []byte(signToken(t, jwt.SigningMethodEdDSA, priv, "k1", validClaims()) + strings.Repeat("x", 1024))}
		},
	}

	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				v := newTestVerifier(t, authjwt.Options{
					Keys:          &staticKey{key: pub},
					MaxTokenBytes: len(signToken(t, jwt.SigningMethodEdDSA, priv, "k1", validClaims())) + 1,
				})

				principal, err := v.Authenticate(context.Background(), credential(t))
				if err != authentication.ErrUnauthenticated {
					t.Fatalf("got principal %#v and err %v, want ErrUnauthenticated", principal, err)
				}
			})
		})
	}
}

// NFR-AUTH-01
func TestVerifierRejectsUnknownKeyAndRedactsTokenFromErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
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
			Keys: &staticKey{err: errors.New("missing key for private-store-secret")},
		})

		principal, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)})
		if err != authentication.ErrUnauthenticated {
			t.Fatalf("got principal %#v and err %v, want ErrUnauthenticated", principal, err)
		}
		if err != nil && strings.Contains(err.Error(), raw) {
			t.Fatalf("error leaks token: %q", err)
		}
	})
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

// TestVerifierExpiryAndClockSkewOverTime advances virtual time across the
// "exp" boundary with and without clock skew.
// FR-AUTH-04
func TestVerifierExpiryAndClockSkewOverTime(t *testing.T) {
	for _, skew := range []time.Duration{0, 30 * time.Second} {
		t.Run(skew.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now().UTC()
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
				v := newTestVerifier(t, authjwt.Options{Keys: &staticKey{key: pub}, ClockSkew: skew})
				credential := authentication.Credential{Kind: "jwt", Token: []byte(raw)}

				time.Sleep(time.Minute + skew - time.Second)
				principal, err := v.Authenticate(context.Background(), credential)
				if err != nil {
					t.Fatalf("Authenticate before exp+skew: %v", err)
				}
				if err := authentication.ValidatePrincipal(principal, time.Now().UTC()); err != nil {
					t.Fatalf("principal invalid at verification time: %v", err)
				}

				time.Sleep(time.Second)
				assertUnauthenticated(t, v, raw)
			})
		})
	}
}

// TestVerifierHonorsSuppliedClock runs on the wall clock with a token issued
// years in the future, so only Options.Clock can make it valid.
// FR-AUTH-27
func TestVerifierHonorsSuppliedClock(t *testing.T) {
	issuedAt := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	now := issuedAt.In(time.FixedZone("UTC+2", 2*60*60))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := signToken(t, jwt.SigningMethodEdDSA, priv, "k1", jwt.MapClaims{
		"iss": "issuer",
		"sub": "user",
		"aud": []string{"api"},
		"iat": issuedAt.Unix(),
		"exp": issuedAt.Add(time.Minute).Unix(),
	})
	v := newTestVerifier(t, authjwt.Options{
		Keys:  &staticKey{key: pub},
		Clock: func() time.Time { return now },
	})

	principal, err := v.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: []byte(raw)})
	if err != nil {
		t.Fatalf("Authenticate at supplied time error = %v", err)
	}
	if !principal.AuthenticatedAt.Equal(issuedAt) || principal.AuthenticatedAt.Location() != time.UTC {
		t.Fatalf("AuthenticatedAt = %v, want %v in UTC", principal.AuthenticatedAt, issuedAt)
	}
	now = now.Add(time.Minute)
	assertUnauthenticated(t, v, raw)
}
