package goauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/justusschock/go-auth/authentication"
	authjwt "github.com/justusschock/go-auth/authentication/jwt"
	"github.com/justusschock/go-auth/authentication/magiclink"
	authsaml "github.com/justusschock/go-auth/authentication/saml"
	"github.com/justusschock/go-auth/authorization"
	authcedar "github.com/justusschock/go-auth/authorization/cedar"
)

func FuzzJWTBytes(f *testing.F) {
	verifier, err := authjwt.NewVerifier(authjwt.Options{
		Issuer:      "https://issuer.example",
		Audiences:   []string{"api"},
		Algorithms:  []string{"HS256"},
		Keys:        exampleKeys{key: []byte("fuzz-key-with-at-least-32-bytes")},
		MaxLifetime: time.Hour,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("not-a-token"))
	f.Add([]byte("eyJhbGciOiJub25lIn0.e30."))
	f.Fuzz(func(t *testing.T, token []byte) {
		if len(token) > 64<<10 {
			t.Skip()
		}
		_, err := verifier.Authenticate(context.Background(), authentication.Credential{Kind: "jwt", Token: token})
		assertCredentialNotLeaked(t, err, string(token))
	})
}

func FuzzSAMLResponseBytes(f *testing.F) {
	now := time.Now().UTC().Truncate(time.Second)
	provider, store := fuzzSAMLProvider(f, now)
	f.Add([]byte("<Response/>"))
	f.Add([]byte("not xml"))
	f.Fuzz(func(t *testing.T, response []byte) {
		if len(response) == 0 || len(response) > 128<<10 {
			t.Skip()
		}
		digest := sha256.Sum256(response)
		requestID := "req-" + base64.RawURLEncoding.EncodeToString(digest[:12])
		if err := store.Put(context.Background(), authsaml.Request{
			ID: requestID, RelayState: "relay", ACSURL: "https://app.example/saml/acs", ExpiresAt: now.Add(time.Minute),
		}); err != nil && !errors.Is(err, authentication.ErrReplay) {
			t.Fatal(err)
		}
		encoded := base64.StdEncoding.EncodeToString(response)
		_, err := provider.Complete(context.Background(), authentication.Callback{
			StateID: requestID, RelayState: "relay", SAMLResponse: encoded,
		})
		assertCredentialNotLeaked(t, err, encoded)
	})
}

func FuzzMagicLinkTokens(f *testing.F) {
	service, err := magiclink.NewService(magiclink.Options{
		Store:        magiclink.NewMemoryStore(),
		BaseURL:      "https://app.example/magic",
		RedirectURIs: []string{"https://app.example/after"},
		TTL:          5 * time.Minute,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add("not-a-token")
	f.Add(strings.Repeat("A", 43))
	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > 64<<10 {
			t.Skip()
		}
		_, err := service.Consume(context.Background(), token)
		assertCredentialNotLeaked(t, err, token)
	})
}

func FuzzCedarContext(f *testing.F) {
	engine, err := authcedar.New(authcedar.Options{
		Policies: examplePolicies(`permit(principal, action, resource) when { context.enabled };`),
		Entities: exampleEntities{},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{0, 'x'})
	f.Add([]byte{3, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16<<10 {
			t.Skip()
		}
		var value any
		if len(data) == 0 {
			value = ""
		} else {
			switch data[0] % 4 {
			case 0:
				value = string(data[1:])
			case 1:
				value = []any{string(data[1:]), string(data[1:])}
			case 2:
				value = map[string]any{"nested": string(data[1:])}
			default:
				value = int64(len(data))
			}
		}
		decision, err := engine.Authorize(context.Background(), authorization.Request{
			Principal: authorization.Entity{Type: "User", ID: "fuzzer"},
			Action:    authorization.Entity{Type: "Action", ID: "read"},
			Resource:  authorization.Entity{Type: "Document", ID: "one"},
			Context:   map[string]any{"enabled": true, "value": value},
		})
		if err != nil && decision.Allowed {
			t.Fatalf("authorization allowed with error: %v", err)
		}
	})
}

func fuzzSAMLProvider(t testing.TB, now time.Time) (*authsaml.Provider, *authsaml.MemoryRequestStore) {
	t.Helper()
	idpKey, idpCert := fuzzCertificate(t, "fuzz-idp", now)
	_ = idpKey
	spKey, spCert := fuzzCertificate(t, "fuzz-sp", now)
	metadata := &crewjamsaml.EntityDescriptor{
		EntityID:   "https://idp.example/saml/metadata",
		ValidUntil: now.Add(time.Hour),
		IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{{
			SSODescriptor: crewjamsaml.SSODescriptor{RoleDescriptor: crewjamsaml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				KeyDescriptors: []crewjamsaml.KeyDescriptor{{Use: "signing", KeyInfo: crewjamsaml.KeyInfo{
					X509Data: crewjamsaml.X509Data{X509Certificates: []crewjamsaml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(idpCert.Raw)}}}}}},
			}},
			SingleSignOnServices: []crewjamsaml.Endpoint{{Binding: crewjamsaml.HTTPRedirectBinding, Location: "https://idp.example/saml/sso"}},
		}},
	}
	store := authsaml.NewMemoryRequestStore()
	provider, err := authsaml.New(authsaml.Options{
		Name: "fuzz", EntityID: mustParseURL(t, "https://sp.example/saml/metadata"),
		MetadataURL: mustParseURL(t, "https://sp.example/saml/metadata-document"),
		ACSURL:      mustParseURL(t, "https://app.example/saml/acs"), IDPMetadata: metadata,
		Key: spKey, Certificate: spCert, RequestStore: store, Clock: func() time.Time { return now }, MaxResponseBytes: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider, store
}

func fuzzCertificate(t testing.TB, commonName string, now time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

func mustParseURL(t testing.TB, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func assertCredentialNotLeaked(t testing.TB, err error, credential string) {
	t.Helper()
	if err != nil && len(credential) >= 16 && strings.Contains(err.Error(), credential) {
		t.Fatalf("error leaked credential")
	}
}
