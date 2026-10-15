package saml_test

import (
	"compress/flate"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/justusschock/go-auth/authentication"
	authsaml "github.com/justusschock/go-auth/authentication/saml"
)

func TestBeginBuildsSignedSHA256RequestForExactRegisteredACS(t *testing.T) {
	store := authsaml.NewMemoryRequestStore()
	provider := signedFixtureProvider(t, store)

	redirect, err := provider.Begin(context.Background(), authentication.BeginRequest{RedirectURI: fixtureACSURL})
	if err != nil {
		t.Fatal(err)
	}
	query := redirect.URL.Query()
	if query.Get("SigAlg") != fixtureRSASHA256SignatureMethod || query.Get("Signature") == "" {
		t.Fatalf("redirect does not contain an RSA-SHA256 signature: %q", redirect.URL.RawQuery)
	}
	if redirect.StateID == "" || query.Get("RelayState") == "" || query.Get("RelayState") == redirect.StateID {
		t.Fatalf("request ID and RelayState must be independent: id=%q relay=%q", redirect.StateID, query.Get("RelayState"))
	}
	requestXML := decodeRedirectRequest(t, query.Get("SAMLRequest"))
	for _, exact := range []string{
		`AssertionConsumerServiceURL="` + fixtureACSURL + `"`,
		`Destination="` + fixtureIDPSSOURL + `"`,
		`<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">` + fixtureEntityID + `</saml:Issuer>`,
		`ID="` + redirect.StateID + `"`,
	} {
		if !strings.Contains(requestXML, exact) {
			t.Fatalf("AuthnRequest missing exact %q: %s", exact, requestXML)
		}
	}
	stored, err := store.Consume(context.Background(), redirect.StateID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != redirect.StateID || stored.RelayState != query.Get("RelayState") || stored.ACSURL != fixtureACSURL || !stored.ExpiresAt.Equal(redirect.ExpiresAt) {
		t.Fatalf("stored request = %#v, redirect = %#v", stored, redirect)
	}
}

func TestBeginRejectsNonExactACS(t *testing.T) {
	provider := signedFixtureProvider(t, authsaml.NewMemoryRequestStore())
	for _, redirectURI := range []string{"", fixtureACSURL + "/", "https://evil.example/saml/acs"} {
		if _, err := provider.Begin(context.Background(), authentication.BeginRequest{RedirectURI: redirectURI}); !errors.Is(err, authentication.ErrInvalidCallback) {
			t.Fatalf("Begin(%q) error = %v, want ErrInvalidCallback", redirectURI, err)
		}
	}
}

func TestProviderOwnsServiceProviderCredentials(t *testing.T) {
	f := fixtureFor(t)
	options := fixtureOptions(t, authsaml.NewMemoryRequestStore())
	provider, err := authsaml.New(options)
	if err != nil {
		t.Fatal(err)
	}

	options.Key.N.SetInt64(3)
	options.Certificate.Raw[0] ^= 0xff
	options.Certificate.PublicKey.(*rsa.PublicKey).N.SetInt64(3)

	redirect, err := provider.Begin(context.Background(), authentication.BeginRequest{RedirectURI: fixtureACSURL})
	if err != nil {
		t.Fatalf("Begin() after caller credential mutation: %v", err)
	}
	if redirect.URL.Query().Get("Signature") == "" || f.spKey.N.BitLen() != 2 {
		t.Fatal("test did not mutate caller-owned credentials")
	}
}

func TestCompleteConsumesRequestBeforeParsing(t *testing.T) {
	store := authsaml.NewMemoryRequestStore()
	putFixtureRequest(t, store)
	provider := signedFixtureProvider(t, store)
	callback := authentication.Callback{StateID: fixtureRequestID, RelayState: fixtureRelayState, SAMLResponse: signedFixtureResponse(t)}

	principal, err := provider.Complete(context.Background(), callback)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != fixtureIDPEntityID+"|alice" || principal.Issuer != fixtureIDPEntityID || principal.Subject != "alice" {
		t.Fatalf("principal identity = %#v", principal)
	}
	if got := principal.Traits["email"]; len(got) != 1 || got[0] != "alice@example.com" {
		t.Fatalf("principal email trait = %#v", got)
	}
	if err := authentication.ValidatePrincipal(principal, fixtureFor(t).now); err != nil {
		t.Fatalf("ValidatePrincipal() error = %v", err)
	}
	if _, err := provider.Complete(context.Background(), callback); !errors.Is(err, authentication.ErrReplay) {
		t.Fatalf("second Complete error = %v, want ErrReplay", err)
	}
}

func TestCompleteAcceptsSignedResponseWithUnsignedAssertion(t *testing.T) {
	store := authsaml.NewMemoryRequestStore()
	putFixtureRequest(t, store)
	provider := signedFixtureProvider(t, store)
	response := fixtureResponse(t, responseOptions{unsigned: true, signResponse: true})
	if _, err := provider.Complete(context.Background(), fixtureCallback(response)); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
}

func TestCompleteRejectsUnsignedOrAmbiguousAssertions(t *testing.T) {
	tests := []struct {
		name     string
		response func(testing.TB) string
	}{
		{name: "unsigned response and assertion", response: func(t testing.TB) string { return fixtureResponse(t, responseOptions{unsigned: true}) }},
		{name: "multiple assertions", response: func(t testing.TB) string { return fixtureResponse(t, responseOptions{secondAssertion: true}) }},
		{name: "encrypted assertion", response: func(t testing.TB) string { return fixtureResponse(t, responseOptions{encryptedAssertion: true}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := authsaml.NewMemoryRequestStore()
			putFixtureRequest(t, store)
			provider := signedFixtureProvider(t, store)
			if _, err := provider.Complete(context.Background(), fixtureCallback(test.response(t))); !errors.Is(err, authentication.ErrUnauthenticated) {
				t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestCompleteRejectsMismatchedSignedProtocolFields(t *testing.T) {
	tests := []struct {
		name    string
		options responseOptions
	}{
		{name: "response destination", options: responseOptions{responseDestination: "https://evil.example/acs"}},
		{name: "response issuer", options: responseOptions{responseIssuer: "https://evil.example/idp"}},
		{name: "response InResponseTo", options: responseOptions{responseInResponseTo: "other-request"}},
		{name: "assertion issuer", options: responseOptions{assertionIssuer: "https://evil.example/idp"}},
		{name: "audience", options: responseOptions{audience: "https://evil.example/sp"}},
		{name: "subject recipient", options: responseOptions{subjectRecipient: "https://evil.example/acs"}},
		{name: "subject InResponseTo", options: responseOptions{subjectInResponseTo: "other-request"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := authsaml.NewMemoryRequestStore()
			putFixtureRequest(t, store)
			provider := signedFixtureProvider(t, store)
			if _, err := provider.Complete(context.Background(), fixtureCallback(fixtureResponse(t, test.options))); !errors.Is(err, authentication.ErrUnauthenticated) {
				t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestCompleteAppliesExplicitClockSkewAndLifetime(t *testing.T) {
	tests := []struct {
		name    string
		options func(time.Time) responseOptions
		wantErr bool
	}{
		{name: "within skew", options: func(now time.Time) responseOptions {
			return responseOptions{conditionsNotBefore: now.Add(29 * time.Second)}
		}},
		{name: "expired within skew", options: func(now time.Time) responseOptions {
			return responseOptions{conditionsNotOnOrAfter: now.Add(-29 * time.Second)}
		}},
		{name: "beyond skew", options: func(now time.Time) responseOptions {
			return responseOptions{conditionsNotBefore: now.Add(31 * time.Second)}
		}, wantErr: true},
		{name: "expired conditions", options: func(now time.Time) responseOptions {
			return responseOptions{conditionsNotOnOrAfter: now.Add(-31 * time.Second)}
		}, wantErr: true},
		{name: "expired subject confirmation", options: func(now time.Time) responseOptions {
			return responseOptions{subjectNotOnOrAfter: now.Add(-31 * time.Second)}
		}, wantErr: true},
		{name: "future authentication", options: func(now time.Time) responseOptions {
			return responseOptions{authenticatedAt: now.Add(time.Second)}
		}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := fixtureFor(t)
			store := authsaml.NewMemoryRequestStore()
			putFixtureRequest(t, store)
			provider := signedFixtureProvider(t, store)
			_, err := provider.Complete(context.Background(), fixtureCallback(fixtureResponse(t, test.options(f.now))))
			if test.wantErr && !errors.Is(err, authentication.ErrUnauthenticated) {
				t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("Complete() error = %v", err)
			}
		})
	}
}

func TestCompleteRejectsRelayMismatchAndExpiredRequest(t *testing.T) {
	t.Run("relay mismatch", func(t *testing.T) {
		store := authsaml.NewMemoryRequestStore()
		putFixtureRequest(t, store)
		provider := signedFixtureProvider(t, store)
		callback := fixtureCallback(signedFixtureResponse(t))
		callback.RelayState = "other-relay"
		if _, err := provider.Complete(context.Background(), callback); !errors.Is(err, authentication.ErrUnauthenticated) {
			t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
		}
		if _, err := store.Consume(context.Background(), fixtureRequestID); !errors.Is(err, authentication.ErrReplay) {
			t.Fatalf("request was not consumed before relay validation: %v", err)
		}
	})
	t.Run("expired request", func(t *testing.T) {
		store := authsaml.NewMemoryRequestStore()
		if err := store.Put(context.Background(), authsaml.Request{ID: fixtureRequestID, RelayState: fixtureRelayState, ACSURL: fixtureACSURL, ExpiresAt: fixtureFor(t).now}); err != nil {
			t.Fatal(err)
		}
		provider := signedFixtureProvider(t, store)
		if _, err := provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t))); !errors.Is(err, authentication.ErrExpired) {
			t.Fatalf("Complete() error = %v, want ErrExpired", err)
		}
	})
}

func TestRelayStateUsesSAMLBindingLimit(t *testing.T) {
	store := authsaml.NewMemoryRequestStore()
	request := authsaml.Request{ID: fixtureRequestID, RelayState: strings.Repeat("r", 80), ACSURL: fixtureACSURL, ExpiresAt: future()}
	if err := store.Put(context.Background(), request); err != nil {
		t.Fatalf("Put(80-byte RelayState) error = %v", err)
	}
	request.ID = "req-2"
	request.RelayState += "r"
	if err := store.Put(context.Background(), request); !errors.Is(err, authentication.ErrInvalidCallback) {
		t.Fatalf("Put(81-byte RelayState) error = %v, want ErrInvalidCallback", err)
	}

	recording := &recordingRequestStore{}
	provider := signedFixtureProvider(t, recording)
	callback := fixtureCallback(signedFixtureResponse(t))
	callback.RelayState = strings.Repeat("r", 81)
	if _, err := provider.Complete(context.Background(), callback); !errors.Is(err, authentication.ErrInvalidCallback) {
		t.Fatalf("Complete(81-byte RelayState) error = %v, want ErrInvalidCallback", err)
	}
	if recording.consumeCalls != 0 {
		t.Fatalf("Consume calls = %d, want 0", recording.consumeCalls)
	}
}

func TestCompleteUsesProviderClockWithoutCrewjamTemporalGlobals(t *testing.T) {
	for _, test := range []struct {
		name   string
		offset time.Duration
	}{
		{name: "ahead of process clock", offset: 10 * time.Minute},
		{name: "behind process clock", offset: -10 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := fixtureFor(t)
			providerNow := f.now.Add(test.offset)
			store := authsaml.NewMemoryRequestStore()
			if err := store.Put(context.Background(), authsaml.Request{
				ID: fixtureRequestID, RelayState: fixtureRelayState, ACSURL: fixtureACSURL, ExpiresAt: providerNow.Add(time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			options := fixtureOptions(t, store)
			options.Clock = func() time.Time { return providerNow }
			provider, err := authsaml.New(options)
			if err != nil {
				t.Fatal(err)
			}
			response := fixtureResponse(t, responseOptions{responseTime: providerNow})
			if _, err := provider.Complete(context.Background(), fixtureCallback(response)); err != nil {
				t.Fatalf("Complete() with provider-owned clock error = %v", err)
			}
		})
	}
}

func TestCompleteRejectsBearerSubjectConfirmationNotBefore(t *testing.T) {
	f := fixtureFor(t)
	store := authsaml.NewMemoryRequestStore()
	putFixtureRequest(t, store)
	provider := signedFixtureProvider(t, store)
	response := fixtureResponse(t, responseOptions{subjectNotBefore: f.now.Add(-time.Second)})
	if _, err := provider.Complete(context.Background(), fixtureCallback(response)); !errors.Is(err, authentication.ErrUnauthenticated) {
		t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
	}
}

func TestCompleteRejectsExcessiveXMLComplexity(t *testing.T) {
	tests := []struct {
		name    string
		options responseOptions
	}{
		{name: "depth", options: responseOptions{nestedAttributeDepth: 40}},
		{name: "elements", options: responseOptions{extraAttributeElements: 500}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := authsaml.NewMemoryRequestStore()
			putFixtureRequest(t, store)
			options := fixtureOptions(t, store)
			options.MaxResponseBytes = 1 << 20
			provider, err := authsaml.New(options)
			if err != nil {
				t.Fatal(err)
			}
			response := fixtureResponse(t, test.options)
			if _, err = provider.Complete(context.Background(), fixtureCallback(response)); !errors.Is(err, authentication.ErrUnauthenticated) {
				t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestCompleteChecksEncodedLimitBeforeDecodeOrStoreAccess(t *testing.T) {
	store := &recordingRequestStore{}
	options := fixtureOptions(t, store)
	options.MaxResponseBytes = 8
	provider, err := authsaml.New(options)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Complete(context.Background(), authentication.Callback{
		StateID: fixtureRequestID, RelayState: fixtureRelayState, SAMLResponse: strings.Repeat("!", 13),
	})
	if !errors.Is(err, authentication.ErrInvalidCallback) {
		t.Fatalf("Complete() error = %v, want ErrInvalidCallback", err)
	}
	if store.consumeCalls != 0 {
		t.Fatalf("Consume calls = %d, want 0", store.consumeCalls)
	}
}

func TestCompleteSanitizesStoreParserAndMapperErrors(t *testing.T) {
	const secret = "SECRET_ASSERTION_OR_PRIVATE_KEY"
	t.Run("store", func(t *testing.T) {
		store := &recordingRequestStore{consumeErr: errors.New(secret)}
		provider := signedFixtureProvider(t, store)
		_, err := provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t)))
		assertSanitized(t, err, secret)
	})
	t.Run("parser", func(t *testing.T) {
		store := authsaml.NewMemoryRequestStore()
		putFixtureRequest(t, store)
		provider := signedFixtureProvider(t, store)
		_, err := provider.Complete(context.Background(), fixtureCallback(base64.StdEncoding.EncodeToString([]byte("<"+secret))))
		assertSanitized(t, err, secret)
	})
	t.Run("mapper", func(t *testing.T) {
		store := authsaml.NewMemoryRequestStore()
		putFixtureRequest(t, store)
		options := fixtureOptions(t, store)
		options.Mapper = func(context.Context, authsaml.Claims) (authentication.Principal, error) {
			return authentication.Principal{}, errors.New(secret)
		}
		provider, err := authsaml.New(options)
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t)))
		assertSanitized(t, err, secret)
	})
}

func TestCompleteRejectsInvalidMappedPrincipal(t *testing.T) {
	store := authsaml.NewMemoryRequestStore()
	putFixtureRequest(t, store)
	options := fixtureOptions(t, store)
	options.Mapper = func(context.Context, authsaml.Claims) (authentication.Principal, error) {
		return authentication.Principal{ID: "invalid"}, nil
	}
	provider, err := authsaml.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t))); !errors.Is(err, authentication.ErrUnauthenticated) {
		t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
	}
}

func TestMemoryRequestStoreIsAtomicAndDoesNotLeakStoredValues(t *testing.T) {
	store := authsaml.NewMemoryRequestStore()
	request := authsaml.Request{ID: fixtureRequestID, RelayState: "SECRET_RELAY", ACSURL: fixtureACSURL, ExpiresAt: future()}
	if err := store.Put(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), request); !errors.Is(err, authentication.ErrReplay) || strings.Contains(err.Error(), request.RelayState) {
		t.Fatalf("duplicate Put error = %v", err)
	}
	if _, err := store.Consume(context.Background(), request.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(context.Background(), request.ID); !errors.Is(err, authentication.ErrReplay) || strings.Contains(err.Error(), request.RelayState) {
		t.Fatalf("second Consume error = %v", err)
	}
}

func putFixtureRequest(t testing.TB, store authsaml.RequestStore) {
	t.Helper()
	if err := store.Put(context.Background(), authsaml.Request{
		ID: fixtureRequestID, RelayState: fixtureRelayState, ACSURL: fixtureACSURL, ExpiresAt: fixtureFor(t).now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
}

func fixtureCallback(response string) authentication.Callback {
	return authentication.Callback{StateID: fixtureRequestID, RelayState: fixtureRelayState, SAMLResponse: response}
}

func decodeRedirectRequest(t testing.TB, encoded string) string {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reader := flate.NewReader(strings.NewReader(string(compressed)))
	defer func() { _ = reader.Close() }()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
}

func assertSanitized(t testing.TB, err error, secret string) {
	t.Helper()
	if !errors.Is(err, authentication.ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked secret: %v", err)
	}
}

type recordingRequestStore struct {
	consumeCalls int
	consumeErr   error
}

func (*recordingRequestStore) Put(context.Context, authsaml.Request) error { return nil }

func (s *recordingRequestStore) Consume(context.Context, string) (authsaml.Request, error) {
	s.consumeCalls++
	return authsaml.Request{}, s.consumeErr
}
