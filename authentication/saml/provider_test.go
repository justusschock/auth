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
	"testing/synctest"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/justusschock/auth/authentication"
	authsaml "github.com/justusschock/auth/authentication/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// FR-AUTH-14
func TestBeginBuildsSignedSHA256RequestForExactRegisteredACS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
}

// FR-AUTH-14
func TestBeginRejectsNonExactACS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider := signedFixtureProvider(t, authsaml.NewMemoryRequestStore())
		for _, redirectURI := range []string{"", fixtureACSURL + "/", "https://evil.example/saml/acs"} {
			if _, err := provider.Begin(context.Background(), authentication.BeginRequest{RedirectURI: redirectURI}); !errors.Is(err, authentication.ErrInvalidCallback) {
				t.Fatalf("Begin(%q) error = %v, want ErrInvalidCallback", redirectURI, err)
			}
		}
	})
}

// FR-AUTH-14
func TestProviderOwnsServiceProviderCredentials(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
}

// FR-AUTH-14
func TestCompleteConsumesRequestBeforeParsing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
}

// FR-AUTH-14
func TestCompleteAcceptsSignedResponseWithUnsignedAssertion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := authsaml.NewMemoryRequestStore()
		putFixtureRequest(t, store)
		provider := signedFixtureProvider(t, store)
		response := fixtureResponse(t, responseOptions{unsigned: true, signResponse: true})
		if _, err := provider.Complete(context.Background(), fixtureCallback(response)); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
	})
}

// FR-AUTH-14
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
			synctest.Test(t, func(t *testing.T) {
				store := authsaml.NewMemoryRequestStore()
				putFixtureRequest(t, store)
				provider := signedFixtureProvider(t, store)
				if _, err := provider.Complete(context.Background(), fixtureCallback(test.response(t))); !errors.Is(err, authentication.ErrUnauthenticated) {
					t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
				}
			})
		})
	}
}

// FR-AUTH-14
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
			synctest.Test(t, func(t *testing.T) {
				store := authsaml.NewMemoryRequestStore()
				putFixtureRequest(t, store)
				provider := signedFixtureProvider(t, store)
				if _, err := provider.Complete(context.Background(), fixtureCallback(fixtureResponse(t, test.options))); !errors.Is(err, authentication.ErrUnauthenticated) {
					t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
				}
			})
		})
	}
}

// FR-AUTH-15
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
			synctest.Test(t, func(t *testing.T) {
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
		})
	}
}

// FR-AUTH-15
func TestCompleteRejectsRelayMismatchAndExpiredRequest(t *testing.T) {
	t.Run("relay mismatch", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
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
	})
	t.Run("expired request", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := authsaml.NewMemoryRequestStore()
			if err := store.Put(context.Background(), authsaml.Request{ID: fixtureRequestID, RelayState: fixtureRelayState, ACSURL: fixtureACSURL, ExpiresAt: fixtureFor(t).now}); err != nil {
				t.Fatal(err)
			}
			provider := signedFixtureProvider(t, store)
			if _, err := provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t))); !errors.Is(err, authentication.ErrExpired) {
				t.Fatalf("Complete() error = %v, want ErrExpired", err)
			}
		})
	})
}

// FR-AUTH-16
func TestRelayStateUsesSAMLBindingLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
}

// TestCompleteIgnoresCrewjamTemporalGlobals moves crewjam/saml's
// process-global clocks away from the real time and checks that response
// validation still follows time.Now. It mutates package globals and must not
// run in parallel.
// FR-AUTH-15
func TestCompleteIgnoresCrewjamTemporalGlobals(t *testing.T) {
	for _, test := range []struct {
		name   string
		offset time.Duration
	}{
		{name: "library clock ahead", offset: 10 * time.Minute},
		{name: "library clock behind", offset: -10 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixtureFor(t)
				previousNow, previousClock := crewjamsaml.TimeNow, crewjamsaml.Clock
				t.Cleanup(func() { crewjamsaml.TimeNow, crewjamsaml.Clock = previousNow, previousClock })
				shifted := f.now.Add(test.offset)
				crewjamsaml.TimeNow = func() time.Time { return shifted }
				crewjamsaml.Clock = dsig.NewFakeClockAt(shifted)

				store := authsaml.NewMemoryRequestStore()
				putFixtureRequest(t, store)
				provider := signedFixtureProvider(t, store)
				if _, err := provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t))); err != nil {
					t.Fatalf("Complete() with shifted crewjam clocks error = %v", err)
				}
			})
		})
	}
}

// TestCompleteRejectsRequestAfterTTL advances virtual time past the pending
// request lifetime. The request is consumed before the expiry check.
// FR-AUTH-15
func TestCompleteRejectsRequestAfterTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := authsaml.NewMemoryRequestStore()
		provider := signedFixtureProvider(t, store)
		redirect, err := provider.Begin(context.Background(), authentication.BeginRequest{RedirectURI: fixtureACSURL})
		if err != nil {
			t.Fatal(err)
		}
		if want := time.Now().Add(10 * time.Minute); !redirect.ExpiresAt.Equal(want) {
			t.Fatalf("ExpiresAt = %v, want %v", redirect.ExpiresAt, want)
		}
		time.Sleep(10 * time.Minute)
		callback := authentication.Callback{
			StateID:      redirect.StateID,
			RelayState:   redirect.URL.Query().Get("RelayState"),
			SAMLResponse: signedFixtureResponse(t),
		}
		if _, err := provider.Complete(context.Background(), callback); !errors.Is(err, authentication.ErrExpired) {
			t.Fatalf("Complete() error = %v, want ErrExpired", err)
		}
		if _, err := store.Consume(context.Background(), redirect.StateID); !errors.Is(err, authentication.ErrReplay) {
			t.Fatalf("expired request was not consumed: %v", err)
		}
	})
}

// TestCompleteAssertionLifetimeWithSkewOverTime advances virtual time across
// the assertion's NotOnOrAfter plus the allowed skew (30s in the fixture).
// FR-AUTH-15
func TestCompleteAssertionLifetimeWithSkewOverTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := fixtureFor(t)
		store := authsaml.NewMemoryRequestStore()
		provider := signedFixtureProvider(t, store)
		response := fixtureResponse(t, responseOptions{
			conditionsNotOnOrAfter: f.now.Add(time.Minute),
			subjectNotOnOrAfter:    f.now.Add(time.Minute),
		})

		time.Sleep(time.Minute + 29*time.Second)
		putFixtureRequest(t, store)
		principal, err := provider.Complete(context.Background(), fixtureCallback(response))
		if err != nil {
			t.Fatalf("Complete() within skew error = %v", err)
		}
		if err := authentication.ValidatePrincipal(principal, time.Now().UTC()); err != nil {
			t.Fatalf("principal invalid within skew: %v", err)
		}

		time.Sleep(time.Second)
		putFixtureRequest(t, store)
		if _, err := provider.Complete(context.Background(), fixtureCallback(response)); !errors.Is(err, authentication.ErrUnauthenticated) {
			t.Fatalf("Complete() beyond skew error = %v, want ErrUnauthenticated", err)
		}
	})
}

// FR-AUTH-15
func TestCompleteRejectsBearerSubjectConfirmationNotBefore(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := fixtureFor(t)
		store := authsaml.NewMemoryRequestStore()
		putFixtureRequest(t, store)
		provider := signedFixtureProvider(t, store)
		response := fixtureResponse(t, responseOptions{subjectNotBefore: f.now.Add(-time.Second)})
		if _, err := provider.Complete(context.Background(), fixtureCallback(response)); !errors.Is(err, authentication.ErrUnauthenticated) {
			t.Fatalf("Complete() error = %v, want ErrUnauthenticated", err)
		}
	})
}

// FR-AUTH-16
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
			synctest.Test(t, func(t *testing.T) {
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
		})
	}
}

// FR-AUTH-16
func TestCompleteChecksEncodedLimitBeforeDecodeOrStoreAccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
}

// NFR-AUTH-01
func TestCompleteSanitizesStoreParserAndMapperErrors(t *testing.T) {
	const secret = "SECRET_ASSERTION_OR_PRIVATE_KEY"
	t.Run("store", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := &recordingRequestStore{consumeErr: errors.New(secret)}
			provider := signedFixtureProvider(t, store)
			_, err := provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t)))
			assertSanitized(t, err, secret)
		})
	})
	t.Run("parser", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := authsaml.NewMemoryRequestStore()
			putFixtureRequest(t, store)
			provider := signedFixtureProvider(t, store)
			_, err := provider.Complete(context.Background(), fixtureCallback(base64.StdEncoding.EncodeToString([]byte("<"+secret))))
			assertSanitized(t, err, secret)
		})
	})
	t.Run("mapper", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
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
	})
}

// FR-AUTH-14
func TestCompleteRejectsInvalidMappedPrincipal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
}

// FR-AUTH-16
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

// TestProviderHonorsSuppliedClock lets virtual time run past the lifetime of
// the fixture's certificates and metadata, then pins Options.Clock to the
// fixture time: construction, request expiry and response validation all
// follow the supplied clock.
// FR-AUTH-27
func TestProviderHonorsSuppliedClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := fixtureFor(t)
		time.Sleep(2 * time.Hour)
		store := authsaml.NewMemoryRequestStore()
		if _, err := authsaml.New(fixtureOptions(t, store)); !errors.Is(err, authentication.ErrInvalidCredential) {
			t.Fatalf("New() with expired credentials on the default clock error = %v, want ErrInvalidCredential", err)
		}

		now := f.now.In(time.FixedZone("UTC+2", 2*60*60))
		options := fixtureOptions(t, store)
		options.Clock = func() time.Time { return now }
		provider, err := authsaml.New(options)
		if err != nil {
			t.Fatalf("New() at supplied time error = %v", err)
		}
		redirect, err := provider.Begin(context.Background(), authentication.BeginRequest{RedirectURI: fixtureACSURL})
		if err != nil {
			t.Fatal(err)
		}
		if want := f.now.Add(10 * time.Minute); !redirect.ExpiresAt.Equal(want) || redirect.ExpiresAt.Location() != time.UTC {
			t.Fatalf("ExpiresAt = %v, want %v in UTC", redirect.ExpiresAt, want)
		}

		putFixtureRequest(t, store)
		if _, err := provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t))); err != nil {
			t.Fatalf("Complete() at supplied time error = %v", err)
		}

		now = now.Add(10 * time.Minute)
		putFixtureRequest(t, store)
		if _, err := provider.Complete(context.Background(), fixtureCallback(signedFixtureResponse(t))); !errors.Is(err, authentication.ErrExpired) {
			t.Fatalf("Complete() after supplied request TTL error = %v, want ErrExpired", err)
		}
	})
}
