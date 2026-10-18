package saml_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	authsaml "github.com/justusschock/go-auth/authentication/saml"
)

const (
	fixtureRSASHA256SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	fixtureACSURL                   = "https://app.example/saml/acs"
	fixtureEntityID                 = "https://sp.example/saml/metadata"
	fixtureMetadataURL              = "https://sp.example/saml/metadata-document"
	fixtureIDPEntityID              = "https://idp.example/saml/metadata"
	fixtureIDPSSOURL                = "https://idp.example/saml/sso"
	fixtureRequestID                = "req-1"
	fixtureRelayState               = "relay"
)

type fixture struct {
	now      time.Time
	idpKey   *rsa.PrivateKey
	idpCert  *x509.Certificate
	spKey    *rsa.PrivateKey
	spCert   *x509.Certificate
	metadata *crewjamsaml.EntityDescriptor
}

type responseOptions struct {
	unsigned               bool
	signResponse           bool
	secondAssertion        bool
	encryptedAssertion     bool
	nestedAttributeDepth   int
	extraAttributeElements int
	responseTime           time.Time
	responseDestination    string
	responseIssuer         string
	responseInResponseTo   string
	assertionIssuer        string
	audience               string
	conditionsNotBefore    time.Time
	conditionsNotOnOrAfter time.Time
	subjectRecipient       string
	subjectInResponseTo    string
	subjectNotBefore       time.Time
	subjectNotOnOrAfter    time.Time
	authenticatedAt        time.Time
}

var (
	fixtureMu    sync.Mutex
	fixtureCache = make(map[testing.TB]*fixture)
)

func future() time.Time {
	return time.Now().UTC().Add(time.Hour)
}

func fixtureFor(t testing.TB) *fixture {
	t.Helper()
	fixtureMu.Lock()
	defer fixtureMu.Unlock()
	if existing := fixtureCache[t]; existing != nil {
		return existing
	}
	now := time.Now().UTC().Truncate(time.Second)
	idpKey, idpCert := generatedCertificate(t, "fixture-idp", now)
	spKey, spCert := generatedCertificate(t, "fixture-sp", now)
	metadata := &crewjamsaml.EntityDescriptor{
		EntityID:   fixtureIDPEntityID,
		ValidUntil: now.Add(time.Hour),
		IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{{
			SSODescriptor: crewjamsaml.SSODescriptor{RoleDescriptor: crewjamsaml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				KeyDescriptors: []crewjamsaml.KeyDescriptor{{
					Use: "signing",
					KeyInfo: crewjamsaml.KeyInfo{X509Data: crewjamsaml.X509Data{X509Certificates: []crewjamsaml.X509Certificate{{
						Data: base64.StdEncoding.EncodeToString(idpCert.Raw),
					}}}},
				}},
			}},
			SingleSignOnServices: []crewjamsaml.Endpoint{{Binding: crewjamsaml.HTTPRedirectBinding, Location: fixtureIDPSSOURL}},
		}},
	}
	created := &fixture{now: now, idpKey: idpKey, idpCert: idpCert, spKey: spKey, spCert: spCert, metadata: metadata}
	fixtureCache[t] = created
	t.Cleanup(func() {
		fixtureMu.Lock()
		delete(fixtureCache, t)
		fixtureMu.Unlock()
	})
	return created
}

func generatedCertificate(t testing.TB, commonName string, now time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
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

func fixtureOptions(t testing.TB, store authsaml.RequestStore) authsaml.Options {
	t.Helper()
	f := fixtureFor(t)
	return authsaml.Options{
		Name:             "test-saml",
		EntityID:         mustURL(t, fixtureEntityID),
		MetadataURL:      mustURL(t, fixtureMetadataURL),
		ACSURL:           mustURL(t, fixtureACSURL),
		IDPMetadata:      f.metadata,
		Key:              f.spKey,
		Certificate:      f.spCert,
		RequestStore:     store,
		AllowedClockSkew: 30 * time.Second,
		MaxResponseBytes: 64 << 10,
	}
}

func signedFixtureProvider(t testing.TB, store authsaml.RequestStore) *authsaml.Provider {
	t.Helper()
	provider, err := authsaml.New(fixtureOptions(t, store))
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func signedFixtureResponse(t testing.TB) string {
	t.Helper()
	return fixtureResponse(t, responseOptions{})
}

func fixtureResponse(t testing.TB, options responseOptions) string {
	t.Helper()
	f := fixtureFor(t)
	responseTime := options.responseTime
	if responseTime.IsZero() {
		responseTime = f.now
	}
	if options.responseDestination == "" {
		options.responseDestination = fixtureACSURL
	}
	if options.responseIssuer == "" {
		options.responseIssuer = fixtureIDPEntityID
	}
	if options.responseInResponseTo == "" {
		options.responseInResponseTo = fixtureRequestID
	}
	if options.assertionIssuer == "" {
		options.assertionIssuer = fixtureIDPEntityID
	}
	if options.audience == "" {
		options.audience = fixtureEntityID
	}
	if options.conditionsNotBefore.IsZero() {
		options.conditionsNotBefore = responseTime.Add(-time.Minute)
	}
	if options.conditionsNotOnOrAfter.IsZero() {
		options.conditionsNotOnOrAfter = responseTime.Add(5 * time.Minute)
	}
	if options.subjectRecipient == "" {
		options.subjectRecipient = fixtureACSURL
	}
	if options.subjectInResponseTo == "" {
		options.subjectInResponseTo = fixtureRequestID
	}
	if options.subjectNotOnOrAfter.IsZero() {
		options.subjectNotOnOrAfter = responseTime.Add(5 * time.Minute)
	}
	if options.authenticatedAt.IsZero() {
		options.authenticatedAt = responseTime.Add(-time.Minute)
	}

	assertion := &crewjamsaml.Assertion{
		ID:           "assertion-1",
		IssueInstant: responseTime,
		Version:      "2.0",
		Issuer:       crewjamsaml.Issuer{Value: options.assertionIssuer},
		Subject: &crewjamsaml.Subject{
			NameID: &crewjamsaml.NameID{Format: string(crewjamsaml.PersistentNameIDFormat), Value: "alice"},
			SubjectConfirmations: []crewjamsaml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &crewjamsaml.SubjectConfirmationData{
					InResponseTo: options.subjectInResponseTo,
					Recipient:    options.subjectRecipient,
					NotBefore:    options.subjectNotBefore,
					NotOnOrAfter: options.subjectNotOnOrAfter,
				},
			}},
		},
		Conditions: &crewjamsaml.Conditions{
			NotBefore:            options.conditionsNotBefore,
			NotOnOrAfter:         options.conditionsNotOnOrAfter,
			AudienceRestrictions: []crewjamsaml.AudienceRestriction{{Audience: crewjamsaml.Audience{Value: options.audience}}},
		},
		AuthnStatements: []crewjamsaml.AuthnStatement{{
			AuthnInstant: options.authenticatedAt,
			AuthnContext: crewjamsaml.AuthnContext{AuthnContextClassRef: &crewjamsaml.AuthnContextClassRef{
				Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			}},
		}},
		AttributeStatements: []crewjamsaml.AttributeStatement{{Attributes: []crewjamsaml.Attribute{{
			Name:   "email",
			Values: []crewjamsaml.AttributeValue{{Type: "xs:string", Value: "alice@example.com"}},
		}}}},
	}
	assertionElement := assertion.Element()
	attributeValue := assertionElement.FindElement(".//AttributeValue")
	if attributeValue == nil {
		t.Fatal("fixture assertion has no AttributeValue")
	}
	if options.nestedAttributeDepth > 0 {
		attributeValue.SetText("")
		parent := attributeValue
		for range options.nestedAttributeDepth {
			child := etree.NewElement("deep:value")
			child.CreateAttr("xmlns:deep", "urn:fixture:deep")
			parent.AddChild(child)
			parent = child
		}
		parent.SetText("alice@example.com")
	}
	for range options.extraAttributeElements {
		child := etree.NewElement("extra:value")
		child.CreateAttr("xmlns:extra", "urn:fixture:extra")
		attributeValue.AddChild(child)
	}
	if !options.unsigned && !options.signResponse {
		assertionElement = signElement(t, f, assertionElement)
	}

	response := (&crewjamsaml.Response{
		ID:           "response-1",
		InResponseTo: options.responseInResponseTo,
		Version:      "2.0",
		IssueInstant: responseTime,
		Destination:  options.responseDestination,
		Issuer:       &crewjamsaml.Issuer{Value: options.responseIssuer},
		Status:       crewjamsaml.Status{StatusCode: crewjamsaml.StatusCode{Value: crewjamsaml.StatusSuccess}},
	}).Element()
	if options.encryptedAssertion {
		response.AddChild(etree.NewElement("saml:EncryptedAssertion"))
	} else {
		response.AddChild(assertionElement)
		if options.secondAssertion {
			response.AddChild(assertionElement.Copy())
		}
	}
	if options.signResponse {
		response = signElement(t, f, response)
	}
	document := etree.NewDocument()
	document.SetRoot(response)
	encoded, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func signElement(t testing.TB, f *fixture, element *etree.Element) *etree.Element {
	t.Helper()
	context, err := crewjamsaml.GetSigningContext(&crewjamsaml.ServiceProvider{
		Key: f.idpKey, Certificate: f.idpCert, SignatureMethod: fixtureRSASHA256SignatureMethod,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := context.SignEnveloped(element)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func mustURL(t testing.TB, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
