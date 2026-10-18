// Package saml authenticates SAML 2.0 Web Browser SSO responses (HTTP-POST
// binding) for service-provider initiated logins, as an
// authentication.FederatedProvider.
//
// Begin sends a signed (RSA-SHA256) AuthnRequest with the HTTP-Redirect
// binding to the single registered ACS URL and stores the request ID and an
// independent RelayState through a caller-owned RequestStore. Complete
// consumes that request atomically, then accepts only a response that:
// is at most Options.MaxResponseBytes, round-trips as XML, has bounded depth
// and element count, contains exactly one unencrypted assertion and unique
// IDs, is signed (response or assertion) by a certificate from the IdP
// metadata, and whose issuer, destination, InResponseTo, audience, bearer
// subject confirmation, conditions and issue instants all match within
// Options.AllowedClockSkew. IdP-initiated logins are rejected.
//
// Time checks use this package's own validation with Options.Clock (default
// time.Now) rather than the process-global clock and skew variables of
// github.com/crewjam/saml.
package saml

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/justusschock/auth/authentication"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	defaultRequestTTL        = 10 * time.Minute
	defaultAllowedClockSkew  = 2 * time.Minute
	defaultMaxResponseBytes  = 1 << 20
	maxProtocolTextBytes     = 4096
	maxRelayStateBytes       = 80
	maxXMLDepth              = 32
	maxXMLElements           = 256
	rsaSHA256SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

	samlAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	bearerConfirmation     = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

// Request is the callback state for one service-provider initiated request.
type Request struct {
	ID         string
	RelayState string
	ACSURL     string
	ExpiresAt  time.Time
}

// RequestStore persists callback state. Put must fail with
// authentication.ErrReplay when the ID exists. Consume must atomically remove
// and return the request and return authentication.ErrReplay when none
// exists, so that concurrent callbacks cannot both consume it.
type RequestStore interface {
	Put(context.Context, Request) error
	Consume(context.Context, string) (Request, error)
}

// MemoryRequestStore is a process-local RequestStore for tests and
// single-process callers. Distributed deployments should provide a durable
// atomic implementation.
type MemoryRequestStore struct {
	mu       sync.Mutex
	requests map[string]Request
}

// NewMemoryRequestStore returns an empty memory-backed request store.
func NewMemoryRequestStore() *MemoryRequestStore {
	return &MemoryRequestStore{requests: make(map[string]Request)}
}

// Put stores a valid request unless its ID is already present.
func (s *MemoryRequestStore) Put(ctx context.Context, request Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validProtocolText(request.ID) || !validRelayState(request.RelayState) ||
		!validProtocolText(request.ACSURL) || request.ExpiresAt.IsZero() || request.ExpiresAt.Location() != time.UTC {
		return authentication.ErrInvalidCallback
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.requests[request.ID]; exists {
		return authentication.ErrReplay
	}
	s.requests[request.ID] = request
	return nil
}

// Consume atomically removes and returns the request with id.
func (s *MemoryRequestStore) Consume(ctx context.Context, id string) (Request, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, exists := s.requests[id]
	if !exists {
		return Request{}, authentication.ErrReplay
	}
	delete(s.requests, id)
	return request, nil
}

// Claims is the bounded, verified SAML data presented to a ClaimsMapper.
type Claims struct {
	NameID          string
	Attributes      map[string][]string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}

// ClaimsMapper maps verified SAML claims to a protocol-neutral principal.
type ClaimsMapper func(context.Context, Claims) (authentication.Principal, error)

// Options configures a Provider. The provider deep-copies keys, certificates
// and metadata, so later changes by the caller have no effect.
type Options struct {
	// Name identifies the provider (lower-cased and trimmed). Required.
	Name string
	// EntityID, MetadataURL and ACSURL are the service provider's https
	// URLs. Required.
	EntityID    *url.URL
	MetadataURL *url.URL
	ACSURL      *url.URL
	// IDPMetadata describes the identity provider. It must have an https
	// entity ID, exactly one HTTP-Redirect SSO endpoint and at least one
	// currently valid signing certificate, and must not be past ValidUntil.
	IDPMetadata *crewjamsaml.EntityDescriptor
	// Key and Certificate are the service provider's signing key pair: RSA
	// of at least 2048 bits with a currently valid certificate. Required.
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
	// RequestStore persists pending requests. Required.
	RequestStore RequestStore
	// Clock returns the current time used to validate key, certificate and
	// metadata lifetimes, request expiry and assertion conditions; its result
	// is converted to UTC. Defaults to time.Now.
	Clock func() time.Time
	// MaxResponseBytes bounds the decoded response. Zero selects the default
	// of 1 MiB.
	MaxResponseBytes int
	// AllowedClockSkew is the tolerated clock difference with the identity
	// provider. Zero selects the default of two minutes; negative values are
	// rejected.
	AllowedClockSkew time.Duration
	// Mapper maps verified claims to a principal. The default uses ID
	// "<idp entity ID>|<NameID>", copies attributes into Traits and sets
	// Methods to ["saml"].
	Mapper ClaimsMapper
}

// Provider is a SAML 2.0 service provider for one identity provider. It is
// safe for concurrent use when its RequestStore and Mapper are.
type Provider struct {
	name             string
	entityID         string
	acsURL           string
	idpEntityID      string
	serviceProvider  crewjamsaml.ServiceProvider
	idpSigningCerts  []*x509.Certificate
	requestStore     RequestStore
	clock            func() time.Time
	maxResponseBytes int
	allowedClockSkew time.Duration
	mapper           ClaimsMapper
}

var _ authentication.FederatedProvider = (*Provider)(nil)

// New validates options and returns a Provider. It returns
// authentication.ErrInvalidCredential for invalid options.
func New(options Options) (*Provider, error) {
	name := strings.ToLower(strings.TrimSpace(options.Name))
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	now := clock().UTC()
	skew := options.AllowedClockSkew
	if skew == 0 {
		skew = defaultAllowedClockSkew
	}
	maxResponseBytes := options.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = defaultMaxResponseBytes
	}
	if !validProtocolText(name) || options.RequestStore == nil || now.IsZero() || skew < 0 ||
		maxResponseBytes < 1 || maxResponseBytes > maxBase64DecodedLength() ||
		!validHTTPSURL(options.EntityID) || !validHTTPSURL(options.MetadataURL) || !validHTTPSURL(options.ACSURL) ||
		!validSPKeyPair(options.Key, options.Certificate, now) {
		return nil, authentication.ErrInvalidCredential
	}
	key, certificate, ok := cloneSigningCredentials(options.Key, options.Certificate)
	if !ok || !validSPKeyPair(key, certificate, now) {
		return nil, authentication.ErrInvalidCredential
	}
	metadata, idpSSOURL, idpSigningCerts, ok := cloneAndValidateIDPMetadata(options.IDPMetadata, now)
	if !ok {
		return nil, authentication.ErrInvalidCredential
	}
	mapper := options.Mapper
	if mapper == nil {
		mapper = defaultClaimsMapper(metadata.EntityID)
	}
	entityID := options.EntityID.String()
	metadataURL := cloneURL(options.MetadataURL)
	acsURL := cloneURL(options.ACSURL)
	serviceProvider := crewjamsaml.ServiceProvider{
		EntityID:          entityID,
		Key:               key,
		Certificate:       certificate,
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		IDPMetadata:       metadata,
		SignatureMethod:   rsaSHA256SignatureMethod,
		AllowIDPInitiated: false,
	}
	if serviceProvider.GetSSOBindingLocation(crewjamsaml.HTTPRedirectBinding) != idpSSOURL {
		return nil, authentication.ErrInvalidCredential
	}
	return &Provider{
		name:             name,
		entityID:         entityID,
		acsURL:           acsURL.String(),
		idpEntityID:      metadata.EntityID,
		serviceProvider:  serviceProvider,
		idpSigningCerts:  idpSigningCerts,
		requestStore:     options.RequestStore,
		clock:            clock,
		maxResponseBytes: maxResponseBytes,
		allowedClockSkew: skew,
		mapper:           mapper,
	}, nil
}

// Name returns the normalized provider name.
func (p *Provider) Name() string {
	return p.name
}

// Begin starts a login. request.RedirectURI must equal the ACS URL. The
// pending request expires after ten minutes.
func (p *Provider) Begin(ctx context.Context, request authentication.BeginRequest) (authentication.Redirect, error) {
	if err := ctx.Err(); err != nil {
		return authentication.Redirect{}, err
	}
	if request.RedirectURI != p.acsURL || (request.Provider != "" && request.Provider != p.name) {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	authnRequest, err := p.serviceProvider.MakeAuthenticationRequest(
		p.serviceProvider.GetSSOBindingLocation(crewjamsaml.HTTPRedirectBinding),
		crewjamsaml.HTTPRedirectBinding,
		crewjamsaml.HTTPPostBinding,
	)
	if err != nil || authnRequest.ID == "" || authnRequest.AssertionConsumerServiceURL != p.acsURL ||
		authnRequest.Issuer == nil || authnRequest.Issuer.Value != p.entityID {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	relayState, err := randomRelayState()
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	redirectURL, err := authnRequest.Redirect(relayState, &p.serviceProvider)
	if err != nil {
		return authentication.Redirect{}, authentication.ErrInvalidCallback
	}
	expiresAt := p.clock().UTC().Add(defaultRequestTTL)
	pending := Request{ID: authnRequest.ID, RelayState: relayState, ACSURL: p.acsURL, ExpiresAt: expiresAt}
	if err := p.requestStore.Put(ctx, pending); err != nil {
		return authentication.Redirect{}, sanitizeStoreError(ctx, err, authentication.ErrInvalidCallback)
	}
	return authentication.Redirect{URL: cloneURL(redirectURL), StateID: authnRequest.ID, ExpiresAt: expiresAt}.Clone(), nil
}

// Complete consumes the pending request and verifies the SAML response in
// callback.SAMLResponse (base64). It returns authentication.ErrInvalidCallback
// for malformed or oversized callbacks, authentication.ErrReplay for unknown
// or reused requests, authentication.ErrExpired for expired requests and
// authentication.ErrUnauthenticated for every verification failure.
func (p *Provider) Complete(ctx context.Context, callback authentication.Callback) (authentication.Principal, error) {
	if err := ctx.Err(); err != nil {
		return authentication.Principal{}, err
	}
	if !validProtocolText(callback.StateID) || !validRelayState(callback.RelayState) || callback.SAMLResponse == "" || callback.Code != "" {
		return authentication.Principal{}, authentication.ErrInvalidCallback
	}
	if len(callback.SAMLResponse) > base64.StdEncoding.EncodedLen(p.maxResponseBytes) {
		return authentication.Principal{}, authentication.ErrInvalidCallback
	}
	responseXML, err := base64.StdEncoding.DecodeString(callback.SAMLResponse)
	if err != nil || len(responseXML) == 0 || len(responseXML) > p.maxResponseBytes {
		return authentication.Principal{}, authentication.ErrInvalidCallback
	}
	pending, err := p.requestStore.Consume(ctx, callback.StateID)
	if err != nil {
		return authentication.Principal{}, sanitizeStoreError(ctx, err, authentication.ErrUnauthenticated)
	}
	now := p.clock().UTC()
	if !validProtocolText(pending.ID) || !validRelayState(pending.RelayState) || !validProtocolText(pending.ACSURL) ||
		pending.ID != callback.StateID || pending.RelayState != callback.RelayState || pending.ACSURL != p.acsURL {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if pending.ExpiresAt.IsZero() || !now.Before(pending.ExpiresAt) {
		return authentication.Principal{}, authentication.ErrExpired
	}
	if err := validateResponseStructure(responseXML); err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	assertion, err := p.parseVerifiedAssertion(responseXML, now)
	if err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	response, err := parseResponseHeader(responseXML)
	if err != nil || !p.validateResponse(response, pending, now) {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	claims, ok := p.validatedClaims(assertion, pending, now)
	if !ok {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	principal, err := p.mapper(ctx, cloneClaims(claims))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return authentication.Principal{}, ctxErr
		}
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if err := authentication.ValidatePrincipal(principal, now); err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	return principal.Clone(), nil
}

type responseHeader struct {
	XMLName      xml.Name
	ID           string `xml:",attr"`
	InResponseTo string `xml:",attr"`
	Version      string `xml:",attr"`
	IssueInstant string `xml:",attr"`
	Destination  string `xml:",attr"`
	Issuer       *struct {
		Value string `xml:",chardata"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status struct {
		StatusCode struct {
			Value string `xml:",attr"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

func parseResponseHeader(value []byte) (responseHeader, error) {
	var response responseHeader
	if err := xml.Unmarshal(value, &response); err != nil {
		return responseHeader{}, err
	}
	return response, nil
}

func (p *Provider) validateResponse(response responseHeader, pending Request, now time.Time) bool {
	issueInstant, err := time.Parse(time.RFC3339Nano, response.IssueInstant)
	if err != nil || response.XMLName.Space != samlProtocolNamespace || response.XMLName.Local != "Response" ||
		!validProtocolText(response.ID) || response.Version != "2.0" || response.InResponseTo != pending.ID ||
		response.Destination != p.acsURL || response.Issuer == nil || response.Issuer.Value != p.idpEntityID ||
		response.Status.StatusCode.Value != crewjamsaml.StatusSuccess {
		return false
	}
	return validIssueInstant(issueInstant, now, p.allowedClockSkew)
}

func (p *Provider) validatedClaims(assertion *crewjamsaml.Assertion, pending Request, now time.Time) (Claims, bool) {
	if assertion == nil || !validProtocolText(assertion.ID) || assertion.Version != "2.0" ||
		assertion.Issuer.Value != p.idpEntityID || !validIssueInstant(assertion.IssueInstant, now, p.allowedClockSkew) ||
		assertion.Subject == nil || assertion.Subject.NameID == nil || !validProtocolText(assertion.Subject.NameID.Value) ||
		assertion.Conditions == nil || len(assertion.Subject.SubjectConfirmations) != 1 || len(assertion.AuthnStatements) != 1 {
		return Claims{}, false
	}
	confirmation := assertion.Subject.SubjectConfirmations[0]
	confirmationData := confirmation.SubjectConfirmationData
	if confirmation.Method != bearerConfirmation || confirmationData == nil ||
		confirmationData.InResponseTo != pending.ID || confirmationData.Recipient != p.acsURL ||
		confirmationData.NotOnOrAfter.IsZero() || !now.Before(confirmationData.NotOnOrAfter.Add(p.allowedClockSkew)) ||
		!confirmationData.NotBefore.IsZero() {
		return Claims{}, false
	}
	conditions := assertion.Conditions
	if conditions.NotBefore.IsZero() || conditions.NotOnOrAfter.IsZero() || !conditions.NotBefore.Before(conditions.NotOnOrAfter) ||
		conditions.NotBefore.After(now.Add(p.allowedClockSkew)) || !now.Before(conditions.NotOnOrAfter.Add(p.allowedClockSkew)) ||
		len(conditions.AudienceRestrictions) == 0 {
		return Claims{}, false
	}
	for _, restriction := range conditions.AudienceRestrictions {
		if restriction.Audience.Value != p.entityID {
			return Claims{}, false
		}
	}
	authenticatedAt := assertion.AuthnStatements[0].AuthnInstant.UTC()
	if authenticatedAt.IsZero() || authenticatedAt.After(now) {
		return Claims{}, false
	}
	signedExpiresAt := conditions.NotOnOrAfter.UTC()
	if confirmationData.NotOnOrAfter.Before(signedExpiresAt) {
		signedExpiresAt = confirmationData.NotOnOrAfter.UTC()
	}
	if sessionExpiry := assertion.AuthnStatements[0].SessionNotOnOrAfter; sessionExpiry != nil && sessionExpiry.Before(signedExpiresAt) {
		signedExpiresAt = sessionExpiry.UTC()
	}
	if !authenticatedAt.Before(signedExpiresAt) || !now.Before(signedExpiresAt.Add(p.allowedClockSkew)) {
		return Claims{}, false
	}
	expiresAt := signedExpiresAt
	if !now.Before(expiresAt) {
		expiresAt = signedExpiresAt.Add(p.allowedClockSkew)
	}
	attributes := make(map[string][]string)
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			name := attribute.Name
			if name == "" {
				name = attribute.FriendlyName
			}
			if !validProtocolText(name) {
				return Claims{}, false
			}
			for _, value := range attribute.Values {
				if !validProtocolValue(value.Value) {
					return Claims{}, false
				}
				attributes[name] = append(attributes[name], value.Value)
			}
		}
	}
	return Claims{
		NameID:          assertion.Subject.NameID.Value,
		Attributes:      attributes,
		AuthenticatedAt: authenticatedAt,
		ExpiresAt:       expiresAt,
	}, true
}

func validateResponseStructure(value []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(value))
	depth := 0
	elements := 0
	responses := 0
	assertions := 0
	directAssertions := 0
	encryptedAssertions := 0
	responseIssuers := 0
	ids := make(map[string]struct{})
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch current := token.(type) {
		case xml.StartElement:
			depth++
			elements++
			if depth > maxXMLDepth || elements > maxXMLElements {
				return authentication.ErrUnauthenticated
			}
			if depth == 1 && (current.Name.Space != samlProtocolNamespace || current.Name.Local != "Response") {
				return authentication.ErrUnauthenticated
			}
			if current.Name.Space == samlProtocolNamespace && current.Name.Local == "Response" {
				responses++
			}
			if current.Name.Space == samlAssertionNamespace && current.Name.Local == "Assertion" {
				assertions++
				if depth == 2 {
					directAssertions++
				}
			}
			if current.Name.Space == samlAssertionNamespace && current.Name.Local == "EncryptedAssertion" {
				encryptedAssertions++
			}
			if depth == 2 && current.Name.Space == samlAssertionNamespace && current.Name.Local == "Issuer" {
				responseIssuers++
			}
			for _, attribute := range current.Attr {
				if attribute.Name.Space == "" && attribute.Name.Local == "ID" && attribute.Value != "" {
					if _, exists := ids[attribute.Value]; exists {
						return authentication.ErrUnauthenticated
					}
					ids[attribute.Value] = struct{}{}
				}
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return authentication.ErrUnauthenticated
			}
		case xml.Directive, xml.ProcInst:
			return authentication.ErrUnauthenticated
		}
	}
	if depth != 0 || responses != 1 || assertions != 1 || directAssertions != 1 || encryptedAssertions != 0 || responseIssuers != 1 {
		return authentication.ErrUnauthenticated
	}
	return nil
}

// parseVerifiedAssertion keeps response time policy per provider. Crewjam's
// high-level parser applies process-global clock and skew values, so this uses
// its underlying round-trip and XMLDSIG dependencies directly.
func (p *Provider) parseVerifiedAssertion(value []byte, now time.Time) (*crewjamsaml.Assertion, error) {
	if err := xrv.Validate(bytes.NewReader(value)); err != nil {
		return nil, err
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(value); err != nil || document.Root() == nil {
		return nil, authentication.ErrUnauthenticated
	}

	responseElement := document.Root()
	assertionElement, ok := directAssertion(responseElement)
	if !ok {
		return nil, authentication.ErrUnauthenticated
	}
	certificateStore := dsig.MemoryX509CertificateStore{Roots: append([]*x509.Certificate(nil), p.idpSigningCerts...)}
	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	validationContext.Clock = dsig.NewFakeClockAt(now)

	verifiedResponse, err := validationContext.Validate(responseElement)
	if err == nil {
		assertionElement, ok = directAssertion(verifiedResponse)
		if !ok {
			return nil, authentication.ErrUnauthenticated
		}
	} else {
		if !errors.Is(err, dsig.ErrMissingSignature) {
			return nil, err
		}
		assertionElement, err = validationContext.Validate(assertionElement)
		if err != nil {
			return nil, err
		}
	}

	assertionXML, err := elementBytes(assertionElement)
	if err != nil {
		return nil, err
	}
	var assertion crewjamsaml.Assertion
	if err := xml.Unmarshal(assertionXML, &assertion); err != nil {
		return nil, err
	}
	return &assertion, nil
}

func directAssertion(response *etree.Element) (*etree.Element, bool) {
	var assertion *etree.Element
	for _, child := range response.ChildElements() {
		if child.NamespaceURI() != samlAssertionNamespace || child.Tag != "Assertion" {
			continue
		}
		if assertion != nil {
			return nil, false
		}
		assertion = child
	}
	return assertion, assertion != nil
}

func elementBytes(element *etree.Element) ([]byte, error) {
	namespaces := make(map[string]string)
	for _, child := range element.FindElements("//*") {
		if namespace := child.NamespaceURI(); namespace != "" {
			namespaces[child.Space] = namespace
		}
	}
	document := etree.NewDocument()
	document.SetRoot(element.Copy())
	for space, namespace := range namespaces {
		name := "xmlns"
		if space != "" {
			name += ":" + space
		}
		document.Root().CreateAttr(name, namespace)
	}
	return document.WriteToBytes()
}

func cloneAndValidateIDPMetadata(metadata *crewjamsaml.EntityDescriptor, now time.Time) (*crewjamsaml.EntityDescriptor, string, []*x509.Certificate, bool) {
	if metadata == nil || !validHTTPSString(metadata.EntityID) ||
		(!metadata.ValidUntil.IsZero() && !now.Before(metadata.ValidUntil)) {
		return nil, "", nil, false
	}
	clone := &crewjamsaml.EntityDescriptor{EntityID: metadata.EntityID, ValidUntil: metadata.ValidUntil}
	redirectLocation := ""
	var signingCertificates []*x509.Certificate
	for _, descriptor := range metadata.IDPSSODescriptors {
		clonedDescriptor := crewjamsaml.IDPSSODescriptor{
			SSODescriptor: crewjamsaml.SSODescriptor{RoleDescriptor: crewjamsaml.RoleDescriptor{
				ProtocolSupportEnumeration: descriptor.ProtocolSupportEnumeration,
			}},
		}
		for _, key := range descriptor.KeyDescriptors {
			clonedKey := crewjamsaml.KeyDescriptor{Use: key.Use}
			for _, encodedCertificate := range key.KeyInfo.X509Data.X509Certificates {
				certificateData, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encodedCertificate.Data), ""))
				if err != nil {
					return nil, "", nil, false
				}
				certificate, err := x509.ParseCertificate(certificateData)
				if err != nil || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
					return nil, "", nil, false
				}
				if key.Use == "" || key.Use == "signing" {
					signingCertificates = append(signingCertificates, certificate)
				}
				clonedKey.KeyInfo.X509Data.X509Certificates = append(
					clonedKey.KeyInfo.X509Data.X509Certificates,
					crewjamsaml.X509Certificate{Data: encodedCertificate.Data},
				)
			}
			clonedDescriptor.KeyDescriptors = append(clonedDescriptor.KeyDescriptors, clonedKey)
		}
		for _, endpoint := range descriptor.SingleSignOnServices {
			if endpoint.Binding == crewjamsaml.HTTPRedirectBinding {
				if redirectLocation != "" || !validHTTPSString(endpoint.Location) {
					return nil, "", nil, false
				}
				redirectLocation = endpoint.Location
			}
			clonedDescriptor.SingleSignOnServices = append(clonedDescriptor.SingleSignOnServices, endpoint)
		}
		clone.IDPSSODescriptors = append(clone.IDPSSODescriptors, clonedDescriptor)
	}
	if redirectLocation == "" || len(signingCertificates) == 0 {
		return nil, "", nil, false
	}
	return clone, redirectLocation, signingCertificates, true
}

func cloneSigningCredentials(key *rsa.PrivateKey, certificate *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate, bool) {
	if key == nil || certificate == nil || len(certificate.Raw) == 0 {
		return nil, nil, false
	}
	clonedKey, err := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(key))
	if err != nil {
		return nil, nil, false
	}
	clonedCertificate, err := x509.ParseCertificate(append([]byte(nil), certificate.Raw...))
	if err != nil {
		return nil, nil, false
	}
	return clonedKey, clonedCertificate, true
}

func validSPKeyPair(key *rsa.PrivateKey, certificate *x509.Certificate, now time.Time) bool {
	if key == nil || certificate == nil || key.N == nil || key.N.BitLen() < 2048 || key.Validate() != nil ||
		now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return false
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	return ok && publicKey.N.Cmp(key.N) == 0 && publicKey.E == key.E
}

func validIssueInstant(value, now time.Time, skew time.Duration) bool {
	if value.IsZero() || value.After(now.Add(skew)) {
		return false
	}
	return !value.Add(defaultRequestTTL + skew).Before(now)
}

func defaultClaimsMapper(issuer string) ClaimsMapper {
	return func(_ context.Context, claims Claims) (authentication.Principal, error) {
		return authentication.Principal{
			ID:              issuer + "|" + claims.NameID,
			Issuer:          issuer,
			Subject:         claims.NameID,
			AuthenticatedAt: claims.AuthenticatedAt,
			ExpiresAt:       claims.ExpiresAt,
			Traits:          cloneAttributes(claims.Attributes),
			Methods:         []string{"saml"},
		}, nil
	}
}

func cloneClaims(claims Claims) Claims {
	claims.Attributes = cloneAttributes(claims.Attributes)
	return claims
}

func cloneAttributes(attributes map[string][]string) map[string][]string {
	if attributes == nil {
		return nil
	}
	clone := make(map[string][]string, len(attributes))
	for name, values := range attributes {
		clone[name] = append([]string(nil), values...)
	}
	return clone
}

func sanitizeStoreError(ctx context.Context, err, fallback error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, authentication.ErrReplay) {
		return authentication.ErrReplay
	}
	if errors.Is(err, authentication.ErrInvalidCallback) {
		return authentication.ErrInvalidCallback
	}
	return fallback
}

func randomRelayState() (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validHTTPSURL(value *url.URL) bool {
	return value != nil && validHTTPSString(value.String())
}

func validHTTPSString(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == "" &&
		parsed.String() == value
}

func cloneURL(value *url.URL) *url.URL {
	clone := *value
	if value.User != nil {
		if password, ok := value.User.Password(); ok {
			clone.User = url.UserPassword(value.User.Username(), password)
		} else {
			clone.User = url.User(value.User.Username())
		}
	}
	return &clone
}

func validProtocolText(value string) bool {
	return value != "" && validProtocolValue(value)
}

func validRelayState(value string) bool {
	return value != "" && len(value) <= maxRelayStateBytes && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0
}

func validProtocolValue(value string) bool {
	return len(value) <= maxProtocolTextBytes && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0
}

func maxBase64DecodedLength() int {
	return int(^uint(0)>>1) / 4 * 3
}
