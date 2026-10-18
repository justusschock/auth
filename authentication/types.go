package authentication

import (
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxTraits          = 128
	maxTraitNameBytes  = 256
	maxTraitValues     = 128
	maxTraitValueBytes = 4096
	maxMethods         = 64
	maxMethodBytes     = 256
)

// Principal is a protocol-neutral authenticated identity. ID is unique across
// issuers (authenticators in this module use "<issuer>|<subject>").
// AuthenticatedAt and ExpiresAt are UTC and bound the principal's validity;
// Traits carries bounded claim data and Methods the authentication methods
// used, such as "jwt", "oidc", "saml" or "apitoken".
type Principal struct {
	ID              string
	Issuer          string
	Subject         string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Traits          map[string][]string
	Methods         []string
}

// Clone returns an independently owned principal. Authentication methods are
// set-like and are returned in stable lexical order.
func (p Principal) Clone() Principal {
	clone := p
	if p.Traits != nil {
		clone.Traits = make(map[string][]string, len(p.Traits))
		for name, values := range p.Traits {
			clone.Traits[name] = slices.Clone(values)
		}
	}
	clone.Methods = slices.Clone(p.Methods)
	slices.Sort(clone.Methods)
	return clone
}

// Well-known Credential kinds produced by transport adapters.
const (
	// CredentialKindJWT is a JWS compact serialization.
	CredentialKindJWT = "jwt"
	// CredentialKindBearer is an opaque bearer token that is not a JWT.
	CredentialKindBearer = "bearer"
)

// Credential is credential material presented to an Authenticator. Callers
// should discard it as soon as authentication completes.
type Credential struct {
	Kind       string
	Token      []byte
	Attributes map[string]string
}

// Clone returns independently owned credential data.
func (c Credential) Clone() Credential {
	clone := c
	clone.Token = slices.Clone(c.Token)
	if c.Attributes != nil {
		clone.Attributes = make(map[string]string, len(c.Attributes))
		for name, value := range c.Attributes {
			clone.Attributes[name] = value
		}
	}
	return clone
}

// ValidatePrincipal checks identity, lifetime, and bounded claim data at now.
// ID, Issuer and Subject must be non-empty UTF-8 without NUL; both times must
// be non-zero UTC with AuthenticatedAt <= now < ExpiresAt; traits and methods
// are bounded in count and size and methods are unique. It returns
// ErrExpired when only the lifetime has ended and ErrInvalidPrincipal
// otherwise.
func ValidatePrincipal(principal Principal, now time.Time) error {
	if invalidText(principal.ID) || invalidText(principal.Issuer) || invalidText(principal.Subject) {
		return ErrInvalidPrincipal
	}
	if principal.AuthenticatedAt.IsZero() || principal.ExpiresAt.IsZero() || now.IsZero() {
		return ErrInvalidPrincipal
	}
	if principal.AuthenticatedAt.Location() != time.UTC || principal.ExpiresAt.Location() != time.UTC {
		return ErrInvalidPrincipal
	}
	if !principal.AuthenticatedAt.Before(principal.ExpiresAt) || principal.AuthenticatedAt.After(now) {
		return ErrInvalidPrincipal
	}
	if !now.Before(principal.ExpiresAt) {
		return ErrExpired
	}
	if len(principal.Traits) > maxTraits {
		return ErrInvalidPrincipal
	}
	for name, values := range principal.Traits {
		if invalidBoundedText(name, maxTraitNameBytes) || len(values) > maxTraitValues {
			return ErrInvalidPrincipal
		}
		for _, value := range values {
			if !validBoundedText(value, maxTraitValueBytes) {
				return ErrInvalidPrincipal
			}
		}
	}
	if len(principal.Methods) > maxMethods {
		return ErrInvalidPrincipal
	}
	methods := slices.Clone(principal.Methods)
	for _, method := range methods {
		if invalidBoundedText(method, maxMethodBytes) {
			return ErrInvalidPrincipal
		}
	}
	slices.Sort(methods)
	for index := 1; index < len(methods); index++ {
		if methods[index] == methods[index-1] {
			return ErrInvalidPrincipal
		}
	}
	return nil
}

func invalidText(value string) bool {
	return value == "" || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0
}

func invalidBoundedText(value string, limit int) bool {
	return invalidText(value) || len(value) > limit
}

func validBoundedText(value string, limit int) bool {
	return utf8.ValidString(value) && strings.IndexByte(value, 0) < 0 && len(value) <= limit
}
