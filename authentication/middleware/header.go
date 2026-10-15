// Package middleware adapts authentication.Authenticator to transports. It
// depends only on the standard library and the authentication contracts so
// that it can be imported without pulling in protocol implementations.
package middleware

import (
	"strings"

	"github.com/justusschock/go-auth/authentication"
)

// MaxAuthorizationBytes bounds Authorization values accepted by
// CredentialFromAuthorizationHeader.
const MaxAuthorizationBytes = 16 << 10

// Credential attribute names and values set by this package.
const (
	// SourceAttribute names the transport location the credential came from.
	SourceAttribute = "source"
	// SourceAuthorization marks credentials from an Authorization value.
	SourceAuthorization = "authorization"
	// SourceCookie marks credentials from a cookie.
	SourceCookie = "cookie"
)

// CredentialFromAuthorizationHeader parses an RFC 6750 "Bearer" Authorization
// value, as used by HTTP headers and gRPC "authorization" metadata. Tokens in
// JWS compact form are returned with Kind authentication.CredentialKindJWT;
// all other tokens with authentication.CredentialKindBearer. The scheme is
// case-insensitive and the token must be an RFC 6750 b64token.
//
// It returns authentication.ErrUnauthenticated for an empty value,
// authentication.ErrUnsupportedCredential for another scheme, and
// authentication.ErrInvalidCredential for a malformed bearer value. Errors
// never contain the value.
func CredentialFromAuthorizationHeader(value string) (authentication.Credential, error) {
	if value == "" {
		return authentication.Credential{}, authentication.ErrUnauthenticated
	}
	if len(value) > MaxAuthorizationBytes {
		return authentication.Credential{}, authentication.ErrInvalidCredential
	}
	scheme, rest, found := strings.Cut(value, " ")
	if !strings.EqualFold(scheme, "bearer") {
		if !validHTTPToken(scheme) {
			return authentication.Credential{}, authentication.ErrInvalidCredential
		}
		return authentication.Credential{}, authentication.ErrUnsupportedCredential
	}
	if !found {
		return authentication.Credential{}, authentication.ErrInvalidCredential
	}
	token := strings.TrimLeft(rest, " ")
	if !validB64Token(token) {
		return authentication.Credential{}, authentication.ErrInvalidCredential
	}
	kind := authentication.CredentialKindBearer
	if isJWS(token) {
		kind = authentication.CredentialKindJWT
	}
	return authentication.Credential{
		Kind:       kind,
		Token:      []byte(token),
		Attributes: map[string]string{SourceAttribute: SourceAuthorization},
	}, nil
}

// validHTTPToken reports whether scheme is an RFC 7230 token.
func validHTTPToken(scheme string) bool {
	if scheme == "" {
		return false
	}
	for index := range len(scheme) {
		c := scheme[index]
		if isAlnum(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// validB64Token implements 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
func validB64Token(token string) bool {
	end := len(strings.TrimRight(token, "="))
	if end == 0 {
		return false
	}
	for index := range end {
		c := token[index]
		if isAlnum(c) || strings.IndexByte("-._~+/", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// isJWS reports whether token has the JWS compact shape
// base64url.base64url.base64url with non-empty header and payload.
func isJWS(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for index := range len(part) {
			c := part[index]
			if !isAlnum(c) && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
