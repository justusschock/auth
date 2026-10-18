package authentication

import "errors"

// Sentinel errors returned by this module's authenticators. They never carry
// credential material.
var (
	// ErrInvalidPrincipal reports a principal that fails ValidatePrincipal's
	// identity or bound checks.
	ErrInvalidPrincipal = errors.New("authentication: invalid principal")
	// ErrInvalidCredential reports malformed credentials or invalid
	// configuration passed to a constructor.
	ErrInvalidCredential = errors.New("authentication: invalid credential")
	// ErrUnauthenticated reports a credential that was rejected. It is the
	// generic failure: authenticators use it instead of revealing why.
	ErrUnauthenticated = errors.New("authentication: unauthenticated")
	// ErrExpired reports a credential, link, state or session whose lifetime
	// has ended.
	ErrExpired = errors.New("authentication: expired")
	// ErrReplay reports one-time state (callback state, magic link, refresh
	// token) that was unknown or already used, or a duplicate store key.
	ErrReplay = errors.New("authentication: replay detected")
	// ErrInvalidCallback reports a malformed federated callback or an
	// unregistered redirect URI.
	ErrInvalidCallback = errors.New("authentication: invalid callback")
	// ErrProviderNotFound reports that no provider matches a name or domain.
	ErrProviderNotFound = errors.New("authentication: provider not found")

	// ErrUnsupportedCredential reports that an Authenticator does not handle
	// the presented credential kind or format. Chain uses it to try the next
	// Authenticator; it is still an authentication failure for callers.
	ErrUnsupportedCredential = errors.New("authentication: unsupported credential")
)
