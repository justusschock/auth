package authentication

import "errors"

var (
	ErrInvalidPrincipal  = errors.New("authentication: invalid principal")
	ErrInvalidCredential = errors.New("authentication: invalid credential")
	ErrUnauthenticated   = errors.New("authentication: unauthenticated")
	ErrExpired           = errors.New("authentication: expired")
	ErrReplay            = errors.New("authentication: replay detected")
	ErrInvalidCallback   = errors.New("authentication: invalid callback")
	ErrProviderNotFound  = errors.New("authentication: provider not found")

	// ErrUnsupportedCredential reports that an Authenticator does not handle
	// the presented credential kind or format. Chain uses it to try the next
	// Authenticator; it is still an authentication failure for callers.
	ErrUnsupportedCredential = errors.New("authentication: unsupported credential")
)
