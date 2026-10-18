// Package authentication defines the protocol-neutral authentication
// contracts shared by every authenticator in this module.
//
// A transport adapter (for example package middleware) turns request data
// into a Credential; an Authenticator verifies it and returns a Principal.
// Federated logins (OIDC, OAuth2, SAML) implement FederatedProvider with a
// Begin/Complete pair instead. Chain composes authenticators, and
// ContextWithPrincipal / PrincipalFromContext carry the result through a
// request.
//
// All values are copied on the way in and out (see the Clone methods), so
// callers never share mutable state with an authenticator. Errors are the
// sentinels declared in this package, returned without wrapping detail that
// could contain credential material; test them with errors.Is.
//
// The package does not import package authorization: authentication and
// authorization are independent and can be used separately.
package authentication
