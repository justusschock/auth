package authentication

import (
	"context"
	"errors"
	"slices"
)

type principalContextKey struct{}

// ContextWithPrincipal returns a child context carrying an independently owned
// copy of principal.
func ContextWithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal.Clone())
}

// PrincipalFromContext returns an independently owned copy of the principal
// stored by ContextWithPrincipal.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok {
		return Principal{}, false
	}
	return principal.Clone(), true
}

type chain []Authenticator

// Chain returns an Authenticator that tries authenticators in order. The first
// result that is not ErrUnsupportedCredential wins, whether it succeeds or
// fails, so a recognized but invalid credential is never retried elsewhere.
// When no authenticator recognizes the credential, Chain returns
// ErrUnsupportedCredential. Each authenticator receives its own copy of the
// credential. A nil authenticator fails closed with ErrUnauthenticated.
//
// Authenticators that reject foreign credential kinds with an error other than
// ErrUnsupportedCredential (for example jwt.Verifier) should be placed last.
func Chain(authenticators ...Authenticator) Authenticator {
	return chain(slices.Clone(authenticators))
}

func (c chain) Authenticate(ctx context.Context, credential Credential) (Principal, error) {
	for _, authenticator := range c {
		if err := ctx.Err(); err != nil {
			return Principal{}, err
		}
		if authenticator == nil {
			return Principal{}, ErrUnauthenticated
		}
		principal, err := authenticator.Authenticate(ctx, credential.Clone())
		if errors.Is(err, ErrUnsupportedCredential) {
			continue
		}
		if err != nil {
			return Principal{}, err
		}
		return principal, nil
	}
	return Principal{}, ErrUnsupportedCredential
}
