package authentication

import (
	"context"
	"net/url"
	"slices"
	"time"
)

// Authenticator validates one credential and returns its principal.
type Authenticator interface {
	Authenticate(context.Context, Credential) (Principal, error)
}

// BeginRequest describes the caller-controlled inputs to a federated flow.
type BeginRequest struct {
	Provider    string
	RedirectURI string
	Scopes      []string
	LoginHint   string
}

// Clone returns an independently owned request.
func (r BeginRequest) Clone() BeginRequest {
	clone := r
	clone.Scopes = slices.Clone(r.Scopes)
	return clone
}

// Redirect describes a provider redirect and its opaque callback state.
type Redirect struct {
	URL       *url.URL
	StateID   string
	ExpiresAt time.Time
}

// Clone returns an independently owned redirect.
func (r Redirect) Clone() Redirect {
	clone := r
	if r.URL != nil {
		clonedURL := *r.URL
		if r.URL.User != nil {
			if password, ok := r.URL.User.Password(); ok {
				clonedURL.User = url.UserPassword(r.URL.User.Username(), password)
			} else {
				clonedURL.User = url.User(r.URL.User.Username())
			}
		}
		clone.URL = &clonedURL
	}
	return clone
}

// Callback contains the mutually exclusive protocol callback values.
type Callback struct {
	StateID      string
	Code         string
	SAMLResponse string
	RelayState   string
}

// FederatedProvider starts and completes a federated login flow.
type FederatedProvider interface {
	Name() string
	Begin(context.Context, BeginRequest) (Redirect, error)
	Complete(context.Context, Callback) (Principal, error)
}
