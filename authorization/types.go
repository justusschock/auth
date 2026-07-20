// Package authorization defines protocol-neutral authorization contracts.
package authorization

import "context"

// Entity identifies one Cedar principal, action, or resource.
type Entity struct {
	Type string
	ID   string
}

// Request contains only authorization inputs. It is independent of authentication.
type Request struct {
	Principal Entity
	Action    Entity
	Resource  Entity
	Context   map[string]any
}

// Decision is a deterministic authorization result.
type Decision struct {
	Allowed bool
	Reasons []string
	Errors  []string
}

// Authorizer evaluates an authorization request.
type Authorizer interface {
	Authorize(context.Context, Request) (Decision, error)
}

// PolicySource supplies Cedar policy text.
type PolicySource interface {
	Policies(context.Context) ([]byte, error)
}

// EntitySource supplies Cedar entity JSON for one request.
type EntitySource interface {
	Entities(context.Context, Request) ([]byte, error)
}
