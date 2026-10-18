// Package authorization defines protocol-neutral authorization contracts: a
// Request of principal, action and resource entities plus context, an
// Authorizer that returns a Decision, and the PolicySource and EntitySource
// interfaces an implementation reads from. Package cedar provides the Cedar
// implementation.
//
// The package does not import package authentication; callers map an
// authenticated principal to a request entity themselves.
package authorization

import "context"

// Principal identifies who makes a request, for example the Cedar entity
// User::"alice": Type "User", ID "alice". Type is a Cedar entity type such as
// "User" or "App::User"; ID is any non-empty UTF-8 string.
type Principal struct {
	Type string
	ID   string
}

// Action identifies what the principal wants to do, for example "read". Its
// Cedar entity type is always Action, so Action{ID: "read"} is the Cedar
// entity Action::"read".
type Action struct {
	ID string
}

// Resource identifies what the action applies to, for example
// Document::"report": Type "Document", ID "report".
type Resource struct {
	Type string
	ID   string
}

// Request contains only authorization inputs. It is independent of authentication.
type Request struct {
	Principal Principal
	Action    Action
	Resource  Resource
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
