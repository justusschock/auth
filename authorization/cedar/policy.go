package cedar

import (
	"bytes"
	"context"

	cedarsdk "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/ast"
	"github.com/justusschock/auth/authorization"
)

// Effect is what a matching Policy does with a request.
type Effect int

const (
	// Permit allows a matching request unless a Forbid policy also matches.
	Permit Effect = iota + 1
	// Forbid denies a matching request regardless of any Permit policy.
	Forbid
)

// Policy is a Cedar policy whose scope is built from the same values as an
// authorization.Request.
//
//   - Principal: nil matches any principal; a value matches exactly that
//     principal.
//   - Action: nil matches any action; a value matches exactly that action.
//   - Resource is required and must have a Type. An empty ID matches every
//     resource of that type; a non-empty ID matches exactly that resource.
//
// For example,
//
//	Policy{
//		Effect:    Permit,
//		Principal: &authorization.Principal{Type: "User", ID: "alice"},
//		Action:    &authorization.Action{ID: "read"},
//		Resource:  authorization.Resource{Type: "Document"},
//	}
//
// is the Cedar policy
//
//	permit(principal == User::"alice", action == Action::"read", resource is Document);
//
// Policies with conditions or hierarchy scopes are written as Cedar text and
// supplied through another authorization.PolicySource.
type Policy struct {
	Effect    Effect
	Principal *authorization.Principal
	Action    *authorization.Action
	Resource  authorization.Resource
}

// Policies is an authorization.PolicySource that renders its policies as
// Cedar text on every call. Entity types and IDs are validated with the
// rules Engine applies to requests, and IDs are always quoted and escaped,
// so policies may be built from untrusted IDs. Policies returns
// authorization.ErrInvalidSource for an empty list, an unknown Effect, a
// missing resource type or an invalid entity; an Engine reading it then
// fails closed with authorization.ErrSource. Policies is safe for concurrent
// use if the policies and the entities they point to are not modified.
type Policies []Policy

// Policies renders the policies as Cedar text.
func (p Policies) Policies(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, authorization.ErrInvalidSource
	}
	rendered := make([][]byte, len(p))
	for i, policy := range p {
		text, err := policy.cedar()
		if err != nil {
			return nil, err
		}
		rendered[i] = text
	}
	return bytes.Join(rendered, []byte("\n\n")), nil
}

func (p Policy) cedar() ([]byte, error) {
	var node *ast.Policy
	switch p.Effect {
	case Permit:
		node = ast.Permit()
	case Forbid:
		node = ast.Forbid()
	default:
		return nil, authorization.ErrInvalidSource
	}
	if p.Principal != nil {
		uid, err := policyEntityUID(p.Principal.Type, p.Principal.ID)
		if err != nil {
			return nil, err
		}
		node = node.PrincipalEq(uid)
	}
	if p.Action != nil {
		uid, err := policyEntityUID(actionType, p.Action.ID)
		if err != nil {
			return nil, err
		}
		node = node.ActionEq(uid)
	}
	if p.Resource.ID == "" {
		if !validEntityType(p.Resource.Type) {
			return nil, authorization.ErrInvalidSource
		}
		node = node.ResourceIs(cedarsdk.EntityType(p.Resource.Type))
	} else {
		uid, err := policyEntityUID(p.Resource.Type, p.Resource.ID)
		if err != nil {
			return nil, err
		}
		node = node.ResourceEq(uid)
	}
	return node.MarshalCedar(), nil
}

func policyEntityUID(entityType, id string) (cedarsdk.EntityUID, error) {
	uid, err := entityUID(entityType, id)
	if err != nil {
		return cedarsdk.EntityUID{}, authorization.ErrInvalidSource
	}
	return uid, nil
}

var _ authorization.PolicySource = Policies(nil)
