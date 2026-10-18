package cedar_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	cedarsdk "github.com/cedar-policy/cedar-go"
	"github.com/justusschock/auth/authorization"
	authcedar "github.com/justusschock/auth/authorization/cedar"
)

var (
	alice     = &authorization.Principal{Type: "User", ID: "alice"}
	read      = &authorization.Action{ID: "read"}
	report    = authorization.Resource{Type: "Document", ID: "report"}
	documents = authorization.Resource{Type: "Document"}
)

// FR-AUTH-28
func TestPoliciesRenderStructuredScopes(t *testing.T) {
	tests := []struct {
		name   string
		policy authcedar.Policy
		want   string
	}{
		{"resource type only", authcedar.Policy{Effect: authcedar.Permit, Resource: documents},
			`permit(principal, action, resource is Document);`},
		{"forbid one resource", authcedar.Policy{Effect: authcedar.Forbid, Resource: report},
			`forbid(principal, action, resource == Document::"report");`},
		{"principal, action and resource type", authcedar.Policy{Effect: authcedar.Permit, Principal: alice, Action: read, Resource: documents},
			`permit(principal == User::"alice", action == Action::"read", resource is Document);`},
		{"every scope exact", authcedar.Policy{Effect: authcedar.Forbid, Principal: alice, Action: read, Resource: report},
			`forbid(principal == User::"alice", action == Action::"read", resource == Document::"report");`},
		{"namespaced types and escaped IDs", authcedar.Policy{
			Effect:    authcedar.Permit,
			Principal: &authorization.Principal{Type: "App::User", ID: "a\"lice\\\n"},
			Action:    &authorization.Action{ID: `re"ad`},
			Resource:  authorization.Resource{Type: "App::Document"},
		}, `permit(principal == App::User::"a\"lice\\\n", action == Action::"re\"ad", resource is App::Document);`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := authcedar.Policies{test.policy}.Policies(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if normalizeCedar(t, got) != normalizeCedar(t, []byte(test.want)) {
				t.Fatalf("rendered %q, want the policy %q", got, test.want)
			}
		})
	}

	got, err := authcedar.Policies{
		{Effect: authcedar.Permit, Action: read, Resource: documents},
		{Effect: authcedar.Forbid, Principal: alice, Resource: report},
	}.Policies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := `permit(principal, action == Action::"read", resource is Document);
forbid(principal == User::"alice", action, resource == Document::"report");`
	if normalizeCedar(t, got) != normalizeCedar(t, []byte(want)) {
		t.Fatalf("rendered %q, want the policies %q in order", got, want)
	}
}

// FR-AUTH-28
func TestPoliciesRejectInvalidPolicies(t *testing.T) {
	permit := func(principal *authorization.Principal, action *authorization.Action, resource authorization.Resource) authcedar.Policies {
		return authcedar.Policies{{Effect: authcedar.Permit, Principal: principal, Action: action, Resource: resource}}
	}
	tests := map[string]authcedar.Policies{
		"nil":                      nil,
		"empty":                    {},
		"zero effect":              {{Principal: alice, Resource: documents}},
		"unknown effect":           {{Effect: authcedar.Forbid + 1, Resource: documents}},
		"missing resource":         permit(alice, read, authorization.Resource{}),
		"resource ID without type": permit(alice, read, authorization.Resource{ID: "report"}),
		"quoted resource type":     permit(nil, nil, authorization.Resource{Type: `Document::"x"`}),
		"trailing resource type":   permit(nil, nil, authorization.Resource{Type: "Document::"}),
		"digit resource type":      permit(nil, nil, authorization.Resource{Type: "1Document"}),
		"empty principal type":     permit(&authorization.Principal{ID: "alice"}, nil, documents),
		"empty principal ID":       permit(&authorization.Principal{Type: "User"}, nil, documents),
		"NUL in principal ID":      permit(&authorization.Principal{Type: "User", ID: "al\x00ice"}, nil, documents),
		"invalid UTF-8 ID":         permit(nil, nil, authorization.Resource{Type: "Document", ID: "\xff"}),
		"empty action ID":          permit(nil, &authorization.Action{}, documents),
		"oversized action ID":      permit(nil, &authorization.Action{ID: strings.Repeat("a", 257)}, documents),
		"one invalid of two":       append(permit(nil, nil, documents), permit(nil, nil, authorization.Resource{})...),
	}
	for name, policies := range tests {
		t.Run(name, func(t *testing.T) {
			text, err := policies.Policies(context.Background())
			if !errors.Is(err, authorization.ErrInvalidSource) || text != nil {
				t.Fatalf("Policies() = %q, %v; want ErrInvalidSource", text, err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (authcedar.Policies{{Effect: authcedar.Permit, Resource: documents}}).Policies(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Policies() error = %v", err)
	}
}

// FR-AUTH-28
func TestEngineEvaluatesStructuredPolicies(t *testing.T) {
	// The injected ID must stay one quoted ID; it must not add a policy that
	// permits everything.
	injected := &authorization.Principal{Type: "User", ID: `x", action, resource is Document); permit(principal, action, resource); //`}
	engine := newEngine(t, authcedar.Policies{
		{Effect: authcedar.Permit, Principal: alice, Action: read, Resource: documents},
		{Effect: authcedar.Forbid, Resource: authorization.Resource{Type: "Document", ID: "secret"}},
		{Effect: authcedar.Permit, Principal: injected, Resource: documents},
	}, emptyEntities{})

	tests := []struct {
		principal, action string
		resource          authorization.Resource
		allowed           bool
	}{
		{"alice", "read", report, true},
		{"alice", "delete", report, false},
		{"bob", "read", report, false},
		{"alice", "read", authorization.Resource{Type: "Document", ID: "secret"}, false},
		{"alice", "read", authorization.Resource{Type: "Folder", ID: "report"}, false},
	}
	for _, test := range tests {
		decision, err := engine.Authorize(context.Background(), authorization.Request{
			Principal: authorization.Principal{Type: "User", ID: test.principal},
			Action:    authorization.Action{ID: test.action},
			Resource:  test.resource,
		})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed != test.allowed {
			t.Fatalf("%s %s %v: allowed = %v, want %v", test.principal, test.action, test.resource, decision.Allowed, test.allowed)
		}
	}

	invalid := newEngine(t, authcedar.Policies{{Effect: authcedar.Permit, Principal: alice}}, emptyEntities{})
	decision, err := invalid.Authorize(context.Background(), request("read", nil))
	if !errors.Is(err, authorization.ErrSource) || decision.Allowed {
		t.Fatalf("policy without resource: %#v, %v; want ErrSource", decision, err)
	}
}

// normalizeCedar parses Cedar text and prints it in cedar-go's canonical
// form, so tests compare policies rather than whitespace.
func normalizeCedar(t *testing.T, text []byte) string {
	t.Helper()
	policies, err := cedarsdk.NewPolicyListFromBytes("test.cedar", text)
	if err != nil {
		t.Fatalf("parse %q: %v", text, err)
	}
	var out strings.Builder
	for _, policy := range policies {
		out.Write(policy.MarshalCedar())
		out.WriteByte('\n')
	}
	return out.String()
}
