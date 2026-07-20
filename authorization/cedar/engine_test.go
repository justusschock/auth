package cedar_test

import (
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/justusschock/go-auth/authorization"
	authcedar "github.com/justusschock/go-auth/authorization/cedar"
)

const basicPolicies = `
@id("read") permit(principal, action == Action::"read", resource);
@id("blocked") forbid(principal, action, resource) when { context.blocked };
`

func TestEnginePermitsDefaultsToDenyAndHonorsForbid(t *testing.T) {
	engine := newEngine(t, staticPolicies(basicPolicies), emptyEntities{})

	permit, err := engine.Authorize(context.Background(), request("read", map[string]any{"blocked": false}))
	if err != nil {
		t.Fatal(err)
	}
	if !permit.Allowed || !slices.IsSorted(permit.Reasons) || len(permit.Errors) != 0 {
		t.Fatalf("permit decision = %#v", permit)
	}

	denied, err := engine.Authorize(context.Background(), request("write", map[string]any{"blocked": false}))
	if err != nil {
		t.Fatal(err)
	}
	if denied.Allowed || len(denied.Reasons) != 0 || len(denied.Errors) != 0 {
		t.Fatalf("default-deny decision = %#v", denied)
	}

	forbidden, err := engine.Authorize(context.Background(), request("read", map[string]any{"blocked": true}))
	if err != nil {
		t.Fatal(err)
	}
	if forbidden.Allowed || len(forbidden.Reasons) == 0 || !slices.IsSorted(forbidden.Reasons) {
		t.Fatalf("forbid decision = %#v", forbidden)
	}
}

func TestEngineUsesEntityHierarchy(t *testing.T) {
	policies := staticPolicies(`@id("folder-reader") permit(principal, action == Action::"read", resource in Folder::"shared");`)
	entities := staticEntities(`[
		{"uid":{"type":"Document","id":"doc-1"},"attrs":{},"parents":[{"type":"Folder","id":"shared"}]},
		{"uid":{"type":"Folder","id":"shared"},"attrs":{},"parents":[]}
	]`)
	engine := newEngine(t, policies, entities)
	decision, err := engine.Authorize(context.Background(), request("read", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("hierarchy decision = %#v", decision)
	}
}

func TestEngineRejectsInvalidConstructionSourcesAndEntities(t *testing.T) {
	for name, options := range map[string]authcedar.Options{
		"missing policies": {Entities: emptyEntities{}},
		"missing entities": {Policies: staticPolicies(basicPolicies)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := authcedar.New(options); !errors.Is(err, authorization.ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}

	cases := []struct {
		name     string
		policies authorization.PolicySource
		entities authorization.EntitySource
		want     error
	}{
		{"policy backend", failingPolicies{errBackendDetail}, emptyEntities{}, authorization.ErrSource},
		{"entity backend", staticPolicies(basicPolicies), failingEntities{errBackendDetail}, authorization.ErrSource},
		{"empty policy", staticPolicies(nil), emptyEntities{}, authorization.ErrInvalidSource},
		{"invalid policy", staticPolicies(`permit(`), emptyEntities{}, authorization.ErrInvalidSource},
		{"invalid entities", staticPolicies(basicPolicies), staticEntities(`{"secret":"value"}`), authorization.ErrInvalidSource},
		{"oversized policy", staticPolicies(strings.Repeat(" ", 1<<20+1)), emptyEntities{}, authorization.ErrInvalidSource},
		{"oversized entities", staticPolicies(basicPolicies), staticEntities(strings.Repeat(" ", 1<<20+1)), authorization.ErrInvalidSource},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newEngine(t, tc.policies, tc.entities)
			decision, err := engine.Authorize(context.Background(), request("read", map[string]any{"blocked": false}))
			if !errors.Is(err, tc.want) || decision.Allowed {
				t.Fatalf("Authorize() = %#v, %v; want deny and %v", decision, err, tc.want)
			}
			if strings.Contains(err.Error(), "backend secret detail") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaked source detail: %v", err)
			}
		})
	}
}

func TestEngineRejectsOversizedSourcesBeforeCopying(t *testing.T) {
	oversized := staticPolicies(strings.Repeat(" ", 1<<20+1))
	engine := newEngine(t, oversized, emptyEntities{})
	failed := newEngine(t, failingPolicies{errBackendDetail}, emptyEntities{})
	request := request("read", map[string]any{"blocked": false})
	allocations := testing.AllocsPerRun(10, func() {
		decision, err := engine.Authorize(context.Background(), request)
		if !errors.Is(err, authorization.ErrInvalidSource) || decision.Allowed {
			t.Fatalf("Authorize() = %#v, %v", decision, err)
		}
	})
	baseline := testing.AllocsPerRun(10, func() {
		_, _ = failed.Authorize(context.Background(), request)
	})
	if allocations > baseline {
		t.Fatalf("oversized source allocated %.1f times versus %.1f source-error baseline", allocations, baseline)
	}
}

func TestEngineRejectsDuplicateAndInvalidEntityUIDs(t *testing.T) {
	valid := `{"uid":{"type":"Document","id":"doc-1"},"attrs":{},"parents":[]}`
	cases := map[string]string{
		"duplicate UID":       `[` + valid + `,` + valid + `]`,
		"empty entity type":   `[{"uid":{"type":"","id":"doc-1"},"attrs":{},"parents":[]}]`,
		"invalid entity type": `[{"uid":{"type":"Bad-Type","id":"doc-1"},"attrs":{},"parents":[]}]`,
		"oversized entity ID": `[{"uid":{"type":"Document","id":"` + strings.Repeat("x", 257) + `"},"attrs":{},"parents":[]}]`,
		"invalid parent type": `[{"uid":{"type":"Document","id":"doc-1"},"attrs":{},"parents":[{"type":"Bad-Type","id":"parent"}]}]`,
		"empty parent ID":     `[{"uid":{"type":"Document","id":"doc-1"},"attrs":{},"parents":[{"type":"Folder","id":""}]}]`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			engine := newEngine(t, staticPolicies(`permit(principal, action, resource);`), staticEntities(document))
			decision, err := engine.Authorize(context.Background(), request("read", nil))
			if !errors.Is(err, authorization.ErrInvalidSource) || decision.Allowed {
				t.Fatalf("Authorize() = %#v, %v", decision, err)
			}
		})
	}
}

func TestEngineValidatesEntityIdentifiers(t *testing.T) {
	engine := newEngine(t, staticPolicies(basicPolicies), emptyEntities{})
	valid := request("read", map[string]any{"blocked": false})
	cases := []authorization.Request{
		{Principal: authorization.Entity{Type: "", ID: "alice"}, Action: valid.Action, Resource: valid.Resource},
		{Principal: valid.Principal, Action: authorization.Entity{Type: "Action", ID: strings.Repeat("a", 257)}, Resource: valid.Resource},
		{Principal: valid.Principal, Action: valid.Action, Resource: authorization.Entity{Type: "Doc\x00ument", ID: "doc-1"}},
	}
	for _, req := range cases {
		decision, err := engine.Authorize(context.Background(), req)
		if !errors.Is(err, authorization.ErrInvalidRequest) || decision.Allowed {
			t.Fatalf("Authorize(%#v) = %#v, %v", req, decision, err)
		}
	}
}

func TestEngineConvertsBoundedContextAndRejectsAmbiguity(t *testing.T) {
	policies := staticPolicies(`@id("context") permit(principal, action, resource) when { context.enabled && context.count == 7 && context.tags.contains("a") && context.nested.ok };`)
	engine := newEngine(t, policies, emptyEntities{})
	decision, err := engine.Authorize(context.Background(), request("read", map[string]any{
		"enabled": true,
		"count":   int64(7),
		"tags":    []any{"a", "b"},
		"nested":  map[string]any{"ok": true},
	}))
	if err != nil || !decision.Allowed {
		t.Fatalf("supported context = %#v, %v", decision, err)
	}

	badValues := []any{
		math.NaN(), math.Inf(1), float64(1), int(1), int32(1), uint(1), uint64(7), uint64(math.MaxUint64),
		map[int]any{1: true}, struct{ Secret string }{"x"}, new(int),
		strings.Repeat("x", 4097),
		[]any{"a", int64(1)},
		[]any{map[string]any{"one": true}, map[string]any{"two": true}},
		deepContext(18),
		manyContext(1025),
	}
	for _, value := range badValues {
		decision, err := engine.Authorize(context.Background(), request("read", map[string]any{"value": value}))
		if !errors.Is(err, authorization.ErrInvalidRequest) || decision.Allowed {
			t.Fatalf("value %T: decision=%#v err=%v", value, decision, err)
		}
	}
}

func TestEngineDeepCopiesRequestBeforeCallingEntitySource(t *testing.T) {
	contextValues := map[string]any{
		"nested":  map[string]any{"value": "original"},
		"list":    []any{map[string]any{"value": "original"}},
		"strings": []string{"original"},
	}
	engine := newEngine(t, staticPolicies(`permit(principal, action, resource);`), mutatingEntities{})
	decision, err := engine.Authorize(context.Background(), request("read", contextValues))
	if err != nil || !decision.Allowed {
		t.Fatalf("Authorize() = %#v, %v", decision, err)
	}
	if contextValues["nested"].(map[string]any)["value"] != "original" ||
		contextValues["list"].([]any)[0].(map[string]any)["value"] != "original" ||
		contextValues["strings"].([]string)[0] != "original" {
		t.Fatalf("entity source mutated caller request: %#v", contextValues)
	}
}

func TestEngineDeniesEvaluationErrorsWithDeterministicSanitizedDiagnostics(t *testing.T) {
	policies := staticPolicies(`
		@id("z-policy") permit(principal, action, resource) when { context.missing };
		@id("a-policy") permit(principal, action, resource) when { context.also_missing };
	`)
	engine := newEngine(t, policies, emptyEntities{})
	first, err := engine.Authorize(context.Background(), request("read", nil))
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Authorize(context.Background(), request("read", nil))
	if err != nil {
		t.Fatal(err)
	}
	if first.Allowed || !reflect.DeepEqual(first, second) || len(first.Errors) != 2 || !slices.IsSorted(first.Errors) {
		t.Fatalf("diagnostics = %#v / %#v", first, second)
	}
	for _, message := range first.Errors {
		if strings.Contains(message, "missing") || strings.Contains(message, "policy.cedar") || strings.Contains(message, "/") {
			t.Fatalf("diagnostic leaked evaluator details: %q", message)
		}
	}
}

func TestEngineHonorsCancellation(t *testing.T) {
	engine := newEngine(t, staticPolicies(basicPolicies), emptyEntities{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err := engine.Authorize(ctx, request("read", map[string]any{"blocked": false}))
	if !errors.Is(err, context.Canceled) || decision.Allowed {
		t.Fatalf("Authorize(canceled) = %#v, %v", decision, err)
	}
}

func newEngine(t *testing.T, policies authorization.PolicySource, entities authorization.EntitySource) *authcedar.Engine {
	t.Helper()
	engine, err := authcedar.New(authcedar.Options{Policies: policies, Entities: entities})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func request(action string, contextValues map[string]any) authorization.Request {
	return authorization.Request{
		Principal: authorization.Entity{Type: "User", ID: "alice"},
		Action:    authorization.Entity{Type: "Action", ID: action},
		Resource:  authorization.Entity{Type: "Document", ID: "doc-1"},
		Context:   contextValues,
	}
}

func deepContext(depth int) any {
	var value any = true
	for range depth {
		value = map[string]any{"next": value}
	}
	return value
}

func manyContext(count int) any {
	values := make([]any, count)
	for i := range values {
		values[i] = int64(i)
	}
	return values
}
