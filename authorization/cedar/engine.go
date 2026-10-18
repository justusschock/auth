// Package cedar implements authorization.Authorizer with the Cedar policy
// language (github.com/cedar-policy/cedar-go).
//
// For every request the Engine reads the policy text and the request-scoped
// entity JSON from its sources, so policy changes take effect immediately and
// no state is cached. Inputs are bounded (1 MiB of policies, 1 MiB of
// entities, entity identifiers, context depth and size) and validated;
// duplicate or invalid entity UIDs, mixed-type context sets and unsupported
// context value types are rejected. Evaluation is default-deny: a decision
// is allowed only when a permit policy matches, no forbid policy matches and
// no policy failed to evaluate. Diagnostic reasons and errors list policy IDs
// only, in deterministic order.
package cedar

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	cedarsdk "github.com/cedar-policy/cedar-go"
	"github.com/justusschock/go-auth/authorization"
)

const (
	maxPolicyBytes  = 1 << 20
	maxEntityBytes  = 1 << 20
	maxEntityType   = 128
	maxEntityID     = 256
	maxContextKey   = 128
	maxStringBytes  = 4096
	maxContextDepth = 16
	maxContextItems = 1024
)

// Options configures an Engine.
type Options struct {
	Policies authorization.PolicySource
	Entities authorization.EntitySource
}

// Engine evaluates Cedar policies against request-scoped entities. It is safe
// for concurrent use when its sources are.
type Engine struct {
	policies authorization.PolicySource
	entities authorization.EntitySource
}

// New validates the required policy and entity sources.
func New(options Options) (*Engine, error) {
	if options.Policies == nil || options.Entities == nil {
		return nil, authorization.ErrInvalidConfiguration
	}
	return &Engine{policies: options.Policies, entities: options.Entities}, nil
}

// Authorize evaluates one request. Every ambiguous or invalid input fails
// closed with an error from package authorization. Request.Context accepts
// bool, string, int64, []string, []any and map[string]any values.
func (e *Engine) Authorize(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	principal, err := entityUID(request.Principal)
	if err != nil {
		return authorization.Decision{}, err
	}
	action, err := entityUID(request.Action)
	if err != nil {
		return authorization.Decision{}, err
	}
	resource, err := entityUID(request.Resource)
	if err != nil {
		return authorization.Decision{}, err
	}
	contextRecord, err := requestContext(request.Context)
	if err != nil {
		return authorization.Decision{}, err
	}

	policyBytes, err := e.policies.Policies(ctx)
	if err != nil {
		return authorization.Decision{}, sourceError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if len(policyBytes) > maxPolicyBytes {
		return authorization.Decision{}, authorization.ErrInvalidSource
	}
	policyBytes = append([]byte(nil), policyBytes...)
	if len(bytes.TrimSpace(policyBytes)) == 0 {
		return authorization.Decision{}, authorization.ErrInvalidSource
	}
	policies, err := cedarsdk.NewPolicySetFromBytes("policy.cedar", policyBytes)
	if err != nil {
		return authorization.Decision{}, authorization.ErrInvalidSource
	}

	entityBytes, err := e.entities.Entities(ctx, cloneRequest(request))
	if err != nil {
		return authorization.Decision{}, sourceError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if len(entityBytes) > maxEntityBytes {
		return authorization.Decision{}, authorization.ErrInvalidSource
	}
	entityBytes = append([]byte(nil), entityBytes...)
	if len(bytes.TrimSpace(entityBytes)) == 0 {
		return authorization.Decision{}, authorization.ErrInvalidSource
	}
	entities, err := parseEntities(entityBytes)
	if err != nil {
		return authorization.Decision{}, authorization.ErrInvalidSource
	}

	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	decision, diagnostic := cedarsdk.Authorize(policies, entities, cedarsdk.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   contextRecord,
	})
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	result := authorization.Decision{
		Allowed: decision == cedarsdk.Allow,
		Reasons: diagnosticReasons(diagnostic),
		Errors:  diagnosticErrors(diagnostic),
	}
	if len(result.Errors) != 0 {
		result.Allowed = false
	}
	return result, nil
}

func entityUID(entity authorization.Entity) (cedarsdk.EntityUID, error) {
	if !validEntityType(entity.Type) || !validText(entity.ID, maxEntityID) {
		return cedarsdk.EntityUID{}, authorization.ErrInvalidRequest
	}
	return cedarsdk.NewEntityUID(cedarsdk.EntityType(entity.Type), cedarsdk.String(entity.ID)), nil
}

func validEntityType(value string) bool {
	if !validText(value, maxEntityType) {
		return false
	}
	for _, component := range strings.Split(value, "::") {
		if component == "" || !isIdentStart(component[0]) {
			return false
		}
		for i := 1; i < len(component); i++ {
			if !isIdentContinue(component[i]) {
				return false
			}
		}
	}
	return true
}

func isIdentStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isIdentContinue(value byte) bool {
	return isIdentStart(value) || value >= '0' && value <= '9'
}

func requestContext(values map[string]any) (cedarsdk.Record, error) {
	if values == nil {
		return cedarsdk.NewRecord(cedarsdk.RecordMap{}), nil
	}
	remaining := maxContextItems
	value, _, err := contextValue(values, 0, &remaining)
	if err != nil {
		return cedarsdk.Record{}, authorization.ErrInvalidRequest
	}
	record, ok := value.(cedarsdk.Record)
	if !ok {
		return cedarsdk.Record{}, authorization.ErrInvalidRequest
	}
	return record, nil
}

func contextValue(value any, depth int, remaining *int) (cedarsdk.Value, string, error) {
	if depth > maxContextDepth || *remaining <= 0 {
		return nil, "", authorization.ErrInvalidRequest
	}
	*remaining--
	switch value := value.(type) {
	case bool:
		return cedarsdk.Boolean(value), "bool", nil
	case string:
		if !validText(value, maxStringBytes) {
			return nil, "", authorization.ErrInvalidRequest
		}
		return cedarsdk.String(value), "string", nil
	case int64:
		return cedarsdk.Long(value), "long", nil
	case []any:
		converted := make([]cedarsdk.Value, len(value))
		elementKind := ""
		for i := range value {
			item, kind, err := contextValue(value[i], depth+1, remaining)
			if err != nil {
				return nil, "", err
			}
			if i == 0 {
				elementKind = kind
			} else if kind != elementKind {
				return nil, "", authorization.ErrInvalidRequest
			}
			converted[i] = item
		}
		return cedarsdk.NewSet(converted...), "set(" + elementKind + ")", nil
	case []string:
		converted := make([]cedarsdk.Value, len(value))
		for i := range value {
			item, _, err := contextValue(value[i], depth+1, remaining)
			if err != nil {
				return nil, "", err
			}
			converted[i] = item
		}
		return cedarsdk.NewSet(converted...), "set(string)", nil
	case map[string]any:
		record := make(cedarsdk.RecordMap, len(value))
		keys := make([]string, 0, len(value))
		for key := range value {
			if !validContextKey(key) {
				return nil, "", authorization.ErrInvalidRequest
			}
			keys = append(keys, key)
		}
		slices.Sort(keys)
		var shape strings.Builder
		shape.WriteString("record{")
		for _, key := range keys {
			converted, kind, err := contextValue(value[key], depth+1, remaining)
			if err != nil {
				return nil, "", err
			}
			record[cedarsdk.String(key)] = converted
			shape.WriteString(strconv.Itoa(len(key)))
			shape.WriteByte(':')
			shape.WriteString(key)
			shape.WriteByte('=')
			shape.WriteString(kind)
			shape.WriteByte(';')
		}
		shape.WriteByte('}')
		return cedarsdk.NewRecord(record), shape.String(), nil
	default:
		return nil, "", authorization.ErrInvalidRequest
	}
}

func validContextKey(value string) bool {
	return len(value) <= maxContextKey && validEntityType(value)
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func sourceError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return authorization.ErrSource
}

func diagnosticReasons(diagnostic cedarsdk.Diagnostic) []string {
	reasons := make([]string, 0, len(diagnostic.Reasons))
	for _, reason := range diagnostic.Reasons {
		reasons = append(reasons, string(reason.PolicyID))
	}
	slices.Sort(reasons)
	return compact(reasons)
}

func diagnosticErrors(diagnostic cedarsdk.Diagnostic) []string {
	errorsOut := make([]string, 0, len(diagnostic.Errors))
	for _, diagnosticError := range diagnostic.Errors {
		policyID := string(diagnosticError.PolicyID)
		if policyID == "" {
			errorsOut = append(errorsOut, "policy evaluation failed")
		} else {
			errorsOut = append(errorsOut, "policy "+policyID+" evaluation failed")
		}
	}
	slices.Sort(errorsOut)
	return compact(errorsOut)
}

func compact(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func cloneRequest(request authorization.Request) authorization.Request {
	clone := request
	clone.Context = cloneMap(request.Context)
	return clone
}

func cloneMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	clone := make(map[string]any, len(values))
	for key, value := range values {
		clone[key] = cloneValue(value)
	}
	return clone
}

func cloneValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return cloneMap(value)
	case []any:
		clone := make([]any, len(value))
		for i := range value {
			clone[i] = cloneValue(value[i])
		}
		return clone
	case []string:
		return append([]string(nil), value...)
	default:
		return value
	}
}

func parseEntities(document []byte) (cedarsdk.EntityMap, error) {
	var values []cedarsdk.Entity
	if err := json.Unmarshal(document, &values); err != nil {
		return nil, err
	}
	entities := make(cedarsdk.EntityMap, len(values))
	for _, entity := range values {
		if !validUID(entity.UID) {
			return nil, authorization.ErrInvalidSource
		}
		for _, parent := range entity.Parents.Slice() {
			if !validUID(parent) {
				return nil, authorization.ErrInvalidSource
			}
		}
		if _, exists := entities[entity.UID]; exists {
			return nil, authorization.ErrInvalidSource
		}
		entities[entity.UID] = entity
	}
	return entities, nil
}

func validUID(uid cedarsdk.EntityUID) bool {
	return validEntityType(string(uid.Type)) && validText(string(uid.ID), maxEntityID)
}

var _ authorization.Authorizer = (*Engine)(nil)
