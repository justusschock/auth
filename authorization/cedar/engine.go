// Package cedar evaluates independent authorization requests with Cedar.
package cedar

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"slices"
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

// Engine evaluates Cedar policies against request-scoped entities.
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

// Authorize evaluates one request. Every ambiguous or invalid input fails closed.
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
	policyBytes = append([]byte(nil), policyBytes...)
	if len(policyBytes) > maxPolicyBytes || len(bytes.TrimSpace(policyBytes)) == 0 {
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
	entityBytes = append([]byte(nil), entityBytes...)
	if len(entityBytes) > maxEntityBytes || len(bytes.TrimSpace(entityBytes)) == 0 {
		return authorization.Decision{}, authorization.ErrInvalidSource
	}
	var entities cedarsdk.EntityMap
	if err := json.Unmarshal(entityBytes, &entities); err != nil {
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
	value, err := contextValue(values, 0, &remaining)
	if err != nil {
		return cedarsdk.Record{}, authorization.ErrInvalidRequest
	}
	record, ok := value.(cedarsdk.Record)
	if !ok {
		return cedarsdk.Record{}, authorization.ErrInvalidRequest
	}
	return record, nil
}

func contextValue(value any, depth int, remaining *int) (cedarsdk.Value, error) {
	if depth > maxContextDepth || *remaining <= 0 {
		return nil, authorization.ErrInvalidRequest
	}
	*remaining--
	switch value := value.(type) {
	case bool:
		return cedarsdk.Boolean(value), nil
	case string:
		if !validText(value, maxStringBytes) {
			return nil, authorization.ErrInvalidRequest
		}
		return cedarsdk.String(value), nil
	case int:
		return cedarsdk.Long(value), nil
	case int8:
		return cedarsdk.Long(value), nil
	case int16:
		return cedarsdk.Long(value), nil
	case int32:
		return cedarsdk.Long(value), nil
	case int64:
		return cedarsdk.Long(value), nil
	case uint:
		if uint64(value) > math.MaxInt64 {
			return nil, authorization.ErrInvalidRequest
		}
		return cedarsdk.Long(value), nil
	case uint8:
		return cedarsdk.Long(value), nil
	case uint16:
		return cedarsdk.Long(value), nil
	case uint32:
		return cedarsdk.Long(value), nil
	case uint64:
		if value > math.MaxInt64 {
			return nil, authorization.ErrInvalidRequest
		}
		return cedarsdk.Long(value), nil
	case []any:
		converted := make([]cedarsdk.Value, len(value))
		for i := range value {
			item, err := contextValue(value[i], depth+1, remaining)
			if err != nil {
				return nil, err
			}
			converted[i] = item
		}
		return cedarsdk.NewSet(converted...), nil
	case []string:
		converted := make([]cedarsdk.Value, len(value))
		for i := range value {
			item, err := contextValue(value[i], depth+1, remaining)
			if err != nil {
				return nil, err
			}
			converted[i] = item
		}
		return cedarsdk.NewSet(converted...), nil
	case map[string]any:
		record := make(cedarsdk.RecordMap, len(value))
		for key, child := range value {
			if !validContextKey(key) {
				return nil, authorization.ErrInvalidRequest
			}
			converted, err := contextValue(child, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			record[cedarsdk.String(key)] = converted
		}
		return cedarsdk.NewRecord(record), nil
	default:
		return nil, authorization.ErrInvalidRequest
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
		switch value := value.(type) {
		case map[string]any:
			clone[key] = cloneMap(value)
		case []any:
			clone[key] = append([]any(nil), value...)
		case []string:
			clone[key] = append([]string(nil), value...)
		default:
			clone[key] = value
		}
	}
	return clone
}

var _ authorization.Authorizer = (*Engine)(nil)
