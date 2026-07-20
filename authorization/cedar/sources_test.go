package cedar_test

import (
	"context"
	"errors"

	"github.com/justusschock/go-auth/authorization"
)

type staticPolicies []byte

func (s staticPolicies) Policies(context.Context) ([]byte, error) {
	return append([]byte(nil), s...), nil
}

type staticEntities []byte

func (s staticEntities) Entities(context.Context, authorization.Request) ([]byte, error) {
	return append([]byte(nil), s...), nil
}

type emptyEntities struct{}

func (emptyEntities) Entities(context.Context, authorization.Request) ([]byte, error) {
	return []byte("[]"), nil
}

type failingPolicies struct{ err error }

func (s failingPolicies) Policies(context.Context) ([]byte, error) { return nil, s.err }

type failingEntities struct{ err error }

func (s failingEntities) Entities(context.Context, authorization.Request) ([]byte, error) {
	return nil, s.err
}

var errBackendDetail = errors.New("backend secret detail")

type mutatingEntities struct{}

func (mutatingEntities) Entities(_ context.Context, request authorization.Request) ([]byte, error) {
	request.Context["nested"].(map[string]any)["value"] = "mutated"
	request.Context["list"].([]any)[0].(map[string]any)["value"] = "mutated"
	request.Context["strings"].([]string)[0] = "mutated"
	return []byte("[]"), nil
}
