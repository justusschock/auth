package authorization

import "errors"

// Sentinel errors returned by authorizers. A non-nil error always means the
// request is not authorized.
var (
	// ErrInvalidConfiguration reports invalid constructor options.
	ErrInvalidConfiguration = errors.New("authorization: invalid configuration")
	// ErrInvalidRequest reports a malformed or unbounded request.
	ErrInvalidRequest = errors.New("authorization: invalid request")
	// ErrSource reports that a policy or entity source failed.
	ErrSource = errors.New("authorization: source unavailable")
	// ErrInvalidSource reports policies or entities that are empty, oversized
	// or malformed.
	ErrInvalidSource = errors.New("authorization: invalid source")
)
