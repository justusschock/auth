package authorization

import "errors"

var (
	ErrInvalidConfiguration = errors.New("authorization: invalid configuration")
	ErrInvalidRequest       = errors.New("authorization: invalid request")
	ErrSource               = errors.New("authorization: source unavailable")
	ErrInvalidSource        = errors.New("authorization: invalid source")
)
