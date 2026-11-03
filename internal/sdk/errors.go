package sdk

import "fmt"

// ErrorCode makes scanner failures distinguishable without parsing messages.
type ErrorCode string

const (
	CodeInvalidInput    ErrorCode = "invalid-input"
	CodeInvalidMetadata ErrorCode = "invalid-metadata"
	CodeUnsafePath      ErrorCode = "unsafe-path"
	CodeResourceLimit   ErrorCode = "resource-limit"
	CodeFilesystem      ErrorCode = "filesystem"
)

// Error adds a stable category and path to an SDK reader failure.
type Error struct {
	Code ErrorCode
	Path string
	Err  error
}

func (e *Error) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("%s: %v", e.Code, e.Err)
	}
	return fmt.Sprintf("%s: %s: %v", e.Code, e.Path, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// LimitError reports which resource bound was exceeded.
type LimitError struct {
	Resource string
	Limit    int64
	Actual   int64
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("%s limit exceeded: limit=%d actual=%d", e.Resource, e.Limit, e.Actual)
}
