package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/shizuku198411/Latra/internal/sdk"
)

// StoreRequest identifies one Store SDK variant requested by a Workshop.
type StoreRequest struct {
	Name    string
	Channel string
	Base    string
}

// StoreResolver obtains and extracts Store SDKs without executing their contents.
type StoreResolver interface {
	Resolve(context.Context, StoreRequest, sdk.Limits) (*sdk.SDK, error)
}

// ResolutionError describes a non-fatal Store SDK resolution failure.
type ResolutionError struct {
	State      sdk.ResolutionState
	Diagnostic sdk.Diagnostic
	Err        error
}

func (e *ResolutionError) Error() string { return e.Err.Error() }
func (e *ResolutionError) Unwrap() error { return e.Err }

// Scan resolves a Workshop project or a project SDK directory.
func Scan(input string, limits sdk.Limits) (*Result, error) {
	return ScanWithResolver(context.Background(), input, limits, nil)
}

// ScanWithResolver scans an input and resolves Store SDK declarations when a resolver is supplied.
func ScanWithResolver(ctx context.Context, input string, limits sdk.Limits, resolver StoreResolver) (*Result, error) {
	absolute, err := filepath.Abs(input)
	if err != nil {
		return nil, fmt.Errorf("resolve input path: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("input must be a directory: %s", absolute)
	}

	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	_, workshopErr := root.Stat(".workshop")
	closeErr := root.Close()
	if closeErr != nil {
		return nil, closeErr
	}
	if workshopErr == nil {
		return readProject(ctx, absolute, limits, resolver, false)
	}
	if !errors.Is(workshopErr, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect .workshop: %w", workshopErr)
	}

	resolved, err := sdk.Read(absolute, filepath.Base(absolute), limits)
	if err != nil {
		return nil, err
	}
	return &Result{
		Kind: InputProjectSDK,
		Root: absolute,
		SDKs: []sdk.SDK{*resolved},
	}, nil
}

// DiscoverProject returns the Explorer inventory without fetching SDKs.
// Unsupported try-/sketch entries remain visible, while system and agent
// are omitted. ScanWithResolver excludes all four special SDK categories.
func DiscoverProject(ctx context.Context, projectPath string, limits sdk.Limits) (*Result, error) {
	return readProject(ctx, projectPath, limits, nil, true)
}
