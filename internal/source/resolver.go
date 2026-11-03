package source

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/shizuku198411/Latra/internal/sdk"
)

// Scan resolves a Workshop project or a project SDK directory.
func Scan(input string, limits sdk.Limits) (*Result, error) {
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
		return readProject(absolute, limits)
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
