package sdkcache

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/shizuku198411/Latra/internal/sdk"
)

// RemoveSDKs removes every cached channel and revision for the named SDKs.
// It returns the SDK names that had cache entries, in input order.
func RemoveSDKs(cacheRoot string, names []string) ([]string, error) {
	root, err := validateCleanRoot(cacheRoot)
	if err != nil {
		return nil, err
	}
	removed := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		if err := sdk.ValidateName(name); err != nil {
			return nil, fmt.Errorf("invalid SDK cache name: %w", err)
		}
		target := filepath.Join(root, name)
		if _, err := os.Lstat(target); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("inspect SDK cache %q: %w", name, err)
		}
		if err := os.RemoveAll(target); err != nil {
			return nil, fmt.Errorf("remove SDK cache %q: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// RemoveAll removes every entry beneath the Latra cache root while preserving
// the cache root itself. It returns the number of top-level entries removed.
func RemoveAll(cacheRoot string) (int, error) {
	root, err := validateCleanRoot(cacheRoot)
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read SDK cache: %w", err)
	}
	removed := 0
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return removed, fmt.Errorf("remove cache entry %q: %w", entry.Name(), err)
		}
		removed++
	}
	return removed, nil
}

func validateCleanRoot(cacheRoot string) (string, error) {
	if cacheRoot == "" {
		return "", fmt.Errorf("SDK cache path must not be empty")
	}
	root := filepath.Clean(cacheRoot)
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("SDK cache path must be absolute: %q", cacheRoot)
	}
	if root == filepath.Clean(string(filepath.Separator)) {
		return "", fmt.Errorf("refusing to clean filesystem root")
	}
	info, err := os.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		return root, nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect SDK cache root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to clean symlinked SDK cache root %q", root)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("SDK cache root is not a directory: %q", root)
	}
	return root, nil
}
