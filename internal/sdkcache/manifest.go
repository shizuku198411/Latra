package sdkcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/shizuku198411/Latra/internal/sdk"
)

const ManifestPath = ".latra-cache-manifest.json"

type manifest struct {
	Version      int            `json:"version"`
	SkippedFiles []manifestFile `json:"skippedFiles"`
}

type manifestFile struct {
	Path       string       `json:"path"`
	Type       sdk.FileType `json:"type"`
	Mode       fs.FileMode  `json:"mode"`
	Size       int64        `json:"size"`
	Digest     string       `json:"digest"`
	LinkTarget string       `json:"linkTarget,omitempty"`
	SkipReason string       `json:"skipReason"`
}

// WriteManifest records entries intentionally omitted from an extracted cache.
func WriteManifest(root string, skipped []sdk.File) error {
	file, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer file.Close()
	output, err := file.OpenFile(ManifestPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	stored := make([]manifestFile, 0, len(skipped))
	for _, item := range skipped {
		stored = append(stored, manifestFile{
			Path: item.Path, Type: item.Type, Mode: item.Mode, Size: item.Size,
			Digest: item.Digest, LinkTarget: item.LinkTarget, SkipReason: item.SkipReason,
		})
	}
	encodeErr := json.NewEncoder(output).Encode(manifest{Version: 1, SkippedFiles: stored})
	closeErr := output.Close()
	return errors.Join(encodeErr, closeErr)
}

// ReadManifest loads and validates skipped cache entries. Older cache entries
// without a manifest are treated as having no skipped content.
func ReadManifest(root string) ([]sdk.File, error) {
	cacheRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer cacheRoot.Close()
	file, err := cacheRoot.Open(ManifestPath)
	if errors.Is(err, fs.ErrNotExist) {
		return []sdk.File{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var stored manifest
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("decode cache manifest: %w", err)
	}
	if stored.Version != 1 {
		return nil, fmt.Errorf("unsupported cache manifest version %d", stored.Version)
	}
	seen := make(map[string]bool, len(stored.SkippedFiles))
	result := make([]sdk.File, 0, len(stored.SkippedFiles))
	for index := range stored.SkippedFiles {
		item := &stored.SkippedFiles[index]
		clean := path.Clean(strings.ReplaceAll(item.Path, "\\", "/"))
		if clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || clean == ManifestPath || seen[clean] {
			return nil, fmt.Errorf("invalid skipped cache path %q", item.Path)
		}
		if (item.Type != sdk.FileRegular && item.Type != sdk.FileSymlink) || item.Size < 0 || item.Digest == "" || item.SkipReason == "" {
			return nil, fmt.Errorf("invalid skipped cache entry %q", item.Path)
		}
		if item.Type == sdk.FileSymlink && item.LinkTarget == "" {
			return nil, fmt.Errorf("invalid skipped cache symlink %q", item.Path)
		}
		item.Path = clean
		seen[clean] = true
		result = append(result, sdk.File{
			Path: clean, Type: item.Type, Mode: item.Mode, Size: item.Size,
			Digest: item.Digest, LinkTarget: item.LinkTarget, Skipped: true, SkipReason: item.SkipReason,
		})
	}
	return result, nil
}

// ContentSkippedError describes a cache entry intentionally not extracted.
type ContentSkippedError struct {
	File sdk.File
}

func (e *ContentSkippedError) Error() string {
	return fmt.Sprintf("content for SDK file %q was not extracted: %s", e.File.Path, e.File.SkipReason)
}

func skippedFile(entry Entry, requestedPath string) (*sdk.File, error) {
	if entry.ProjectRoot != "" {
		return nil, nil
	}
	files, err := ReadManifest(entry.Root)
	if err != nil {
		return nil, err
	}
	for index := range files {
		if files[index].Path == requestedPath {
			return &files[index], nil
		}
	}
	return nil, nil
}
