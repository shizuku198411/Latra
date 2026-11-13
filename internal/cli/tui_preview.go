package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/sdkcache"
)

// Keep the interactive screen responsive even if a cached file is huge.
const maxTUIPreviewBytes = 1 << 20

type tuiPreview struct {
	Interface   bool
	Path        string
	Status      string
	Lines       []string
	SourceLines []string
	Scroll      int
}

func loadTUIPreview(entry sdkcache.Entry, name string) (tuiPreview, error) {
	// Reject symlinks in *every* path component, including the selected file.
	// ReadDir performs confined, no-symlink directory traversal.
	parts := strings.Split(path.Clean(name), "/")
	for i, component := range parts {
		parent := "."
		if i > 0 {
			parent = path.Join(parts[:i]...)
		}
		children, err := sdkcache.ReadDir(entry, parent)
		if err != nil {
			return tuiPreview{}, err
		}
		found := false
		for _, child := range children {
			if child.Name() != component {
				continue
			}
			found = true
			if child.Type()&fs.ModeSymlink != 0 {
				return tuiPreview{}, fmt.Errorf("symlink preview is disabled: %s", name)
			}
			if i < len(parts)-1 && !child.IsDir() {
				return tuiPreview{}, fmt.Errorf("not a directory: %s", component)
			}
			if i == len(parts)-1 && !child.IsDir() {
				// Check the full mode rather than relying on DirEntry.Type.
				info, err := child.Info()
				if err != nil {
					return tuiPreview{}, err
				}
				if !info.Mode().IsRegular() {
					return tuiPreview{}, fmt.Errorf("not a regular file: %s", name)
				}
			}
			break
		}
		if !found {
			return tuiPreview{}, fs.ErrNotExist
		}
	}
	file, info, err := sdkcache.OpenFile(entry, name)
	if err != nil {
		var skipped *sdkcache.ContentSkippedError
		if errors.As(err, &skipped) {
			return tuiPreview{Path: name, Status: "Not extracted", Lines: []string{fmt.Sprintf("File type: %s", skipped.File.Type), fmt.Sprintf("Size: %d bytes", skipped.File.Size), "Reason: " + skipped.File.SkipReason}}, nil
		}
		return tuiPreview{}, err
	}
	defer file.Close()
	preview := tuiPreview{Path: name, Status: fmt.Sprintf("%d bytes", info.Size())}
	// Too-large files are classified by their small header only; never load the entire file.
	limit := int64(maxTUIPreviewBytes)
	if info.Size() > limit {
		limit = 512
	}
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return tuiPreview{}, err
	}
	if info.Size() > maxTUIPreviewBytes {
		preview.Status = fmt.Sprintf("File too large for text preview (%d bytes)", info.Size())
		preview.Lines = []string{"Type: " + describeBinary(data), "MIME: " + http.DetectContentType(data), "Content not displayed (size limit)"}
		return preview, nil
	}
	if !sdk.IsTextContent(data) {
		preview.Status = "Binary file (content hidden)"
		preview.Lines = []string{"Type: " + describeBinary(data), "MIME: " + http.DetectContentType(data), fmt.Sprintf("Size: %d bytes", info.Size())}
		return preview, nil
	}
	// Remove terminal escape/control sequences and keep line endings consistent.
	content := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	preview.Status = fmt.Sprintf("Text file · %d bytes", info.Size())
	preview.SourceLines = strings.Split(content, "\n")
	preview.Lines = make([]string, len(preview.SourceLines))
	for i, line := range preview.SourceLines {
		preview.Lines[i] = fmt.Sprintf("%5d  %s", i+1, strings.ReplaceAll(line, "\t", "    "))
	}
	return preview, nil
}
