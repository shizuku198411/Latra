package sdk

import (
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

// Limits bounds work performed on an untrusted SDK directory.
type Limits struct {
	MaxFiles         int64
	MaxFileSize      int64
	MaxTotalBytes    int64
	MaxRetainedBytes int64
	MaxDepth         int
}

// DefaultLimits returns conservative initial bounds for project SDKs.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:         25_000,
		MaxFileSize:      512 << 20,
		MaxTotalBytes:    2 << 30,
		MaxRetainedBytes: 128 << 20,
		MaxDepth:         64,
	}
}

// Read opens and extracts an SDK directory supplied directly by the user.
func Read(directory, declaredName string, limits Limits) (*SDK, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, wrap(CodeFilesystem, directory, err)
	}
	defer root.Close()
	return ReadRoot(root, directory, declaredName, limits)
}

// ReadRoot extracts an SDK through a confined os.Root.
func ReadRoot(root *os.Root, displayPath, declaredName string, limits Limits) (*SDK, error) {
	if err := validateLimits(limits); err != nil {
		return nil, wrap(CodeInvalidInput, displayPath, err)
	}

	metadataPath, err := selectMetadata(root)
	if err != nil {
		return nil, wrap(CodeInvalidMetadata, displayPath, err)
	}
	hooksRoot, err := selectHooksRoot(root)
	if err != nil {
		return nil, wrap(CodeInvalidInput, displayPath, err)
	}

	files, contents, totalBytes, err := inventory(root, limits)
	if err != nil {
		return nil, errAt(displayPath, err)
	}
	_ = totalBytes

	metadataContent, ok := contents[metadataPath]
	if !ok {
		return nil, wrap(CodeInvalidMetadata, path.Join(displayPath, metadataPath), fmt.Errorf("metadata was not retained"))
	}
	metadata, err := decodeMetadata(metadataContent)
	if err != nil {
		return nil, wrap(CodeInvalidMetadata, path.Join(displayPath, metadataPath), err)
	}
	if declaredName != "" && metadata.Name != declaredName {
		return nil, wrap(CodeInvalidMetadata, path.Join(displayPath, metadataPath), fmt.Errorf("SDK name %q does not match declared name %q", metadata.Name, declaredName))
	}

	hooks := make([]Hook, 0, len(HookNames))
	for _, name := range HookNames {
		hookPath := path.Join(hooksRoot, string(name))
		file := findFile(files, hookPath)
		if file == nil {
			continue
		}
		if file.Type != FileRegular {
			return nil, wrap(CodeInvalidInput, path.Join(displayPath, hookPath), fmt.Errorf("hook must be a regular file"))
		}
		content, exists := contents[hookPath]
		if !exists {
			return nil, wrap(CodeInvalidInput, path.Join(displayPath, hookPath), fmt.Errorf("hook content was not retained"))
		}
		hooks = append(hooks, Hook{
			Name:    name,
			Path:    hookPath,
			Content: content,
			Digest:  file.Digest,
			Size:    file.Size,
		})
	}

	return &SDK{
		Name:         metadata.Name,
		Source:       SourceProject,
		State:        StateResolved,
		Root:         displayPath,
		MetadataPath: metadataPath,
		Metadata:     metadata,
		Hooks:        hooks,
		Files:        files,
		Digest:       digestDirectory(files),
	}, nil
}

func validateLimits(limits Limits) error {
	if limits.MaxFiles <= 0 || limits.MaxFileSize <= 0 || limits.MaxTotalBytes <= 0 || limits.MaxRetainedBytes <= 0 || limits.MaxDepth <= 0 {
		return fmt.Errorf("all resource limits must be positive")
	}
	return nil
}

func selectMetadata(root *os.Root) (string, error) {
	const short = "sdk.yaml"
	const long = "meta/sdk.yaml"
	shortExists, err := entryExists(root, short)
	if err != nil {
		return "", err
	}
	longExists, err := entryExists(root, long)
	if err != nil {
		return "", err
	}
	if shortExists && longExists {
		return "", fmt.Errorf("SDK contains both %s and %s", short, long)
	}
	if !shortExists && !longExists {
		return "", fmt.Errorf("SDK metadata not found; expected %s or %s", short, long)
	}
	selected := short
	if longExists {
		selected = long
	}
	info, err := root.Lstat(selected)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular file", selected)
	}
	return selected, nil
}

func selectHooksRoot(root *os.Root) (string, error) {
	const short = "hooks"
	const long = "sdk/hooks"
	shortExists, err := entryExists(root, short)
	if err != nil {
		return "", err
	}
	longExists, err := entryExists(root, long)
	if err != nil {
		return "", err
	}
	if shortExists && longExists {
		return "", fmt.Errorf("SDK contains both %s and %s", short, long)
	}
	selected := short
	if longExists {
		selected = long
	}
	if shortExists || longExists {
		info, err := root.Lstat(selected)
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return "", fmt.Errorf("%s must be a directory", selected)
		}
	}
	return selected, nil
}

func entryExists(root *os.Root, name string) (bool, error) {
	_, err := root.Lstat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func inventory(root *os.Root, limits Limits) ([]File, map[string][]byte, int64, error) {
	var files []File
	contents := make(map[string][]byte)
	var totalBytes int64
	var retainedBytes int64

	err := fs.WalkDir(root.FS(), ".", func(entryPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return wrap(CodeFilesystem, entryPath, walkErr)
		}
		if entryPath == "." {
			return nil
		}
		if depth(entryPath) > limits.MaxDepth {
			return resourceError(entryPath, "directory-depth", int64(limits.MaxDepth), int64(depth(entryPath)))
		}
		if int64(len(files)+1) > limits.MaxFiles {
			return resourceError(entryPath, "file-count", limits.MaxFiles, int64(len(files)+1))
		}

		info, err := entry.Info()
		if err != nil {
			return wrap(CodeFilesystem, entryPath, err)
		}
		file := File{Path: entryPath, Mode: info.Mode(), Type: classify(info.Mode())}

		switch file.Type {
		case FileRegular:
			if info.Size() > limits.MaxFileSize {
				return resourceError(entryPath, "single-file-bytes", limits.MaxFileSize, info.Size())
			}
			remaining := limits.MaxTotalBytes - totalBytes
			if remaining < 0 {
				remaining = 0
			}
			readLimit := min(limits.MaxFileSize, remaining)
			digest, content, size, binary, err := readRegular(root, entryPath, readLimit)
			if err != nil {
				var limitErr *LimitError
				if errors.As(err, &limitErr) && readLimit == remaining && remaining < limits.MaxFileSize {
					return resourceError(entryPath, "total-read-bytes", limits.MaxTotalBytes, totalBytes+limitErr.Actual)
				}
				return err
			}
			if size > remaining {
				return resourceError(entryPath, "total-read-bytes", limits.MaxTotalBytes, totalBytes+size)
			}
			totalBytes += size
			file.Size = size
			file.Digest = digest
			file.Binary = binary
			if !file.Binary {
				retainedBytes += int64(len(content))
				if retainedBytes > limits.MaxRetainedBytes {
					return resourceError(entryPath, "retained-bytes", limits.MaxRetainedBytes, retainedBytes)
				}
				file.Content = content
				contents[entryPath] = content
			}
		case FileSymlink:
			target, err := root.Readlink(entryPath)
			if err != nil {
				return wrap(CodeFilesystem, entryPath, err)
			}
			if _, err := root.Stat(entryPath); err != nil {
				return wrap(CodeUnsafePath, entryPath, fmt.Errorf("unsafe or broken symlink to %q: %w", target, err))
			}
			file.LinkTarget = target
			file.Size = int64(len(target))
			file.Digest = digestBytes([]byte(target))
		}

		files = append(files, file)
		return nil
	})
	if err != nil {
		return nil, nil, totalBytes, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, contents, totalBytes, nil
}

func readRegular(root *os.Root, name string, limit int64) (string, []byte, int64, bool, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", nil, 0, false, wrap(CodeFilesystem, name, err)
	}
	defer file.Close()

	hasher := sha3.New384()
	const sampleSize int64 = 64 << 10
	sample, err := io.ReadAll(io.LimitReader(file, min(sampleSize, limit+1)))
	if err != nil {
		return "", nil, 0, false, wrap(CodeFilesystem, name, err)
	}
	written := int64(len(sample))
	if written > limit {
		return "", nil, written, false, resourceError(name, "single-file-bytes", limit, written)
	}
	if _, err := hasher.Write(sample); err != nil {
		return "", nil, written, false, wrap(CodeFilesystem, name, err)
	}
	if !isTextSample(sample) {
		copied, err := io.Copy(hasher, io.LimitReader(file, limit-written+1))
		written += copied
		if err != nil {
			return "", nil, written, true, wrap(CodeFilesystem, name, err)
		}
		if written > limit {
			return "", nil, written, true, resourceError(name, "single-file-bytes", limit, written)
		}
		return formatDigest(hasher), nil, written, true, nil
	}

	var builder strings.Builder
	builder.Write(sample)
	writer := io.MultiWriter(hasher, &builder)
	copied, err := io.Copy(writer, io.LimitReader(file, limit-written+1))
	written += copied
	if err != nil {
		return "", nil, written, false, wrap(CodeFilesystem, name, err)
	}
	if written > limit {
		return "", nil, written, false, resourceError(name, "single-file-bytes", limit, written)
	}
	content := []byte(builder.String())
	binary := !IsTextContent(content)
	if binary {
		content = nil
	}
	return formatDigest(hasher), content, written, binary, nil
}

func isTextSample(content []byte) bool {
	if IsTextContent(content) {
		return true
	}
	// A bounded sample can end in the middle of a valid UTF-8 sequence.
	for trim := 1; trim <= 3 && trim < len(content); trim++ {
		if IsTextContent(content[:len(content)-trim]) {
			return true
		}
	}
	return false
}

func classify(mode fs.FileMode) FileType {
	switch {
	case mode.IsRegular():
		return FileRegular
	case mode.IsDir():
		return FileDirectory
	case mode&fs.ModeSymlink != 0:
		return FileSymlink
	default:
		return FileOther
	}
}

func digestDirectory(files []File) string {
	hasher := sha3.New384()
	for _, file := range files {
		fmt.Fprintf(hasher, "%s\x00%s\x00%o\x00%d\x00%s\x00%s\x00", file.Path, file.Type, file.Mode, file.Size, file.Digest, file.LinkTarget)
	}
	return formatDigest(hasher)
}

func digestBytes(content []byte) string {
	sum := sha3.Sum384(content)
	return "sha3-384:" + hex.EncodeToString(sum[:])
}

func formatDigest(hasher hash.Hash) string {
	return "sha3-384:" + hex.EncodeToString(hasher.Sum(nil))
}

func findFile(files []File, name string) *File {
	for i := range files {
		if files[i].Path == name {
			return &files[i]
		}
	}
	return nil
}

func depth(name string) int { return strings.Count(name, "/") + 1 }

func resourceError(name, resource string, limit, actual int64) error {
	return wrap(CodeResourceLimit, name, &LimitError{Resource: resource, Limit: limit, Actual: actual})
}

func wrap(code ErrorCode, name string, err error) error {
	return &Error{Code: code, Path: name, Err: err}
}

func errAt(base string, err error) error {
	var sdkErr *Error
	if errors.As(err, &sdkErr) {
		copy := *sdkErr
		copy.Path = path.Join(base, sdkErr.Path)
		return &copy
	}
	return wrap(CodeFilesystem, base, err)
}
