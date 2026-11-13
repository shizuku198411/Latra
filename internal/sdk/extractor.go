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
	MaxFiles            int64
	MaxFileSize         int64
	MaxRequiredFileSize int64
	MaxTotalBytes       int64
	MaxStreamedBytes    int64
	MaxRetainedBytes    int64
	MaxDepth            int
}

// DefaultLimits returns conservative initial bounds for project SDKs.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:            25_000,
		MaxFileSize:         512 << 20,
		MaxRequiredFileSize: 16 << 20,
		MaxTotalBytes:       2 << 30,
		MaxStreamedBytes:    16 << 30,
		MaxRetainedBytes:    128 << 20,
		MaxDepth:            64,
	}
}

// ReadOptions supplies cache-only inventory information that is not present as
// an extracted filesystem entry.
type ReadOptions struct {
	AdditionalFiles []File
	IgnorePaths     []string
}

// Read opens and extracts an SDK directory supplied directly by the user.
func Read(directory, declaredName string, limits Limits) (*SDK, error) {
	return ReadWithOptions(directory, declaredName, limits, ReadOptions{})
}

// ReadWithOptions reads an SDK and merges validated inventory-only entries.
func ReadWithOptions(directory, declaredName string, limits Limits, options ReadOptions) (*SDK, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, wrap(CodeFilesystem, directory, err)
	}
	defer root.Close()
	return readRoot(root, directory, declaredName, limits, options)
}

// ReadRoot extracts an SDK through a confined os.Root.
func ReadRoot(root *os.Root, displayPath, declaredName string, limits Limits) (*SDK, error) {
	return readRoot(root, displayPath, declaredName, limits, ReadOptions{})
}

// ReadMetadataRoot reads only the required SDK metadata through a confined root.
func ReadMetadataRoot(root *os.Root, declaredName string, limits Limits) (*Metadata, string, error) {
	if err := validateLimits(limits); err != nil {
		return nil, "", err
	}
	name, err := selectMetadata(root)
	if err != nil {
		return nil, "", err
	}
	_, content, size, _, err := readRegular(root, name, limits.MaxRequiredFileSize)
	if err != nil {
		return nil, "", err
	}
	if size > limits.MaxRequiredFileSize || size > limits.MaxTotalBytes || size > limits.MaxRetainedBytes {
		return nil, "", fmt.Errorf("metadata exceeds resource limit")
	}
	metadata, err := decodeMetadata(content)
	if err != nil {
		return nil, "", err
	}
	if declaredName != "" && metadata.Name != declaredName {
		return nil, "", fmt.Errorf("SDK name %q does not match declared name %q", metadata.Name, declaredName)
	}
	return metadata, name, nil
}

func readRoot(root *os.Root, displayPath, declaredName string, limits Limits, options ReadOptions) (*SDK, error) {
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

	required := requiredPaths(metadataPath, hooksRoot)
	ignored := make(map[string]bool, len(options.IgnorePaths))
	for _, name := range options.IgnorePaths {
		ignored[path.Clean(name)] = true
	}
	files, contents, totalBytes, err := inventory(root, limits, required, ignored)
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

	files, err = mergeAdditionalFiles(files, options.AdditionalFiles)
	if err != nil {
		return nil, wrap(CodeInvalidInput, displayPath, err)
	}
	result := &SDK{
		Name:         metadata.Name,
		Source:       SourceProject,
		State:        StateResolved,
		Root:         displayPath,
		MetadataPath: metadataPath,
		Metadata:     metadata,
		Hooks:        hooks,
		Files:        files,
		Digest:       digestDirectory(files),
	}
	if skipped := skippedFileCount(files); skipped > 0 {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			Code: "file-content-skipped", Severity: SeverityWarning, Phase: "inventory",
			Message: fmt.Sprintf("%d non-essential file content(s) were skipped due to resource limits", skipped),
		})
	}
	return result, nil
}

func validateLimits(limits Limits) error {
	if limits.MaxFiles <= 0 || limits.MaxFileSize <= 0 || limits.MaxRequiredFileSize <= 0 || limits.MaxTotalBytes <= 0 || limits.MaxStreamedBytes <= 0 || limits.MaxRetainedBytes <= 0 || limits.MaxDepth <= 0 {
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

func inventory(root *os.Root, limits Limits, required, ignored map[string]bool) ([]File, map[string][]byte, int64, error) {
	var files []File
	contents := make(map[string][]byte)
	var totalBytes int64
	var retainedBytes int64
	var streamedBytes int64
	nonRequiredBudget := max(int64(0), limits.MaxTotalBytes-requiredReserve(limits))
	nonRequiredRetainedBudget := max(int64(0), limits.MaxRetainedBytes-requiredReserve(limits))

	err := fs.WalkDir(root.FS(), ".", func(entryPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return wrap(CodeFilesystem, entryPath, walkErr)
		}
		if entryPath == "." {
			return nil
		}
		if ignored[entryPath] {
			if entry.IsDir() {
				return fs.SkipDir
			}
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
			isRequired := required[entryPath]
			if isRequired && info.Size() > limits.MaxRequiredFileSize {
				return resourceError(entryPath, "required-file-bytes", limits.MaxRequiredFileSize, info.Size())
			}
			streamedBytes += info.Size()
			if streamedBytes > limits.MaxStreamedBytes {
				return resourceError(entryPath, "streamed-bytes", limits.MaxStreamedBytes, streamedBytes)
			}
			shouldSkip := !isRequired && (info.Size() > limits.MaxFileSize || totalBytes+info.Size() > nonRequiredBudget)
			if shouldSkip {
				remainingStream := limits.MaxStreamedBytes - (streamedBytes - info.Size())
				digest, size, err := hashRegular(root, entryPath, remainingStream)
				if err != nil {
					return err
				}
				file.Size, file.Digest = size, digest
				file.Skipped, file.SkipReason = true, "size-limit"
				files = append(files, file)
				return nil
			}
			readLimit := limits.MaxFileSize
			if isRequired {
				readLimit = limits.MaxRequiredFileSize
			}
			digest, content, size, binary, err := readRegular(root, entryPath, readLimit)
			if err != nil {
				return err
			}
			totalBytes += size
			if isRequired && totalBytes > limits.MaxTotalBytes {
				return resourceError(entryPath, "total-read-bytes", limits.MaxTotalBytes, totalBytes)
			}
			file.Size = size
			file.Digest = digest
			file.Binary = binary
			if !file.Binary {
				contentSize := int64(len(content))
				if !isRequired && retainedBytes+contentSize > nonRequiredRetainedBudget {
					file.Content = nil
					file.Skipped, file.SkipReason = true, "retained-size-limit"
					files = append(files, file)
					return nil
				}
				retainedBytes += contentSize
				if isRequired && retainedBytes > limits.MaxRetainedBytes {
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

func hashRegular(root *os.Root, name string, limit int64) (string, int64, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", 0, wrap(CodeFilesystem, name, err)
	}
	defer file.Close()
	hasher := sha3.New384()
	size, err := io.Copy(hasher, io.LimitReader(file, limit+1))
	if err != nil {
		return "", size, wrap(CodeFilesystem, name, err)
	}
	if size > limit {
		return "", size, resourceError(name, "streamed-bytes", limit, size)
	}
	return formatDigest(hasher), size, nil
}

func requiredPaths(metadataPath, hooksRoot string) map[string]bool {
	result := map[string]bool{metadataPath: true}
	for _, hook := range HookNames {
		result[path.Join(hooksRoot, string(hook))] = true
	}
	return result
}

// IsRequiredFile reports whether an archive path is SDK metadata or a standard hook.
func IsRequiredFile(name string) bool {
	clean := path.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "sdk.yaml" || clean == "meta/sdk.yaml" {
		return true
	}
	for _, root := range []string{"hooks", "sdk/hooks"} {
		for _, hook := range HookNames {
			if clean == path.Join(root, string(hook)) {
				return true
			}
		}
	}
	return false
}

func requiredReserve(limits Limits) int64 {
	const requiredSlots = int64(6) // one metadata file and five standard hooks
	if limits.MaxRequiredFileSize > limits.MaxTotalBytes/requiredSlots {
		return limits.MaxTotalBytes
	}
	return requiredSlots * limits.MaxRequiredFileSize
}

func mergeAdditionalFiles(files, additional []File) ([]File, error) {
	seen := make(map[string]bool, len(files)+len(additional))
	for _, file := range files {
		seen[file.Path] = true
	}
	for _, file := range additional {
		clean := path.Clean(strings.ReplaceAll(file.Path, "\\", "/"))
		if clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || seen[clean] || IsRequiredFile(clean) {
			return nil, fmt.Errorf("invalid additional inventory path %q", file.Path)
		}
		if !file.Skipped || file.Size < 0 || (file.Type != FileRegular && file.Type != FileSymlink) || file.Digest == "" {
			return nil, fmt.Errorf("invalid skipped inventory entry %q", file.Path)
		}
		if file.Type == FileSymlink && file.LinkTarget == "" {
			return nil, fmt.Errorf("invalid skipped symlink inventory entry %q", file.Path)
		}
		file.Path = clean
		file.Content = nil
		files = append(files, file)
		seen[clean] = true
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func skippedFileCount(files []File) int {
	count := 0
	for _, file := range files {
		if file.Skipped {
			count++
		}
	}
	return count
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
