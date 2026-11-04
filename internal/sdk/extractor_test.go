package sdk_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/shizuku198411/Latra/internal/sdk"
)

func TestReadSupportedLayouts(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project", ".workshop")
	tests := []struct {
		name         string
		metadataPath string
		hookCount    int
	}{
		{name: "standard", metadataPath: "sdk.yaml", hookCount: 5},
		{name: "mixed-normalized-hooks", metadataPath: "sdk.yaml", hookCount: 1},
		{name: "mixed-normalized-metadata", metadataPath: "meta/sdk.yaml", hookCount: 1},
		{name: "fully-normalized", metadataPath: "meta/sdk.yaml", hookCount: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolved, err := sdk.Read(filepath.Join(root, tt.name), tt.name, sdk.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if resolved.State != sdk.StateResolved {
				t.Errorf("state = %q, want %q", resolved.State, sdk.StateResolved)
			}
			if resolved.MetadataPath != tt.metadataPath {
				t.Errorf("metadata path = %q, want %q", resolved.MetadataPath, tt.metadataPath)
			}
			if len(resolved.Hooks) != tt.hookCount {
				t.Errorf("hook count = %d, want %d", len(resolved.Hooks), tt.hookCount)
			}
			if resolved.Digest == "" {
				t.Error("directory digest is empty")
			}
			for _, file := range resolved.Files {
				if file.Type == sdk.FileRegular && file.Digest == "" {
					t.Errorf("regular file %q has no digest", file.Path)
				}
				if file.Type == sdk.FileRegular && !file.Binary && int64(len(file.Content)) != file.Size {
					t.Errorf("regular file %q retained %d bytes, want %d", file.Path, len(file.Content), file.Size)
				}
				if file.Binary && len(file.Content) != 0 {
					t.Errorf("binary file %q retained %d bytes", file.Path, len(file.Content))
				}
			}
		})
	}
}

func TestReadLargeBinaryHashesWithoutRetainingContent(t *testing.T) {
	t.Parallel()

	sdkDir := filepath.Join(t.TempDir(), "large-binary")
	writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), "name: large-binary\n")
	binaryPath := filepath.Join(sdkDir, "bin", "tool")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte{0}, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(binaryPath, 17<<20); err != nil {
		t.Fatal(err)
	}
	resolved, err := sdk.Read(sdkDir, "large-binary", sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range resolved.Files {
		if file.Path != "bin/tool" {
			continue
		}
		if !file.Binary || len(file.Content) != 0 || file.Digest == "" || file.Size != 17<<20 {
			t.Fatalf("large binary = %#v", file)
		}
		return
	}
	t.Fatal("large binary was not inventoried")
}

func TestReadDigestIsDeterministic(t *testing.T) {
	t.Parallel()

	directory := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project", ".workshop", "standard")
	first, err := sdk.Read(directory, "standard", sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	second, err := sdk.Read(directory, "standard", sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("digest changed between reads: %q != %q", first.Digest, second.Digest)
	}
}

func TestReadRejectsNameMismatch(t *testing.T) {
	t.Parallel()

	directory := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project", ".workshop", "standard")
	_, err := sdk.Read(directory, "different", sdk.DefaultLimits())
	assertErrorCode(t, err, sdk.CodeInvalidMetadata)
}

func TestReadRejectsInvalidMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{name: "missing name", content: "summary: missing name\n"},
		{name: "wrong field type", content: "name: fixture\nplugs: []\n"},
		{name: "unknown field", content: "name: fixture\nunknown: true\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sdkDir := filepath.Join(t.TempDir(), "fixture")
			writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), tt.content)
			_, err := sdk.Read(sdkDir, "fixture", sdk.DefaultLimits())
			assertErrorCode(t, err, sdk.CodeInvalidMetadata)
		})
	}
}

func TestReadRejectsEscapingSymlink(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	sdkDir := filepath.Join(parent, "fixture")
	writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), "name: fixture\n")
	outside := filepath.Join(parent, "outside.txt")
	writeFile(t, outside, "outside")
	if err := os.Symlink(outside, filepath.Join(sdkDir, "escape")); err != nil {
		t.Fatal(err)
	}

	_, err := sdk.Read(sdkDir, "fixture", sdk.DefaultLimits())
	assertErrorCode(t, err, sdk.CodeUnsafePath)
}

func TestReadAcceptsConfinedSymlink(t *testing.T) {
	t.Parallel()

	sdkDir := filepath.Join(t.TempDir(), "fixture")
	writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), "name: fixture\n")
	writeFile(t, filepath.Join(sdkDir, "payload"), "payload")
	if err := os.Symlink("payload", filepath.Join(sdkDir, "payload-link")); err != nil {
		t.Fatal(err)
	}

	resolved, err := sdk.Read(sdkDir, "fixture", sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, file := range resolved.Files {
		if file.Path == "payload-link" {
			found = true
			if file.Type != sdk.FileSymlink || file.LinkTarget != "payload" {
				t.Errorf("unexpected symlink inventory: %#v", file)
			}
		}
	}
	if !found {
		t.Error("confined symlink is missing from inventory")
	}
}

func TestReadRejectsSymlinkHook(t *testing.T) {
	t.Parallel()

	sdkDir := filepath.Join(t.TempDir(), "fixture")
	writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), "name: fixture\n")
	writeFile(t, filepath.Join(sdkDir, "script"), "true\n")
	if err := os.MkdirAll(filepath.Join(sdkDir, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../script", filepath.Join(sdkDir, "hooks", "setup-base")); err != nil {
		t.Fatal(err)
	}

	_, err := sdk.Read(sdkDir, "fixture", sdk.DefaultLimits())
	assertErrorCode(t, err, sdk.CodeInvalidInput)
}

func TestReadResourceLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		limits func() sdk.Limits
	}{
		{
			name: "file count",
			limits: func() sdk.Limits {
				limits := sdk.DefaultLimits()
				limits.MaxFiles = 1
				return limits
			},
		},
		{
			name: "single file",
			limits: func() sdk.Limits {
				limits := sdk.DefaultLimits()
				limits.MaxFileSize = 8
				return limits
			},
		},
		{
			name: "total bytes",
			limits: func() sdk.Limits {
				limits := sdk.DefaultLimits()
				limits.MaxTotalBytes = 16
				return limits
			},
		},
		{
			name: "retained bytes",
			limits: func() sdk.Limits {
				limits := sdk.DefaultLimits()
				limits.MaxRetainedBytes = 8
				return limits
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sdkDir := filepath.Join(t.TempDir(), "fixture")
			writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), "name: fixture\n")
			writeFile(t, filepath.Join(sdkDir, "payload"), "payload-data")

			_, err := sdk.Read(sdkDir, "fixture", tt.limits())
			assertErrorCode(t, err, sdk.CodeResourceLimit)
			var limitErr *sdk.LimitError
			if !errors.As(err, &limitErr) {
				t.Fatalf("error %v does not contain LimitError", err)
			}
		})
	}
}

func TestReadDirectoryDepthLimit(t *testing.T) {
	t.Parallel()

	sdkDir := filepath.Join(t.TempDir(), "fixture")
	writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), "name: fixture\n")
	writeFile(t, filepath.Join(sdkDir, "nested", "payload"), "payload")
	limits := sdk.DefaultLimits()
	limits.MaxDepth = 1

	_, err := sdk.Read(sdkDir, "fixture", limits)
	assertErrorCode(t, err, sdk.CodeResourceLimit)
}

func assertErrorCode(t *testing.T, err error, want sdk.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %q error, got nil", want)
	}
	var sdkErr *sdk.Error
	if !errors.As(err, &sdkErr) {
		t.Fatalf("error %v does not contain *sdk.Error", err)
	}
	if sdkErr.Code != want {
		t.Fatalf("error code = %q, want %q; error: %v", sdkErr.Code, want, err)
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
