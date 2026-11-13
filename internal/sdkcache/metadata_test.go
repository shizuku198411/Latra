package sdkcache

import (
	"github.com/shizuku198411/Latra/internal/sdk"
	"os"
	"path/filepath"
	"testing"
)

func TestReadMetadataSelectedEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sdk.yaml"), []byte("name: example\nplugs:\n  camera: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	entry := Entry{SDK: "example", Root: root}
	metadata, path, err := ReadMetadata(entry, sdk.DefaultLimits())
	if err != nil || path != "sdk.yaml" || metadata == nil || len(metadata.Plugs) != 1 {
		t.Fatalf("metadata=%+v path=%q err=%v", metadata, path, err)
	}
	entry.SDK = "other"
	if _, _, err = ReadMetadata(entry, sdk.DefaultLimits()); err == nil {
		t.Fatal("expected name mismatch")
	}
}
