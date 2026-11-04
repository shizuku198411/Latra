package sdkcache_test

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/sdkcache"
)

func TestResolveSelectsLatestRevisionAndExplicitChannel(t *testing.T) {
	cache := t.TempDir()
	createRevision(t, cache, "rust", "latest/stable", 42)
	createRevision(t, cache, "rust", "latest/stable", 54)

	entry, err := sdkcache.Resolve(cache, sdkcache.Selection{SDK: "rust"})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Channel != "latest/stable" || entry.Revision != 54 {
		t.Fatalf("entry = %#v", entry)
	}
	explicit, err := sdkcache.Resolve(cache, sdkcache.Selection{SDK: "rust", Channel: "latest/stable", Revision: 42})
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Revision != 42 {
		t.Fatalf("explicit entry = %#v", explicit)
	}
}

func TestResolveRejectsAmbiguousChannels(t *testing.T) {
	cache := t.TempDir()
	createRevision(t, cache, "rust", "latest/stable", 54)
	createRevision(t, cache, "rust", "latest/edge", 55)
	_, err := sdkcache.Resolve(cache, sdkcache.Selection{SDK: "rust"})
	if err == nil || !strings.Contains(err.Error(), "multiple cached channels") {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenFileConfinesPath(t *testing.T) {
	cache := t.TempDir()
	entry := createRevision(t, cache, "rust", "latest/stable", 54)
	if err := os.WriteFile(filepath.Join(entry.Root, "sdk.yaml"), []byte("name: rust\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, _, err := sdkcache.OpenFile(entry, "sdk.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(content) != "name: rust\n" {
		t.Fatalf("content = %q, error = %v", content, err)
	}
	if _, _, err := sdkcache.OpenFile(entry, "../54.sdk"); err == nil {
		t.Fatal("expected traversal to be rejected")
	}
}

func TestResolveProjectAndOpenFile(t *testing.T) {
	project := t.TempDir()
	writeFile(t, filepath.Join(project, ".workshop", "local", "sdk.yaml"), "name: local\n")
	entry, err := sdkcache.ResolveProject(project, "local")
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := sdkcache.OpenFile(entry, "sdk.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(content) != "name: local\n" {
		t.Fatalf("content = %q, error = %v", content, err)
	}
}

func TestResolveProjectRejectsEscapingSDKDirectory(t *testing.T) {
	parent := t.TempDir()
	project := filepath.Join(parent, "project")
	outside := filepath.Join(parent, "outside")
	writeFile(t, filepath.Join(outside, "sdk.yaml"), "name: local\n")
	if err := os.MkdirAll(filepath.Join(project, ".workshop"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(project, ".workshop", "local")); err != nil {
		t.Fatal(err)
	}
	if _, err := sdkcache.ResolveProject(project, "local"); err == nil {
		t.Fatal("expected escaping project SDK directory to be rejected")
	}
}

func createRevision(t *testing.T, cache, name, channel string, revision int) sdkcache.Entry {
	t.Helper()
	root := filepath.Join(cache, name, filepath.FromSlash(channel), strconv.Itoa(revision))
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+".sdk", []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	return sdkcache.Entry{SDK: name, Channel: channel, Revision: revision, Root: root}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
