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

func TestResolveMatchesWorkshopChannelShorthand(t *testing.T) {
	t.Parallel()

	cache := t.TempDir()
	createRevision(t, cache, "go", "latest/stable", 10)
	createRevision(t, cache, "go", "1.26/stable", 26)
	createRevision(t, cache, "go", "1.27/stable", 27)

	stable, err := sdkcache.Resolve(cache, sdkcache.Selection{SDK: "go", Channel: "stable"})
	if err != nil || stable.Channel != "latest/stable" {
		t.Fatalf("stable entry = %#v, error = %v", stable, err)
	}
	track, err := sdkcache.Resolve(cache, sdkcache.Selection{SDK: "go", Channel: "1.26"})
	if err != nil || track.Channel != "1.26/stable" || track.Revision != 26 {
		t.Fatalf("track entry = %#v, error = %v", track, err)
	}
}

func TestListReturnsCompleteEntriesInStableOrder(t *testing.T) {
	t.Parallel()

	cache := t.TempDir()
	createRevision(t, cache, "rust", "latest/stable", 42)
	createRevision(t, cache, "go", "1.27/stable", 26)
	createRevision(t, cache, "go", "1.27/stable", 27)
	incomplete := filepath.Join(cache, "go", "latest", "edge", "99")
	if err := os.MkdirAll(incomplete, 0o700); err != nil {
		t.Fatal(err)
	}

	entries, err := sdkcache.List(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %#v", entries)
	}
	want := []struct {
		sdk      string
		channel  string
		revision int
	}{
		{sdk: "go", channel: "1.27/stable", revision: 27},
		{sdk: "go", channel: "1.27/stable", revision: 26},
		{sdk: "rust", channel: "latest/stable", revision: 42},
	}
	for index, expected := range want {
		entry := entries[index]
		if entry.SDK != expected.sdk || entry.Channel != expected.channel || entry.Revision != expected.revision {
			t.Errorf("entries[%d] = %#v, want %#v", index, entry, expected)
		}
	}
}

func TestListMissingCacheIsEmpty(t *testing.T) {
	t.Parallel()

	entries, err := sdkcache.List(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %#v", entries)
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

func TestRemoveSDKsOnlyRemovesNamedEntries(t *testing.T) {
	t.Parallel()

	cache := t.TempDir()
	createRevision(t, cache, "go", "latest/stable", 27)
	createRevision(t, cache, "rust", "latest/stable", 54)

	removed, err := sdkcache.RemoveSDKs(cache, []string{"go", "go", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != "go" {
		t.Fatalf("removed = %q", removed)
	}
	if _, err := os.Stat(filepath.Join(cache, "go")); !os.IsNotExist(err) {
		t.Fatalf("go cache still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cache, "rust")); err != nil {
		t.Fatalf("rust cache was removed: %v", err)
	}
}

func TestRemoveAllPreservesCacheRoot(t *testing.T) {
	t.Parallel()

	cache := t.TempDir()
	createRevision(t, cache, "go", "latest/stable", 27)
	if err := os.WriteFile(filepath.Join(cache, ".temporary"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	count, err := sdkcache.RemoveAll(cache)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("removed count = %d, want 2", count)
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cache entries remain: %v", entries)
	}
}

func TestRemoveAllRejectsUnsafeRoot(t *testing.T) {
	t.Parallel()

	if _, err := sdkcache.RemoveAll("/"); err == nil {
		t.Fatal("expected filesystem root to be rejected")
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "cache")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := sdkcache.RemoveAll(link); err == nil {
		t.Fatal("expected symlinked cache root to be rejected")
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
