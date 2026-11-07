package cli

import (
	"bytes"
	"context"
	"errors"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/sdkcache"
	"github.com/shizuku198411/Latra/internal/source"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTUIInventoryUsesExistingProjectScanner(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project")
	path, items, err := loadTUIInventory(root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("path is not absolute: %q", path)
	}
	if len(items) == 0 {
		t.Fatal("missing SDKs")
	}
	project, store := false, false
	for _, item := range items {
		if item.Name == "fully-normalized" && item.Source == "project" && item.Status == "local" {
			project = true
		}
		if item.Name == "rust" && item.Source == "store" && item.Status == "not cached" {
			store = true
		}
	}
	if !project || !store {
		t.Fatalf("unexpected inventory: %+v", items)
	}
}

func TestTUIRequiresProjectBeforeTerminal(t *testing.T) {
	var out, errout bytes.Buffer
	code := RunWithDependencies([]string{"tui", "--project", t.TempDir()}, &out, &errout, Dependencies{})
	if code != exitError || !strings.Contains(errout.String(), ".workshop") {
		t.Fatalf("code=%d stderr=%q", code, errout.String())
	}
}

func TestTUIRejectsUnknownOption(t *testing.T) {
	var out, errout bytes.Buffer
	if code := RunWithDependencies([]string{"tui", "--bad"}, &out, &errout, Dependencies{}); code != exitUsage {
		t.Fatalf("code=%d", code)
	}
}

func TestTUITreeNavigation(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".workshop", "example", "hooks"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".workshop", "example", "hooks", "setup-project"), []byte("echo ok"), 0644); err != nil {
		t.Fatal(err)
	}
	entry, err := sdkcache.ResolveProject(root, "example")
	if err != nil {
		t.Fatal(err)
	}
	model := tuiExplorer{SDKs: []tuiSDK{{Name: "example", Status: "local", Entry: entry}}}
	model.enter()
	if !model.InTree || len(model.Nodes) != 1 || model.Nodes[0].Name != "hooks" {
		t.Fatalf("open SDK: %+v", model)
	}
	model.enter()
	if len(model.Nodes) != 2 || model.Nodes[1].Name != "setup-project" {
		t.Fatalf("expand hooks: %+v", model.Nodes)
	}
	model.move(1)
	model.enter() // file selection opens a read-only preview
	if model.Preview == nil || !model.InTree {
		t.Fatal("file selection did not open preview")
	}
	model.back()
	model.move(-1)
	model.enter()
	if len(model.Nodes) != 1 || model.Nodes[0].Expanded {
		t.Fatalf("collapse hooks: %+v", model.Nodes)
	}
	model.back()
	if model.InTree {
		t.Fatal("Esc must return to SDK list")
	}
}

func TestTUIUncachedSDKDoesNotEnterTree(t *testing.T) {
	model := tuiExplorer{SDKs: []tuiSDK{{Name: "remote", Status: "not cached"}}}
	model.enter()
	if model.InTree || !strings.Contains(model.Message, "not cached") {
		t.Fatalf("unexpected model: %+v", model)
	}
}

func TestTUITreeDoesNotTraverseSymlinks(t *testing.T) {
	root := t.TempDir()
	sdkDir := filepath.Join(root, ".workshop", "example")
	if err := os.MkdirAll(sdkDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(sdkDir, "linked")); err != nil {
		t.Fatal(err)
	}
	entry, err := sdkcache.ResolveProject(root, "example")
	if err != nil {
		t.Fatal(err)
	}
	items, err := readTUINodes(entry, ".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !items[0].Symlink || items[0].Directory {
		t.Fatalf("symlink: %+v", items)
	}
	if _, err := sdkcache.ReadDir(entry, "linked"); err == nil {
		t.Fatal("symlink traversal unexpectedly accepted")
	}
}

func TestTUITreeHidesCacheManifest(t *testing.T) {
	root := t.TempDir()
	sdkDir := filepath.Join(root, ".workshop", "example")
	if err := os.MkdirAll(sdkDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{sdkcache.ManifestPath, "sdk.yaml"} {
		if err := os.WriteFile(filepath.Join(sdkDir, name), []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := sdkcache.ResolveProject(root, "example")
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := readTUINodes(entry, ".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "sdk.yaml" {
		t.Fatalf("unexpected visible SDK files: %+v", nodes)
	}
}

func TestTUIPreviewTextAndNavigation(t *testing.T) {
	root := t.TempDir()
	sdkDir := filepath.Join(root, ".workshop", "example")
	if err := os.MkdirAll(sdkDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "notes.txt"), []byte("hello\nworld\n"), 0644); err != nil {
		t.Fatal(err)
	}
	entry, err := sdkcache.ResolveProject(root, "example")
	if err != nil {
		t.Fatal(err)
	}
	m := tuiExplorer{SDKs: []tuiSDK{{Name: "example", Status: "local", Entry: entry}}}
	m.enter()
	m.enter()
	if m.Preview == nil || !strings.Contains(m.Preview.Status, "Text file") || !strings.Contains(m.Preview.Lines[0], "hello") {
		t.Fatalf("preview: %+v", m.Preview)
	}
	m.move(1)
	if m.Preview.Scroll != 1 {
		t.Fatalf("scroll: %d", m.Preview.Scroll)
	}
	m.back()
	if m.Preview != nil || !m.InTree {
		t.Fatal("back must return to tree")
	}
}

func TestTUIPreviewBinaryAndSymlink(t *testing.T) {
	root := t.TempDir()
	sdkDir := filepath.Join(root, ".workshop", "example")
	if err := os.MkdirAll(sdkDir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := []byte{0x7f, 'E', 'L', 'F', 2, 1, 0, 0}
	if err := os.WriteFile(filepath.Join(sdkDir, "tool"), binary, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tool", filepath.Join(sdkDir, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	entry, err := sdkcache.ResolveProject(root, "example")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := loadTUIPreview(entry, "tool")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.Status, "Binary file") || !strings.Contains(strings.Join(preview.Lines, " "), "ELF") {
		t.Fatalf("binary: %+v", preview)
	}
	if _, err := loadTUIPreview(entry, "linked"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink allowed: %v", err)
	}
}

func TestTUIPreviewLargeFileIsNotRendered(t *testing.T) {
	root := t.TempDir()
	sdkDir := filepath.Join(root, ".workshop", "example")
	if err := os.MkdirAll(sdkDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "large.txt"), bytes.Repeat([]byte("a"), maxTUIPreviewBytes+1), 0644); err != nil {
		t.Fatal(err)
	}
	entry, err := sdkcache.ResolveProject(root, "example")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := loadTUIPreview(entry, "large.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.Status, "too large") || len(preview.Lines) > 3 {
		t.Fatalf("large: %+v", preview)
	}
}

// inventoryStoreResolver captures Store requests without touching the network.
type inventoryStoreResolver struct {
	requests []source.StoreRequest
	cache    string
	fail     bool
}

func (r *inventoryStoreResolver) Resolve(_ context.Context, request source.StoreRequest, _ sdk.Limits) (*sdk.SDK, error) {
	r.requests = append(r.requests, request)
	if r.fail {
		return nil, errors.New("test download failed")
	}
	root := filepath.Join(r.cache, request.Name, request.Channel, "1")
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(root, "sdk.yaml"), []byte("name: "+request.Name+"\n"), 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(root+".sdk", []byte("archive"), 0644); err != nil {
		return nil, err
	}
	return &sdk.SDK{Name: request.Name, Source: sdk.SourceStore}, nil
}

func TestTUIAutoFetchesMissingStoreSDKAndReusesCache(t *testing.T) {
	project := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project")
	cache := t.TempDir()
	resolver := &inventoryStoreResolver{cache: cache}
	var downloading []string
	_, items, err := loadTUIInventoryWithResolver(project, cache, resolver, func(name string) {
		downloading = append(downloading, name)
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		if item.Name == "rust" && item.Source == "store" {
			found = true
			if item.Status != "cached" || item.Entry.Root == "" {
				t.Fatalf("Store SDK not available: %+v", item)
			}
		}
	}
	if !found || len(resolver.requests) != 1 || len(downloading) != 1 || downloading[0] != "rust" {
		t.Fatalf("items=%+v requests=%+v downloads=%+v", items, resolver.requests, downloading)
	}
	if resolver.requests[0] != (source.StoreRequest{Name: "rust", Channel: "latest/stable", Base: "ubuntu@24.04"}) {
		t.Fatalf("unexpected Store request: %+v", resolver.requests[0])
	}
	_, _, err = loadTUIInventoryWithResolver(project, cache, resolver, nil)
	if err != nil || len(resolver.requests) != 1 {
		t.Fatalf("cached SDK redownloaded: err=%v requests=%+v", err, resolver.requests)
	}
}

func TestTUIAutoFetchFailureDoesNotAbortInventory(t *testing.T) {
	project := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project")
	resolver := &inventoryStoreResolver{cache: t.TempDir(), fail: true}
	_, items, err := loadTUIInventoryWithResolver(project, resolver.cache, resolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Name == "rust" && item.Source == "store" {
			if item.Status != "failed" || !strings.Contains(item.Error, "test download failed") {
				t.Fatalf("missing failure details: %+v", item)
			}
			return
		}
	}
	t.Fatal("Store SDK missing from inventory")
}
