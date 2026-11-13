package cli

import (
	"bytes"
	"context"
	"errors"
	"github.com/shizuku198411/Latra/internal/interfaceexposure"
	"github.com/shizuku198411/Latra/internal/interfacegraph"
	"github.com/shizuku198411/Latra/internal/report"
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
	code := RunWithDependencies([]string{"explorer", "--project", t.TempDir()}, &out, &errout, Dependencies{})
	if code != exitError || !strings.Contains(errout.String(), ".workshop") {
		t.Fatalf("code=%d stderr=%q", code, errout.String())
	}
}

func TestTUIRejectsUnknownOption(t *testing.T) {
	var out, errout bytes.Buffer
	if code := RunWithDependencies([]string{"explorer", "--bad"}, &out, &errout, Dependencies{}); code != exitUsage {
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
	if !model.InTree || len(model.Nodes) != 8 || model.Nodes[1].Name != "[Hooks]" || model.Nodes[2].Name != "hooks" {
		t.Fatalf("open SDK: %+v", model)
	}
	model.enter()
	if len(model.Nodes) != 9 || model.Nodes[3].Name != "setup-project" {
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
	if len(model.Nodes) != 8 || model.Nodes[2].Expanded {
		t.Fatalf("collapse hooks: %+v", model.Nodes)
	}
	model.back()
	if model.InTree {
		t.Fatal("Esc must return to SDK list")
	}
}

func TestTUIUncachedSDKShowsInterfaces(t *testing.T) {
	model := tuiExplorer{SDKs: []tuiSDK{{Name: "remote", Status: "not cached", Declarations: []sdk.Declaration{{Workshop: "dev", Definition: ".workshop/dev.yaml", Plugs: map[string]any{"camera": nil}}}}}}
	model.enter()
	if !model.InTree || model.Nodes[1].Name != "SDK declarations: unavailable" {
		t.Fatalf("unexpected model: %+v", model)
	}
	model.enter()
	model.move(1)
	model.enter()
	if model.Preview == nil || !model.Preview.Interface || !strings.Contains(strings.Join(model.Preview.Lines, " "), "Workshop: dev") {
		t.Fatalf("interface preview: %+v", model.Preview)
	}
	model.back()
	if model.Preview != nil || !model.InTree {
		t.Fatal("back must return to interface tree")
	}
}

func selectTUIKind(t *testing.T, m *tuiExplorer, kind string) {
	t.Helper()
	for i, n := range m.Nodes {
		if n.Kind == kind {
			m.SelectedNode = i
			return
		}
	}
	t.Fatalf("missing %s in %+v", kind, m.Nodes)
}
func TestTUIWorkshopConfigurationNavigation(t *testing.T) {
	m := tuiExplorer{Configurations: []source.Configuration{{Name: "dev", Definition: "dev.yaml"}, {Name: "review", Definition: "review.yaml"}}, Topology: []interfacegraph.Graph{{Workshop: "dev", Definition: "dev.yaml", Edges: []interfacegraph.Edge{{Kind: "connection", From: interfacegraph.Endpoint{Reference: "app:data"}, To: interfacegraph.Endpoint{Reference: "system:mount"}, State: "Unresolved"}}}}}
	m.openTopology()
	if len(m.Nodes) != 2 {
		t.Fatalf("workshop list: %+v", m.Nodes)
	}
	if strings.Index(m.Nodes[0].Name, "dev.yaml") != strings.Index(m.Nodes[1].Name, "review.yaml") {
		t.Fatalf("Workshop columns are not aligned: %+v", m.Nodes)
	}
	m.enter()
	selectTUIKind(t, &m, "workshop-interfaces")
	m.enter()
	selectTUIKind(t, &m, "topology-edge")
	m.enter()
	if m.Preview == nil || !strings.Contains(strings.Join(m.Preview.Lines, " "), "Unresolved") {
		t.Fatalf("preview: %+v", m.Preview)
	}
	m.back()
	m.back()
	if m.Nodes[m.SelectedNode].Kind != "workshop-interfaces" {
		t.Fatal("did not restore Workshop selection")
	}
	m.back()
	if m.Nodes[m.SelectedNode].Kind != "workshop" {
		t.Fatal("did not return to Workshop list")
	}
	m.back()
	if m.InTree {
		t.Fatal("did not return to SDK list")
	}
}

func TestTUIWorkshopRootAndSDKListNavigation(t *testing.T) {
	m := tuiExplorer{Configurations: []source.Configuration{{Name: "dev", Definition: "dev.yaml"}, {Name: "review", Definition: "review.yaml"}}, SDKs: []tuiSDK{{Name: "example", Status: "not cached"}}}
	m.openTopology()
	m.History = nil // Startup establishes the Workshop list as the root.
	if !m.InTopology || len(m.Nodes) != 2 {
		t.Fatalf("root: %+v", m)
	}
	m.SelectedNode = 1
	m.openSDKList()
	if m.InTree || len(m.History) != 1 {
		t.Fatal("SDK list did not open")
	}
	m.enter()
	if !m.InTree || m.InTopology || strings.Contains(m.Title, "Workshop:") {
		t.Fatal("SDK tree did not open from SDK list")
	}
	m.back()
	if m.InTree {
		t.Fatal("SDK tree did not return to SDK list")
	}
	m.back()
	if !m.InTopology || m.SelectedNode != 1 || len(m.History) != 0 {
		t.Fatal("Workshop root selection not restored")
	}
}
func TestTUIExposureReviewNavigation(t *testing.T) {
	m := tuiExplorer{Configurations: []source.Configuration{{Name: "dev", Definition: "dev.yaml"}}, Reviews: []interfaceexposure.Review{{Workshop: "dev", Definition: "dev.yaml", Items: []interfaceexposure.Item{{SDK: "app", Name: "token", Kind: "Plug", Fact: "Secret plug declared", Limitation: "Runtime not inspected"}}}}}
	m.openTopology()
	m.enter()
	selectTUIKind(t, &m, "workshop-interfaces")
	m.enter()
	selectTUIKind(t, &m, "exposure-review")
	m.enter()
	if m.Preview == nil || !strings.Contains(strings.Join(m.Preview.Lines, " "), "Runtime not inspected") {
		t.Fatalf("preview: %+v", m.Preview)
	}
}

func TestTUIUnifiedInterfacesShowsDelegationAndOrphans(t *testing.T) {
	graph := interfacegraph.Graph{Definition: "dev.yaml", Edges: []interfacegraph.Edge{{Kind: "connection", State: "Unresolved", From: interfacegraph.Endpoint{SDK: "missing", Name: "plug", Reference: "missing:plug"}, To: interfacegraph.Endpoint{Reference: "system:mount"}}}}
	review := interfaceexposure.Review{Definition: "dev.yaml", Items: []interfaceexposure.Item{{Kind: "Plug", SDK: "app", Name: "cache", Type: "mount", Startup: "Delegated", Target: "provider:cache", ViaTarget: "system:mount", ViaStartup: "Auto-connect candidate"}}}
	m := tuiExplorer{Configurations: []source.Configuration{{Name: "dev", Definition: "dev.yaml"}}, Topology: []interfacegraph.Graph{graph}, Reviews: []interfaceexposure.Review{review}}
	m.openTopology()
	m.enter()
	selectTUIKind(t, &m, "workshop-interfaces")
	m.enter()
	var all []string
	for _, node := range m.Nodes {
		all = append(all, node.Name)
	}
	view := strings.Join(all, "\n")
	for _, want := range []string{"system:mount", "app:cache", "via provider:cache", "[Unresolved configuration]", "missing:plug"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q: %s", want, view)
		}
	}
	for i, node := range m.Nodes {
		if node.Review != nil && node.Review.SDK == "app" {
			m.SelectedNode = i
			break
		}
	}
	m.enter()
	if m.Preview == nil || !strings.Contains(strings.Join(m.Preview.Lines, "\n"), "Delegated plug candidate: system:mount") {
		t.Fatalf("preview: %+v", m.Preview)
	}
}

func TestTUIWorkshopAssessmentUsesScanReport(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	m := tuiExplorer{Configurations: []source.Configuration{{Name: "dev", Definition: "dev.yaml", SDKs: []source.ConfigurationSDK{{Name: "example", Order: 0}}}}, Scanning: true}
	m.openTopology()
	m.enter()
	selectTUIKind(t, &m, "workshop-assessment")
	m.enter()
	if m.Preview != nil || m.Message != "Scan in progress" {
		t.Fatalf("pending scan: %+v", m)
	}
	document := report.NewDocument(&source.Result{Kind: source.InputProject, SDKs: []sdk.SDK{{Name: "example", State: sdk.StateResolved, Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 0}}}}})
	m.finishScan(&document, nil)
	m.enter()
	if m.Preview == nil {
		t.Fatal("assessment preview did not open")
	}
	var expected bytes.Buffer
	if err := report.WriteSDKAssessmentsWithOptions(&expected, document.Assessment.BySDK, report.TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.Preview.Lines, "\n"); got != strings.Trim(expected.String(), "\n") {
		t.Fatalf("assessment mismatch:\n%s\nexpected:\n%s", got, expected.String())
	}
	m.back()
	if m.Preview != nil || m.Nodes[m.SelectedNode].Kind != "workshop-assessment" {
		t.Fatal("assessment did not return to Workshop")
	}
}

func TestTUIWorkshopAssessmentFiltersSDKVariantsWithoutChangingScores(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	items := []sdk.SDK{
		{Name: "same", Source: sdk.SourceStore, Channel: "stable", State: sdk.StateResolved, Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 0}}},
		{Name: "same", Source: sdk.SourceStore, Channel: "edge", State: sdk.StateNotResolved, Declarations: []sdk.Declaration{{Definition: "other.yaml", Order: 0}}},
		{Name: "other", State: sdk.StateNotResolved, Declarations: []sdk.Declaration{{Definition: "other.yaml", Order: 1}}},
	}
	document := report.NewDocument(&source.Result{Kind: source.InputProject, SDKs: items})
	config := source.Configuration{Name: "dev", Definition: "dev.yaml", SDKs: []source.ConfigurationSDK{{Name: "same", Order: 0}}}
	m := tuiExplorer{Scan: &document, InTopology: true, Configurations: []source.Configuration{config}}
	m.openAssessment()
	if m.Preview == nil {
		t.Fatal("assessment unavailable")
	}
	output := strings.Join(m.Preview.Lines, "\n")
	if strings.Count(output, "    same:") != 1 || strings.Contains(output, "    other:") {
		t.Fatalf("incorrect SDK filtering: %s", output)
	}
	if !strings.HasPrefix(output, "  By SDK:") || strings.Contains(output, "Classification:") {
		t.Fatalf("project assessment was shown: %s", output)
	}
	if len(document.Assessment.BySDK) != 3 {
		t.Fatal("original assessment changed")
	}
}

func TestTUIAssessmentColorsMatchCLIAndSanitizeEvidence(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	document := report.NewDocument(&source.Result{Kind: source.InputProject, SDKs: []sdk.SDK{{Name: "example", State: sdk.StateResolved}}})
	document.Assessment.ReviewPriority.Level = "high"
	document.Assessment.ReviewPriority.Score = 70
	m := tuiExplorer{Scan: &document}
	m.openAssessment()
	if m.Preview == nil || !m.Preview.Colored {
		t.Fatal("colored assessment missing")
	}
	var expected bytes.Buffer
	if err := report.WriteAssessmentWithOptions(&expected, document.Assessment, report.TextOptions{Color: true}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.Preview.Lines, "\n"); got != strings.Trim(expected.String(), "\n") || !strings.Contains(got, "\x1b[31m70/100") {
		t.Fatalf("unexpected colors: %q", got)
	}
	document.Assessment.Classification = "bad\x1b]0;unsafe\a"
	m.openAssessment()
	if strings.Contains(strings.Join(m.Preview.Lines, "\n"), "\x1b]0;") {
		t.Fatal("untrusted terminal escape retained")
	}
}
func TestTUIWorkshopSDKUsesDeclarationIdentity(t *testing.T) {
	root := t.TempDir()
	sdkDir := filepath.Join(root, ".workshop", "example")
	if err := os.MkdirAll(sdkDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdkDir, "sdk.yaml"), []byte("name: example"), 0644); err != nil {
		t.Fatal(err)
	}
	entry, err := sdkcache.ResolveProject(root, "example")
	if err != nil {
		t.Fatal(err)
	}
	m := tuiExplorer{SDKs: []tuiSDK{{Name: "example", Source: "project", Status: "local", Entry: entry, Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 1}}}, {Name: "example", Source: "store", Status: "not cached", Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 0}}}}, Configurations: []source.Configuration{{Name: "dev", Definition: "dev.yaml", SDKs: []source.ConfigurationSDK{{Name: "example", Order: 0}, {Name: "project-example", Order: 1}, {Name: "system", Order: 2, Slots: map[string]any{"key": map[string]any{"interface": "secret"}}}}}}}
	m.openTopology()
	m.enter()
	selectTUIKind(t, &m, "workshop-sdk")
	if m.Nodes[m.SelectedNode].Index != 1 {
		t.Fatal("wrong SDK variant")
	}
	m.move(1)
	m.enter()
	if m.InTopology || m.SelectedSDK != 0 {
		t.Fatal("did not open project SDK tree")
	}
	m.back()
	if m.Nodes[m.SelectedNode].Index != 0 {
		t.Fatal("SDK selection not restored")
	}
	selectTUIKind(t, &m, "workshop-system")
	m.enter()
	selectTUIKind(t, &m, "interface-group")
	m.move(1) // Slots
	m.enter()
	m.move(1)
	m.enter()
	if m.Preview == nil || !strings.Contains(strings.Join(m.Preview.Lines, " "), "secret") {
		t.Fatalf("system preview: %+v", m.Preview)
	}
	m.back()
	m.back()
	if m.Nodes[m.SelectedNode].Kind != "workshop-system" {
		t.Fatal("system did not return to Workshop")
	}
}

func TestTUIWorkshopSDKColumnsAligned(t *testing.T) {
	m := tuiExplorer{SDKs: []tuiSDK{
		{Name: "docker-ce", Source: "store", Status: "cached", Channel: "latest/stable", Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 0}}},
		{Name: "act-base", Source: "project", Status: "local", Channel: "edge", Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 1}}},
	}, Configurations: []source.Configuration{{Name: "dev", Definition: "dev.yaml", SDKs: []source.ConfigurationSDK{{Name: "docker-ce", Order: 0}, {Name: "project-act-base", Order: 1}}}}}
	m.openTopology()
	m.enter()
	a, b := m.Nodes[1].Name, m.Nodes[2].Name
	for _, pair := range [][2]string{{"store", "project"}, {"cached", "local"}, {"latest/stable", "edge"}} {
		if strings.Index(a, pair[0]) != strings.Index(b, pair[1]) {
			t.Fatalf("columns do not align: %q and %q", a, b)
		}
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
	for i, node := range m.Nodes {
		if node.Path == "notes.txt" {
			m.SelectedNode = i
			break
		}
	}
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

func TestTUIGroupedSectionsAndNavigation(t *testing.T) {
	root := t.TempDir()
	sdkDir := filepath.Join(root, ".workshop", "example")
	for _, dir := range []string{"meta", "sdk/hooks", "sdk/bin"} {
		if err := os.MkdirAll(filepath.Join(sdkDir, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, filename := range []string{"meta/sdk.yaml", "sdk/hooks/setup-base", "sdk/bin/tool", "README.md", sdkcache.ManifestPath} {
		if err := os.WriteFile(filepath.Join(sdkDir, filename), []byte("hello"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := sdkcache.ResolveProject(root, "example")
	if err != nil {
		t.Fatal(err)
	}
	m := tuiExplorer{SDKs: []tuiSDK{{Name: "example", Status: "local", Entry: entry}}}
	m.enter()
	names := make([]string, 0, len(m.Nodes))
	for _, n := range m.Nodes {
		names = append(names, n.Name)
	}
	expected := []string{"[SDK Metadata]", "meta", "[Hooks]", "sdk", "[Interfaces]", "SDK declarations: unavailable", "Plugs (0)", "Slots (0)", "[Files]", "sdk", "README.md"}
	if strings.Join(names, "|") != strings.Join(expected, "|") {
		t.Fatalf("sections: %v", names)
	}
	if m.SelectedNode != 1 {
		t.Fatalf("selection=%d", m.SelectedNode)
	}
	m.move(1) // skip Hooks header
	if m.SelectedNode != 3 {
		t.Fatalf("selection=%d", m.SelectedNode)
	}
	m.enter() // SDK under Hooks
	if m.Nodes[4].Path != "sdk/hooks" {
		t.Fatalf("hook branch: %+v", m.Nodes)
	}
	m.enter() // collapse
	m.move(1) // skip Interfaces headers
	m.move(1) // Slots
	m.move(1) // skip Files header
	if m.Nodes[m.SelectedNode].Group != "files" {
		t.Fatalf("selection=%+v", m.Nodes[m.SelectedNode])
	}
	m.enter()
	for _, n := range m.Nodes {
		if n.Group == "files" && n.Path == "sdk/hooks" {
			t.Fatalf("hooks leaked into files: %+v", m.Nodes)
		}
	}
}

func TestExplorerScanRetainsReport(t *testing.T) {
	project := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project")
	document, err := scanExplorer(project, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if document == nil || document.Input.Kind != source.InputProject || len(document.SDKs) == 0 {
		t.Fatalf("missing scan report: %+v", document)
	}
	model := tuiExplorer{}
	model.Scanning = true
	model.finishScan(document, nil)
	if model.Scanning || model.Scan != document || model.ScanStatus != "Scan complete" {
		t.Fatalf("scan not retained: %+v", model)
	}
}

func TestExplorerScanFailurePreservesLastReport(t *testing.T) {
	previous := &report.Document{}
	model := tuiExplorer{Scan: previous, Scanning: true}
	model.finishScan(nil, errors.New("store unavailable"))
	if model.Scanning || model.Scan != previous || !strings.Contains(model.ScanStatus, "store unavailable") {
		t.Fatalf("failed scan lost previous result: %+v", model)
	}
	if document, err := scanExplorer(filepath.Join(t.TempDir(), "missing"), nil); document != nil || err == nil {
		t.Fatalf("expected failed scan without a report: document=%v err=%v", document, err)
	}
}

func TestExplorerScanIncompleteRetainsReport(t *testing.T) {
	document := &report.Document{}
	model := tuiExplorer{Scanning: true}
	model.finishScan(document, errors.New("one hook could not be parsed"))
	if model.Scanning || model.Scan != document || !strings.Contains(model.ScanStatus, "Scan incomplete") {
		t.Fatalf("incomplete scan not retained: %+v", model)
	}
}

func TestTUIInventorySpecialSDKVisibility(t *testing.T) {
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".workshop"), 0o755); err != nil {
		t.Fatal(err)
	}
	definition := "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: system\n  - name: agent\n  - name: sketch\n  - name: try-preview\n"
	if err := os.WriteFile(filepath.Join(project, ".workshop", "dev.yaml"), []byte(definition), 0o644); err != nil {
		t.Fatal(err)
	}
	_, items, err := loadTUIInventory(project, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("SDK list = %#v, want try and sketch", items)
	}
	for _, item := range items {
		if item.Status != "unsupported" || (item.Source != "try" && item.Source != "sketch") {
			t.Fatalf("unexpected SDK: %#v", item)
		}
	}
}
