package source_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
)

type fakeStoreResolver struct {
	requests []source.StoreRequest
	err      error
}

func (resolver *fakeStoreResolver) Resolve(_ context.Context, request source.StoreRequest, _ sdk.Limits) (*sdk.SDK, error) {
	resolver.requests = append(resolver.requests, request)
	if resolver.err != nil {
		return nil, resolver.err
	}
	return &sdk.SDK{Name: request.Name, Source: sdk.SourceStore, State: sdk.StateResolved, Channel: "latest/stable"}, nil
}

func TestScanProject(t *testing.T) {
	t.Parallel()

	project := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project")
	result, err := source.Scan(project, sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != source.InputProject {
		t.Errorf("kind = %q, want %q", result.Kind, source.InputProject)
	}
	if len(result.Workshops) != 1 {
		t.Fatalf("workshop count = %d, want 1", len(result.Workshops))
	}
	if len(result.SDKs) != 5 {
		t.Fatalf("SDK count = %d, want 5", len(result.SDKs))
	}

	rust := findSDK(t, result, "rust")
	if rust.Source != sdk.SourceStore || rust.State != sdk.StateNotResolved {
		t.Errorf("rust = source %q state %q, want store NotResolved", rust.Source, rust.State)
	}
	if rust.Channel != "latest/stable" {
		t.Errorf("rust channel = %q, want latest/stable", rust.Channel)
	}

	standard := findSDK(t, result, "standard")
	if standard.State != sdk.StateResolved || standard.Metadata == nil {
		t.Fatalf("standard SDK was not resolved: %#v", standard)
	}
	if len(standard.Hooks) != 5 {
		t.Errorf("standard hook count = %d, want 5", len(standard.Hooks))
	}
}

func TestScanProjectSDKDirectly(t *testing.T) {
	t.Parallel()

	directory := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project", ".workshop", "standard")
	result, err := source.Scan(directory, sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != source.InputProjectSDK {
		t.Errorf("kind = %q, want %q", result.Kind, source.InputProjectSDK)
	}
	if len(result.SDKs) != 1 || result.SDKs[0].Name != "standard" {
		t.Fatalf("unexpected SDKs: %#v", result.SDKs)
	}
}

func TestResolveSDKReferenceUsesDeclaredChannel(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "dev.yaml"), `
name: dev
base: ubuntu@24.04
sdks:
  - name: go
    channel: 1.26/stable
`)
	reference, err := source.ResolveSDKReference(project, "go")
	if err != nil {
		t.Fatal(err)
	}
	if reference.Source != sdk.SourceStore || reference.Channel != "1.26/stable" ||
		len(reference.Definitions) != 1 || reference.Definitions[0] != ".workshop/dev.yaml" {
		t.Fatalf("reference = %#v", reference)
	}
}

func TestResolveSDKReferenceRejectsConflictingChannels(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "one.yaml"), "name: one\nbase: ubuntu@24.04\nsdks:\n  - name: go\n    channel: 1.26/stable\n")
	writeSourceFile(t, filepath.Join(project, ".workshop", "two.yaml"), "name: two\nbase: ubuntu@24.04\nsdks:\n  - name: go\n    channel: 1.27/stable\n")
	if _, err := source.ResolveSDKReference(project, "go"); err == nil || !strings.Contains(err.Error(), "conflicting Workshop declarations") {
		t.Fatalf("error = %v", err)
	}
}

func TestScanDeduplicatesSharedProjectSDK(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "shared", "sdk.yaml"), "name: shared\n")
	writeSourceFile(t, filepath.Join(project, ".workshop", "one.yaml"), "name: one\nbase: ubuntu@24.04\nsdks:\n  - name: project-shared\n")
	writeSourceFile(t, filepath.Join(project, ".workshop", "two.yaml"), "name: two\nbase: ubuntu@24.04\nsdks:\n  - name: project-shared\n")

	result, err := source.Scan(project, sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SDKs) != 1 {
		t.Fatalf("SDK count = %d, want 1", len(result.SDKs))
	}
	if len(result.SDKs[0].Declarations) != 2 {
		t.Fatalf("declaration count = %d, want 2", len(result.SDKs[0].Declarations))
	}
}

func TestScanKeepsStorePlatformsSeparate(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "one.yaml"), "name: one\nbase: ubuntu@22.04\nsdks:\n  - name: rust\n    channel: latest/stable\n")
	writeSourceFile(t, filepath.Join(project, ".workshop", "two.yaml"), "name: two\nbase: ubuntu@24.04\nsdks:\n  - name: rust\n    channel: latest/stable\n")

	result, err := source.Scan(project, sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SDKs) != 2 {
		t.Fatalf("SDK count = %d, want 2 platform-specific entries", len(result.SDKs))
	}
	if result.SDKs[0].Declarations[0].Base == result.SDKs[1].Declarations[0].Base {
		t.Fatalf("store SDK bases were merged: %#v", result.SDKs)
	}
}

func TestScanWithResolverResolvesStoreSDK(t *testing.T) {
	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "dev.yaml"), "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: rust\n")
	resolver := &fakeStoreResolver{}
	result, err := source.ScanWithResolver(context.Background(), project, sdk.DefaultLimits(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	resolved := findSDK(t, result, "rust")
	if resolved.State != sdk.StateResolved || resolved.Source != sdk.SourceStore {
		t.Fatalf("Store SDK was not resolved: %#v", resolved)
	}
	if len(resolver.requests) != 1 || resolver.requests[0] != (source.StoreRequest{Name: "rust", Channel: "stable", Base: "ubuntu@24.04"}) {
		t.Fatalf("resolve requests = %#v", resolver.requests)
	}
	if len(resolved.Declarations) != 1 || resolved.Declarations[0].Workshop != "dev" {
		t.Fatalf("declarations were not retained: %#v", resolved.Declarations)
	}
}

func TestScanWithResolverKeepsProjectResultsWhenStoreResolutionFails(t *testing.T) {
	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "local", "sdk.yaml"), "name: local\n")
	writeSourceFile(t, filepath.Join(project, ".workshop", "dev.yaml"), "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: rust\n  - name: project-local\n")
	resolver := &fakeStoreResolver{err: &source.ResolutionError{
		State:      sdk.StateDownloadFailed,
		Diagnostic: sdk.Diagnostic{Code: "store-download-failed", Severity: sdk.SeverityError, Phase: "download", Message: "service unavailable"},
		Err:        errors.New("service unavailable"),
	}}
	result, err := source.ScanWithResolver(context.Background(), project, sdk.DefaultLimits(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	storeSDK := findSDK(t, result, "rust")
	if storeSDK.State != sdk.StateDownloadFailed || len(storeSDK.Diagnostics) != 1 || storeSDK.Diagnostics[0].Code != "store-download-failed" {
		t.Fatalf("failed Store SDK = %#v", storeSDK)
	}
	projectSDK := findSDK(t, result, "local")
	if projectSDK.State != sdk.StateResolved {
		t.Fatalf("project SDK was not retained: %#v", projectSDK)
	}
}

func TestScanExcludesWorkshopSpecialSDKs(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "local", "sdk.yaml"), "name: local\n")
	writeSourceFile(t, filepath.Join(project, ".workshop", "dev.yaml"), "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: store-sdk\n  - name: project-local\n  - name: try-preview\n  - name: system\n  - name: sketch\n  - name: agent\n")

	resolver := &fakeStoreResolver{}
	result, err := source.ScanWithResolver(context.Background(), project, sdk.DefaultLimits(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string]sdk.Source{"store-sdk": sdk.SourceStore, "local": sdk.SourceProject}
	if len(result.SDKs) != len(wants) {
		t.Fatalf("SDKs = %#v, want only store-sdk and local", result.SDKs)
	}
	for name, want := range wants {
		if got := findSDK(t, result, name).Source; got != want {
			t.Errorf("SDK %q source = %q, want %q", name, got, want)
		}
	}
	if len(resolver.requests) != 1 || resolver.requests[0].Name != "store-sdk" {
		t.Fatalf("Store requests = %#v", resolver.requests)
	}

	inventory, err := source.DiscoverProject(context.Background(), project, sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.SDKs) != 4 {
		t.Fatalf("Explorer SDKs = %#v, want 4", inventory.SDKs)
	}
	if got := findSDK(t, inventory, "preview"); got.Source != sdk.SourceTry {
		t.Fatalf("try SDK = %#v", got)
	}
	if got := findSDK(t, inventory, "sketch"); got.Source != sdk.SourceSketch {
		t.Fatalf("sketch SDK = %#v", got)
	}
}

func TestStoreSDKNamesExcludesSpecialNames(t *testing.T) {
	t.Parallel()
	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "dev.yaml"), "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: go\n  - name: system\n  - name: sketch\n  - name: agent\n  - name: try-preview\n")
	names, err := source.StoreSDKNames(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "go" {
		t.Fatalf("StoreSDKNames = %#v", names)
	}
}

func TestScanInvalidFixtures(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "project-sdks", "invalid-projects")
	for _, name := range []string{"dual-metadata", "dual-hooks", "inline-hooks", "unknown-field", "missing-metadata"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := source.Scan(filepath.Join(root, name), sdk.DefaultLimits()); err == nil {
				t.Fatal("expected scan to fail")
			}
		})
	}
}

func TestScanRejectsProjectSDKEscape(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	project := filepath.Join(parent, "project")
	outside := filepath.Join(parent, "outside")
	writeSourceFile(t, filepath.Join(outside, "sdk.yaml"), "name: escape\n")
	writeSourceFile(t, filepath.Join(project, ".workshop", "dev.yaml"), "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: project-escape\n")
	if err := os.Symlink(outside, filepath.Join(project, ".workshop", "escape")); err != nil {
		t.Fatal(err)
	}

	_, err := source.Scan(project, sdk.DefaultLimits())
	if err == nil {
		t.Fatal("expected scan to reject escaping project SDK")
	}
	var sdkErr *sdk.Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != sdk.CodeUnsafePath {
		t.Fatalf("error = %v, want unsafe-path SDK error", err)
	}
}

func TestScanRejectsUnknownWorkshopField(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "dev.yaml"), "name: dev\nbase: ubuntu@24.04\nunknown: true\n")
	if _, err := source.Scan(project, sdk.DefaultLimits()); err == nil {
		t.Fatal("expected strict Workshop YAML parsing to fail")
	}
}

func TestScanRejectsInvalidChannel(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, ".workshop", "dev.yaml"), "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: rust\n    channel: latest/unsafe\n")
	if _, err := source.Scan(project, sdk.DefaultLimits()); err == nil {
		t.Fatal("expected invalid channel to fail")
	}
}

func findSDK(t *testing.T, result *source.Result, name string) *sdk.SDK {
	t.Helper()
	for i := range result.SDKs {
		if result.SDKs[i].Name == name {
			return &result.SDKs[i]
		}
	}
	t.Fatalf("SDK %q not found", name)
	return nil
}

func writeSourceFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRootWorkshopDefinitions(t *testing.T) {
	for _, filename := range []string{"workshop.yaml", ".workshop.yaml"} {
		t.Run(filename, func(t *testing.T) {
			project := t.TempDir()
			writeSourceFile(t, filepath.Join(project, filename), "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: rust\n    channel: 1.26/stable\n  - name: project-local\n")
			writeSourceFile(t, filepath.Join(project, ".workshop", "local", "sdk.yaml"), "name: local\n")
			result, err := source.Scan(project, sdk.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if result.Kind != source.InputProject || len(result.Workshops) != 1 || result.Workshops[0].Definition != filename || len(result.SDKs) != 2 || len(result.Configurations) != 1 || result.Configurations[0].Definition != filename {
				t.Fatalf("unexpected scan: %+v", result)
			}
			for _, item := range result.SDKs {
				if len(item.Declarations) != 1 || item.Declarations[0].Definition != filename {
					t.Fatalf("missing SDK declaration: %+v", item)
				}
			}
			inventory, err := source.DiscoverProject(context.Background(), project, sdk.DefaultLimits())
			if err != nil || len(inventory.Workshops) != 1 || inventory.Workshops[0].Definition != filename {
				t.Fatalf("inventory=%+v err=%v", inventory, err)
			}
			ref, err := source.ResolveSDKReference(project, "rust")
			if err != nil || ref.Channel != "1.26/stable" || len(ref.Definitions) != 1 || ref.Definitions[0] != filename {
				t.Fatalf("reference=%+v err=%v", ref, err)
			}
			names, err := source.StoreSDKNames(project)
			if err != nil || len(names) != 1 || names[0] != "rust" {
				t.Fatalf("names=%v err=%v", names, err)
			}
		})
	}
}

func TestRootWorkshopWithoutWorkshopDirectory(t *testing.T) {
	project := t.TempDir()
	writeSourceFile(t, filepath.Join(project, "workshop.yaml"), "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: rust\n")
	result, err := source.Scan(project, sdk.DefaultLimits())
	if err != nil || result.Kind != source.InputProject || len(result.Workshops) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestConflictingWorkshopDefinitions(t *testing.T) {
	for _, other := range []string{".workshop.yaml", ".workshop/dev.yaml"} {
		t.Run(other, func(t *testing.T) {
			project := t.TempDir()
			for _, filename := range []string{"workshop.yaml", other} {
				writeSourceFile(t, filepath.Join(project, filename), "name: dev\nbase: ubuntu@24.04\n")
			}
			if _, err := source.Scan(project, sdk.DefaultLimits()); err == nil || !strings.Contains(err.Error(), "conflicting Workshop definitions") {
				t.Fatalf("scan err=%v", err)
			}
			if _, err := source.DiscoverProject(context.Background(), project, sdk.DefaultLimits()); err == nil {
				t.Fatal("Explorer discovery accepted conflicting definitions")
			}
			if _, err := source.ResolveSDKReference(project, "rust"); err == nil {
				t.Fatal("reference accepted conflicting definitions")
			}
			if _, err := source.StoreSDKNames(project); err == nil {
				t.Fatal("cache discovery accepted conflicting definitions")
			}
		})
	}
}
