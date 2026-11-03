package sdkstore

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
)

func TestResolveDownloadsExtractsAndAnalyzesStoreSDK(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"meta/sdk.yaml":        "name: rust\nbase: ubuntu@24.04\n",
		"sdk/hooks/setup-base": "#!/bin/bash\ncurl https://example.invalid/install.sh\n",
	})
	digest := sha3.Sum384(archive)
	hexdigest := hex.EncodeToString(digest[:])

	var resolveRequestBody resolveRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/revisions/resolve", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("resolve method = %s", request.Method)
		}
		if err := json.NewDecoder(request.Body).Decode(&resolveRequestBody); err != nil {
			t.Error(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(map[string]any{"package-results": []any{
			map[string]any{"instance-key": "latra-0", "status": "error", "error": map[string]any{"code": "revision-not-found", "message": "not found"}},
			map[string]any{"instance-key": "latra-1", "status": "ok", "name": "rust", "id": "package-id", "result": map[string]any{
				"channel":  map[string]any{"effective-channel": "latest/stable"},
				"revision": map[string]any{"revision": 42, "download": map[string]any{"size": len(archive), "sha3-384": hexdigest}},
			}},
		}})
	})
	mux.HandleFunc("/api/v1/sdks/download/package-id_42.sdk", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := NewClient(Config{BaseURL: server.URL, CacheDir: filepath.Join(t.TempDir(), "latra_cache"), Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Resolve(context.Background(), source.StoreRequest{Name: "rust", Channel: "latest/stable", Base: "ubuntu@24.04"}, sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Source != sdk.SourceStore || result.State != sdk.StateResolved || result.Channel != "latest/stable" {
		t.Fatalf("unexpected SDK result: %#v", result)
	}
	if len(result.Hooks) != 1 || string(result.Hooks[0].Content) == "" {
		t.Fatalf("hooks were not analyzed: %#v", result.Hooks)
	}
	if result.Digest != hexdigest {
		t.Errorf("digest = %q, want %q", result.Digest, hexdigest)
	}
	if len(resolveRequestBody.Packages) != 4 {
		t.Fatalf("platform requests = %d, want 4", len(resolveRequestBody.Packages))
	}
	wantPlatforms := []platform{
		{Name: "ubuntu", Channel: "24.04", Architecture: "amd64"},
		{Name: "all", Channel: "all", Architecture: "amd64"},
		{Name: "ubuntu", Channel: "24.04", Architecture: "all"},
		{Name: "all", Channel: "all", Architecture: "all"},
	}
	for index, want := range wantPlatforms {
		if got := resolveRequestBody.Packages[index].Platform; got != want {
			t.Errorf("platform[%d] = %#v, want %#v", index, got, want)
		}
	}
}

func TestExtractArchiveRejectsTraversal(t *testing.T) {
	archive := testArchive(t, map[string]string{"../outside": "unsafe"})
	archivePath := filepath.Join(t.TempDir(), "unsafe.sdk")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := extractArchive(archivePath, target, sdk.DefaultLimits()); err == nil {
		t.Fatal("expected archive traversal to be rejected")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(target), "outside")); !os.IsNotExist(err) {
		t.Fatalf("outside path was created: %v", err)
	}
}

func TestDownloadRejectsDigestMismatch(t *testing.T) {
	archive := testArchive(t, map[string]string{"meta/sdk.yaml": "name: rust\n"})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Write(archive)
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, CacheDir: t.TempDir(), Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	err = client.download(context.Background(), resolvedArchive{
		Name: "rust", PackageID: "id", Revision: 1, Size: int64(len(archive)), Digest: string(bytes.Repeat([]byte{'0'}, sha3.New384().Size()*2)),
	}, filepath.Join(t.TempDir(), "rust.sdk"))
	if err == nil {
		t.Fatal("expected digest mismatch")
	}
	var resolutionError *source.ResolutionError
	if !errors.As(err, &resolutionError) || resolutionError.State != sdk.StateDigestMismatch || resolutionError.Diagnostic.Code != "store-artifact-digest-mismatch" {
		t.Fatalf("error = %#v, want digest mismatch resolution error", err)
	}
}

func TestResolveReportsUnsupportedPlatform(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		results := make([]any, 0, 4)
		for index := range 4 {
			results = append(results, map[string]any{
				"instance-key": "latra-" + fmt.Sprint(index), "status": "error", "name": "rust",
				"error": map[string]any{"code": "revision-not-found", "message": "no compatible revision"},
			})
		}
		json.NewEncoder(writer).Encode(map[string]any{"package-results": results})
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, CacheDir: t.TempDir(), Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Resolve(context.Background(), source.StoreRequest{Name: "rust", Channel: "stable", Base: "ubuntu@24.04"}, sdk.DefaultLimits())
	var resolutionError *source.ResolutionError
	if !errors.As(err, &resolutionError) || resolutionError.State != sdk.StateUnsupportedPlatform || resolutionError.Diagnostic.Code != "store-sdk-unsupported-platform" {
		t.Fatalf("error = %#v, want unsupported platform resolution error", err)
	}
}

func testArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var tarBuffer bytes.Buffer
	writer := tar.NewWriter(&tarBuffer)
	for name, content := range files {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(tarBuffer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}
