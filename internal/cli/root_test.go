package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/cli"
)

func runCLI(args []string, stdout, stderr *bytes.Buffer) int {
	return cli.RunWithDependencies(args, stdout, stderr, cli.Dependencies{})
}

func runCLIWithCache(args []string, cache string, stdout, stderr *bytes.Buffer) int {
	return cli.RunWithDependencies(args, stdout, stderr, cli.Dependencies{CacheRoot: cache})
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "help by default",
			wantCode:   0,
			wantStdout: "Usage:\n  latra <command>",
		},
		{
			name:       "explicit help",
			args:       []string{"help"},
			wantCode:   0,
			wantStdout: "Latra statically analyzes",
		},
		{
			name:       "version",
			args:       []string{"version"},
			wantCode:   0,
			wantStdout: "latra dev (commit: unknown, built: unknown)\n",
		},
		{
			name:       "scan requires path",
			args:       []string{"scan"},
			wantCode:   2,
			wantStderr: "latra: scan requires exactly one PROJECT_OR_PROJECT_SDK path",
		},
		{
			name:       "unknown command",
			args:       []string{"unknown"},
			wantCode:   2,
			wantStderr: "latra: unknown command \"unknown\"",
		},
		{
			name:       "version rejects arguments",
			args:       []string{"version", "extra"},
			wantCode:   2,
			wantStderr: "latra: \"version\" does not accept arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runCLI(tt.args, &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("Run() code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunScanProject(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{"scan", "../../testdata/project-sdks/valid-project", "--verbose"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr = %q", code, stderr.String())
	}
	for _, want := range []string{
		"Kind: project",
		"fully-normalized",
		"Source: project",
		"State: Resolved",
		"rust",
		"Source: store",
		"State: NotResolved",
		"share/config.json: regular",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout does not contain %q:\n%s", want, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunScanReportsMalformedHookAsIncomplete(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "malformed")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sdk.yaml"), []byte("name: malformed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "hooks", "setup-base"),
		[]byte("echo ${unterminated\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{"scan", root, "--verbose"}, &stdout, &stderr)

	if code != 1 {
		t.Errorf("Run() code = %d, want 1", code)
	}
	for _, want := range []string{"setup-base", "Failed", "not a valid parameter expansion operator"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout does not contain %q:\n%s", want, stdout.String())
		}
	}
	if !strings.Contains(stderr.String(), "latra: scan incomplete: 1 hook(s) could not be parsed completely") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunScanJSONToStandardOutput(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{
		"scan", "--format", "json", "--no-color", "--quiet",
		"../../testdata/project-sdks/valid-project",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %q", code, stderr.String())
	}
	var document struct {
		SchemaVersion string `json:"schemaVersion"`
		Summary       struct {
			SDKs struct {
				Count int `json:"count"`
			} `json:"sdks"`
		} `json:"summary"`
		SDKs json.RawMessage `json:"sdks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if document.SchemaVersion != "1" || document.Summary.SDKs.Count != 5 || len(document.SDKs) != 0 {
		t.Errorf("document = %#v", document)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunScanJSONFileMatchesStandardOutput(t *testing.T) {
	t.Parallel()

	project := "../../testdata/project-sdks/valid-project"
	var standardOutput bytes.Buffer
	var standardError bytes.Buffer
	if code := runCLI([]string{"scan", project, "--format=json", "--verbose"}, &standardOutput, &standardError); code != 0 {
		t.Fatalf("stdout scan code = %d; stderr = %q", code, standardError.String())
	}

	outputPath := filepath.Join(t.TempDir(), "inventory.json")
	var fileStdout bytes.Buffer
	var fileStderr bytes.Buffer
	if code := runCLI([]string{"scan", project, "--format", "json", "-o", outputPath, "--verbose"}, &fileStdout, &fileStderr); code != 0 {
		t.Fatalf("file scan code = %d; stderr = %q", code, fileStderr.String())
	}
	if fileStdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", fileStdout.String())
	}
	fileOutput, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileOutput, standardOutput.Bytes()) {
		t.Error("file JSON and stdout JSON differ")
	}
}

func TestRunScanJSONFileIsCompactByDefault(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "inventory.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{
		"scan", "../../testdata/project-sdks/valid-project",
		"--format", "json", "--output", outputPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %q", code, stderr.String())
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Summary json.RawMessage `json:"summary"`
		SDKs    json.RawMessage `json:"sdks"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Summary) == 0 || len(document.SDKs) != 0 {
		t.Errorf("compact document has summary=%s sdks=%s", document.Summary, document.SDKs)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRunScanTextIsCompactByDefault(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{"scan", "../../testdata/project-sdks/valid-project"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"Input\n", "Workshops\n", "Summary\n"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout does not contain %q", want)
		}
	}
	if strings.Contains(stdout.String(), "\nSDKs\n") {
		t.Errorf("compact stdout contains SDK details:\n%s", stdout.String())
	}
}

func TestRunScanRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"scan", "project", "--format", "yaml"},
		{"scan", "project", "--unknown"},
		{"scan", "project", "--output", ""},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := runCLI(args, &stdout, &stderr); code != 2 {
			t.Errorf("Run(%q) code = %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("Run(%q) stdout = %q", args, stdout.String())
		}
	}
}

func TestRunDBOverviewAndCapabilityDetail(t *testing.T) {
	t.Parallel()

	var overview bytes.Buffer
	var overviewError bytes.Buffer
	if code := runCLI([]string{"db"}, &overview, &overviewError); code != 0 {
		t.Fatalf("overview code = %d; stderr = %q", code, overviewError.String())
	}
	for _, want := range []string{"Latra Embedded DB", "Capabilities:", "Commands:", "Rules:"} {
		if !strings.Contains(overview.String(), want) {
			t.Errorf("overview does not contain %q:\n%s", want, overview.String())
		}
	}

	var detail bytes.Buffer
	var detailError bytes.Buffer
	if code := runCLI([]string{"db", "capabilities", "network-access"}, &detail, &detailError); code != 0 {
		t.Fatalf("detail code = %d; stderr = %q", code, detailError.String())
	}
	for _, want := range []string{"network-access", "curl [direct]", "command.curl-network"} {
		if !strings.Contains(detail.String(), want) {
			t.Errorf("detail does not contain %q:\n%s", want, detail.String())
		}
	}
}

func TestRunDBJSONReverseLookup(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{"db", "commands", "--capability", "identity-change", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %q", code, stderr.String())
	}
	var document struct {
		Kind     string `json:"kind"`
		Commands []struct {
			Name string `json:"name"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Kind != "capability-catalog" || !slices.ContainsFunc(document.Commands, func(item struct {
		Name string `json:"name"`
	}) bool {
		return item.Name == "sudo"
	}) {
		t.Errorf("document = %#v", document)
	}
}

func TestRunDBFileMatchesStandardOutput(t *testing.T) {
	t.Parallel()

	args := []string{"db", "commands", "curl", "--format=json"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runCLI(args, &stdout, &stderr); code != 0 {
		t.Fatalf("stdout code = %d; stderr = %q", code, stderr.String())
	}
	path := filepath.Join(t.TempDir(), "curl.json")
	var fileStdout bytes.Buffer
	var fileStderr bytes.Buffer
	if code := runCLI(append(args, "--output", path), &fileStdout, &fileStderr); code != 0 {
		t.Fatalf("file code = %d; stderr = %q", code, fileStderr.String())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, stdout.Bytes()) || fileStdout.Len() != 0 {
		t.Error("db file output differs from stdout")
	}
}

func TestRunDBRejectsInvalidQueries(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"db", "rules"}, {"db", "commands", "--command", "curl"}, {"db", "capabilities", "--capability", "network-access"}} {
		var stdout, stderr bytes.Buffer
		if code := runCLI(args, &stdout, &stderr); code != 2 {
			t.Errorf("Run(%q) code = %d, want 2", args, code)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"db", "commands", "not-in-latra-db"}, &stdout, &stderr); code != 1 {
		t.Errorf("missing command code = %d, want 1", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"db", "commands", "--capability", "not-in-latra-db"}, &stdout, &stderr); code != 1 {
		t.Errorf("missing capability filter code = %d, want 1", code)
	}
}

func TestRunScanDoesNotReplaceFileWhenHookParsingFails(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "malformed")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sdk.yaml"), []byte("name: malformed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hooks", "setup-base"), []byte("echo ${unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(outputPath, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{"scan", root, "--format", "json", "-o", outputPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "existing\n" {
		t.Errorf("file content = %q", content)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRunCatPrintsTextAndDescribesBinary(t *testing.T) {
	t.Parallel()

	cache := createCachedSDK(t, "rust", "latest/stable", "54")
	writeCachedFile(t, filepath.Join(cache, "meta", "sdk.yaml"), "name: rust\n")
	if err := os.WriteFile(filepath.Join(cache, "rustup"), []byte{'\x7f', 'E', 'L', 'F', 2, 1, 0}, 0o700); err != nil {
		t.Fatal(err)
	}
	cacheRoot := filepath.Clean(filepath.Join(cache, "..", "..", "..", ".."))

	var stdout, stderr bytes.Buffer
	code := runCLIWithCache([]string{"cat", "rust", "meta/sdk.yaml"}, cacheRoot, &stdout, &stderr)
	if code != 0 || stdout.String() != "name: rust\n" || stderr.Len() != 0 {
		t.Fatalf("text cat code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCLIWithCache([]string{"cat", "rust", "rustup"}, cacheRoot, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("binary cat code=%d stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"Binary file", "Type: ELF 64-bit LSB", "Size: 7 bytes", "SHA3-384:"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("binary output does not contain %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunHookResolvesWorkshopHookLayouts(t *testing.T) {
	t.Parallel()

	cache := createCachedSDK(t, "rust", "latest/stable", "54")
	writeCachedFile(t, filepath.Join(cache, "sdk", "hooks", "check-health"), "#!/bin/bash\necho ok\n")
	writeCachedFile(t, filepath.Join(cache, "hooks", "setup-base"), "#!/bin/bash\necho base\n")
	cacheRoot := filepath.Clean(filepath.Join(cache, "..", "..", "..", ".."))
	var stdout, stderr bytes.Buffer
	code := runCLIWithCache([]string{"hook", "rust", "check-health"}, cacheRoot, &stdout, &stderr)
	if code != 0 || stdout.String() != "#!/bin/bash\necho ok\n" || stderr.Len() != 0 {
		t.Fatalf("hook code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCLIWithCache([]string{"hook", "rust", "setup-base"}, cacheRoot, &stdout, &stderr)
	if code != 0 || stdout.String() != "#!/bin/bash\necho base\n" {
		t.Fatalf("short-layout hook code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunCachedContentRequiresChannelWhenAmbiguous(t *testing.T) {
	t.Parallel()

	stable := createCachedSDK(t, "rust", "latest/stable", "54")
	edge := createCachedSDKAtRoot(t, filepath.Clean(filepath.Join(stable, "..", "..", "..", "..")), "rust", "latest/edge", "55")
	writeCachedFile(t, filepath.Join(stable, "sdk.yaml"), "name: stable\n")
	writeCachedFile(t, filepath.Join(edge, "sdk.yaml"), "name: edge\n")
	cacheRoot := filepath.Clean(filepath.Join(stable, "..", "..", "..", ".."))
	var stdout, stderr bytes.Buffer
	if code := runCLIWithCache([]string{"cat", "rust", "sdk.yaml"}, cacheRoot, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "multiple cached channels") {
		t.Fatalf("ambiguous code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runCLIWithCache([]string{"cat", "rust", "sdk.yaml", "--channel", "latest/edge"}, cacheRoot, &stdout, &stderr); code != 0 || stdout.String() != "name: edge\n" {
		t.Fatalf("selected code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunCatAndHookReadProjectSDK(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeCachedFile(t, filepath.Join(project, ".workshop", "local", "sdk.yaml"), "name: local\n")
	writeCachedFile(t, filepath.Join(project, ".workshop", "local", "hooks", "check-health"), "echo project-ok\n")
	var stdout, stderr bytes.Buffer
	code := runCLIWithCache([]string{"cat", "local", "sdk.yaml", "--project", project}, t.TempDir(), &stdout, &stderr)
	if code != 0 || stdout.String() != "name: local\n" || stderr.Len() != 0 {
		t.Fatalf("project cat code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCLIWithCache([]string{"hook", "local", "check-health", "--project=" + project}, t.TempDir(), &stdout, &stderr)
	if code != 0 || stdout.String() != "echo project-ok\n" || stderr.Len() != 0 {
		t.Fatalf("project hook code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func createCachedSDK(t *testing.T, name, channel, revision string) string {
	t.Helper()
	return createCachedSDKAtRoot(t, t.TempDir(), name, channel, revision)
}

func createCachedSDKAtRoot(t *testing.T, root, name, channel, revision string) string {
	t.Helper()
	directory := filepath.Join(root, name, filepath.FromSlash(channel), revision)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory+".sdk", []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeCachedFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
