package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/cli"
)

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
			code := cli.Run(tt.args, &stdout, &stderr)

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
	code := cli.Run([]string{"scan", "../../testdata/project-sdks/valid-project"}, &stdout, &stderr)

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
	code := cli.Run([]string{"scan", root}, &stdout, &stderr)

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
	code := cli.Run([]string{
		"scan", "--format", "json", "--no-color", "--quiet",
		"../../testdata/project-sdks/valid-project",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d; stderr = %q", code, stderr.String())
	}
	var document struct {
		SchemaVersion string `json:"schemaVersion"`
		SDKs          []struct {
			Name string `json:"name"`
		} `json:"sdks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if document.SchemaVersion != "1" || len(document.SDKs) != 5 {
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
	if code := cli.Run([]string{"scan", project, "--format=json"}, &standardOutput, &standardError); code != 0 {
		t.Fatalf("stdout scan code = %d; stderr = %q", code, standardError.String())
	}

	outputPath := filepath.Join(t.TempDir(), "inventory.json")
	var fileStdout bytes.Buffer
	var fileStderr bytes.Buffer
	if code := cli.Run([]string{"scan", project, "--format", "json", "-o", outputPath}, &fileStdout, &fileStderr); code != 0 {
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

func TestRunScanRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"scan", "project", "--format", "yaml"},
		{"scan", "project", "--unknown"},
		{"scan", "project", "--output", ""},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := cli.Run(args, &stdout, &stderr); code != 2 {
			t.Errorf("Run(%q) code = %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("Run(%q) stdout = %q", args, stdout.String())
		}
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
	code := cli.Run([]string{"scan", root, "--format", "json", "-o", outputPath}, &stdout, &stderr)
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
