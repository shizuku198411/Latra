package report_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
	"github.com/shizuku198411/Latra/internal/source"
)

func TestWriteJSONGolden(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := report.WriteJSON(&output, fixtureResult()); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), want) {
		t.Errorf("JSON output differs from golden\n--- got ---\n%s\n--- want ---\n%s", output.Bytes(), want)
	}
}

func TestWriteFileMatchesStandardOutput(t *testing.T) {
	t.Parallel()

	var standardOutput bytes.Buffer
	if err := report.Write(&standardOutput, report.FormatJSON, fixtureResult()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := report.WriteFile(path, report.FormatJSON, fixtureResult()); err != nil {
		t.Fatal(err)
	}
	fileOutput, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileOutput, standardOutput.Bytes()) {
		t.Error("file and standard output differ")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Errorf("file permissions = %o, want 600", permissions)
	}
}

func TestWriteFilePreservesExistingFileOnSerializationFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(path, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteFile(path, report.Format("unsupported"), fixtureResult()); err == nil {
		t.Fatal("expected serialization error")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "existing\n" {
		t.Errorf("content = %q", content)
	}
}

func TestWriteTextIncludesInventoryDetailsAndEscapesControls(t *testing.T) {
	t.Parallel()

	result := fixtureResult()
	result.SDKs[0].Hooks[0].Analysis.Operations[0].Arguments[0].Literal = "line1\nline2\x1b"
	var output bytes.Buffer
	if err := report.WriteText(&output, result); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"Context: root=false project=true interfaces=true state=false",
		`command="curl"`, `args=["line1\nline2\x1b"]`,
		"network-download [Resolved]", "Summary", "Operations: 1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text does not contain %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "line1\nline2") {
		t.Error("text contains an unescaped argument newline")
	}
}

func TestDocumentEncodesFileContentWithoutDataLoss(t *testing.T) {
	t.Parallel()

	result := fixtureResult()
	result.SDKs[0].Files = append(result.SDKs[0].Files,
		sdk.File{Path: "text.txt", Type: sdk.FileRegular, Content: []byte("hello\n")},
		sdk.File{Path: "binary", Type: sdk.FileRegular, Content: []byte{0xff, 0x00}},
	)
	document := report.NewDocument(result)
	files := document.SDKs[0].Files
	if files[0].Content == nil || *files[0].Content != "/wA=" || files[0].ContentEncoding != "base64" {
		t.Errorf("binary file = %#v", files[0])
	}
	if files[2].Content == nil || *files[2].Content != "hello\n" || files[2].ContentEncoding != "utf-8" {
		t.Errorf("text file = %#v", files[2])
	}
}

func TestDocumentSummaryDeduplicatesDetectedItems(t *testing.T) {
	t.Parallel()

	result := fixtureResult()
	result.SDKs[0].Hooks[0].Parse.Diagnostics = []shell.Diagnostic{{Code: "syntax-warning"}}
	other := result.SDKs[0]
	other.Name = "other"
	other.State = sdk.StateNotResolved
	result.SDKs = append(result.SDKs, other)
	summary := report.NewDocument(result).Summary
	if summary.SDKs.Count != 2 ||
		!slices.Equal(summary.SDKs.SDKNames.Resolved, []string{"example"}) ||
		!slices.Equal(summary.SDKs.SDKNames.Unresolved, []string{"other"}) ||
		summary.SDKs.Resolved != 1 || summary.SDKs.Unresolved != 1 {
		t.Errorf("SDK summary = %#v", summary.SDKs)
	}
	if summary.Files.Count != 2 || len(summary.Files.BySDK) != 2 ||
		!slices.Equal(summary.Files.BySDK[0].FilePaths, []string{"hooks/setup-project"}) ||
		!slices.Equal(summary.Files.BySDK[1].FilePaths, []string{"hooks/setup-project"}) {
		t.Errorf("file summary = %#v", summary.Files)
	}
	if summary.Hooks.Count != 2 || len(summary.Hooks.BySDK) != 2 ||
		!slices.Equal(summary.Hooks.BySDK[0].HookNames, []string{"setup-project"}) {
		t.Errorf("hook summary = %#v", summary.Hooks)
	}
	if summary.Operations.Count != 2 || len(summary.Operations.BySDK) != 2 ||
		!slices.Equal(summary.Operations.BySDK[0].OperationKinds, []string{"command-invocation"}) {
		t.Errorf("operation summary = %#v", summary.Operations)
	}
	if summary.Capabilities.Count != 2 || len(summary.Capabilities.BySDK) != 2 ||
		!slices.Equal(summary.Capabilities.BySDK[0].CapabilityNames, []string{"network-download"}) {
		t.Errorf("capability summary = %#v", summary.Capabilities)
	}
	if summary.Diagnostics.Count != 2 || !slices.Equal(summary.Diagnostics.DiagnosticCodes, []string{"syntax-warning"}) {
		t.Errorf("diagnostic summary = %d %#v", summary.Diagnostics.Count, summary.Diagnostics.DiagnosticCodes)
	}
}

func fixtureResult() *source.Result {
	location := shell.Location{Path: "example/hooks/setup-project", StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 34}
	command := analysis.Value{Parts: []analysis.ValuePart{{Kind: analysis.PartLiteral, Text: "curl"}}, Resolution: analysis.Resolved, Literal: "curl"}
	target := analysis.Value{Parts: []analysis.ValuePart{{Kind: analysis.PartQuotedLiteral, Text: "https://example.invalid/tool"}}, Resolution: analysis.Resolved, Literal: "https://example.invalid/tool"}
	return &source.Result{
		Kind: source.InputProjectSDK, Root: "/fixture/example",
		SDKs: []sdk.SDK{{
			Name: "example", Source: sdk.SourceProject, State: sdk.StateResolved,
			Root: "/fixture/example", Digest: "sha3-384:sdk", MetadataPath: "sdk.yaml",
			Metadata: &sdk.Metadata{Name: "example", Version: "1.0.0"},
			Files:    []sdk.File{{Path: "hooks/setup-project", Type: sdk.FileRegular, Mode: 0o644, Size: 34, Digest: "sha3-384:hook"}},
			Hooks: []sdk.Hook{{
				Name: sdk.HookSetupProject, Path: "hooks/setup-project", Digest: "sha3-384:hook", Size: 34,
				Parse: &shell.Result{Path: location.Path, Status: shell.StatusParsed, NodeTypes: map[string]int{"CallExpr": 1, "File": 1}},
				Analysis: &analysis.Result{
					Context:      analysis.ContextFor("setup-project"),
					Operations:   []analysis.Operation{{Kind: analysis.OperationCommand, Command: command, Arguments: []analysis.Value{target}, Resolution: analysis.Resolved, Location: location}},
					Capabilities: []analysis.Capability{{Kind: "network-download", Operation: analysis.OperationCommand, Target: command, Resolution: analysis.Resolved, Location: location}},
				},
			}},
		}},
	}
}
