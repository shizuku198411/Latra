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
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "report", "inventory.json"))
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
		"network-download [Resolved]", "Summary", "Operations: 1", "Unknown Commands: 0",
		"Assessment", "Classification: expected-and-controlled", "Review Priority: 0/100 (info)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text does not contain %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "line1\nline2") {
		t.Error("text contains an unescaped argument newline")
	}
}

func TestWriteTextKeyRiskLocationUsesCLIArguments(t *testing.T) {
	t.Parallel()
	result := fixtureResult()
	hook := &result.SDKs[0].Hooks[0]
	hook.Name = sdk.HookSetupBase
	hook.Path = "hooks/setup-base"
	hook.Parse.Path = "example/hooks/setup-base"
	hook.Analysis.Context = analysis.ContextFor("setup-base")
	operation := &hook.Analysis.Operations[0]
	operation.Command = analysis.Value{Parts: []analysis.ValuePart{{Kind: analysis.PartLiteral, Text: "unknown-tool"}}, Resolution: analysis.Resolved, Literal: "unknown-tool"}
	operation.Location.Path = "example/hooks/setup-base"
	hook.Analysis.Capabilities = nil

	var output bytes.Buffer
	if err := report.WriteTextSummary(&output, result); err != nil {
		t.Fatal(err)
	}
	want := `sdk=example file=hooks/setup-base:1:1 hook=setup-base value="unknown-tool"`
	if !strings.Contains(output.String(), want) {
		t.Errorf("text does not contain %q:\n%s", want, output.String())
	}
}

func TestDocumentRepresentsBinaryFileContentByDigest(t *testing.T) {
	t.Parallel()

	result := fixtureResult()
	result.SDKs[0].Files = append(result.SDKs[0].Files,
		sdk.File{Path: "text.txt", Type: sdk.FileRegular, Content: []byte("hello\n")},
		sdk.File{Path: "binary", Type: sdk.FileRegular, Content: []byte{0xff, 0x00}},
		sdk.File{Path: "z-nul-binary", Type: sdk.FileRegular, Content: []byte{'a', 0x00, 'b'}},
	)
	document := report.NewDocument(result)
	files := document.SDKs[0].Files
	const binaryDigest = "sha3-384:c100c311dfd4de0ca49c25625b170bfdc221fe73ac05033f80b94d7369e03bdab47a810f48f34e1137a349c18c351716"
	if files[0].Content == nil || *files[0].Content != binaryDigest || files[0].ContentEncoding != "sha3-384" || files[0].Digest != binaryDigest {
		t.Errorf("binary file = %#v", files[0])
	}
	if files[2].Content == nil || *files[2].Content != "hello\n" || files[2].ContentEncoding != "utf-8" {
		t.Errorf("text file = %#v", files[2])
	}
	if files[3].Content == nil || files[3].ContentEncoding != "sha3-384" || *files[3].Content != files[3].Digest {
		t.Errorf("NUL-containing file = %#v", files[3])
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
		!slices.Equal(summary.Operations.BySDK[0].OperationKinds, []report.CountedName{{Name: "command-invocation", Count: 1}}) {
		t.Errorf("operation summary = %#v", summary.Operations)
	}
	if summary.Capabilities.Count != 2 || len(summary.Capabilities.BySDK) != 2 ||
		!slices.Equal(summary.Capabilities.BySDK[0].CapabilityNames, []report.CountedName{{Name: "network-download", Count: 1}}) {
		t.Errorf("capability summary = %#v", summary.Capabilities)
	}
	if summary.UnknownCommands.Count != 0 || len(summary.UnknownCommands.BySDK) != 2 {
		t.Errorf("unknown command summary = %#v", summary.UnknownCommands)
	}
	if summary.Diagnostics.Count != 2 || !slices.Equal(summary.Diagnostics.DiagnosticCodes, []report.CountedName{{Name: "syntax-warning", Count: 2}}) {
		t.Errorf("diagnostic summary = %d %#v", summary.Diagnostics.Count, summary.Diagnostics.DiagnosticCodes)
	}
}

func TestDocumentIncludesSDKResolutionDiagnostic(t *testing.T) {
	t.Parallel()

	result := fixtureResult()
	result.SDKs[0].State = sdk.StateDownloadFailed
	result.SDKs[0].Diagnostics = []sdk.Diagnostic{{
		Code: "store-download-failed", Severity: sdk.SeverityError,
		Phase: "download", Message: "service unavailable",
	}}
	document := report.NewDocument(result)
	if document.Summary.SDKs.Resolved != 0 || document.Summary.SDKs.Unresolved != 1 {
		t.Fatalf("SDK summary = %#v", document.Summary.SDKs)
	}
	if document.Summary.Diagnostics.Count != 1 || len(document.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v", document.Diagnostics)
	}
	diagnostic := document.Diagnostics[0]
	if diagnostic.Code != "store-download-failed" || diagnostic.Phase != "download" || diagnostic.SDK != "example" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
	var output bytes.Buffer
	if err := report.WriteTextSummary(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1 unresolved", "store-download-failed", "service unavailable"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("text does not contain %q:\n%s", want, output.String())
		}
	}
	output.Reset()
	if err := report.WriteJSONSummary(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"diagnostics"`, `"store-download-failed"`, `"service unavailable"`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("compact JSON does not contain %q:\n%s", want, output.String())
		}
	}
}

func TestWriteTextSummaryCompactsNonHookFiles(t *testing.T) {
	t.Parallel()

	result := fixtureResult()
	result.SDKs[0].Files = append(result.SDKs[0].Files,
		sdk.File{Path: "sdk.yaml", Type: sdk.FileRegular},
		sdk.File{Path: "bin/tool", Type: sdk.FileRegular},
		sdk.File{Path: "share/config.json", Type: sdk.FileRegular},
	)

	var compact bytes.Buffer
	if err := report.WriteTextSummary(&compact, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hooks/setup-project", "sdk.yaml", "... and more files (2)"} {
		if !strings.Contains(compact.String(), want) {
			t.Errorf("compact text does not contain %q:\n%s", want, compact.String())
		}
	}
	for _, excluded := range []string{"bin/tool", "share/config.json"} {
		if strings.Contains(compact.String(), excluded) {
			t.Errorf("compact text unexpectedly contains %q:\n%s", excluded, compact.String())
		}
	}

	var verbose bytes.Buffer
	if err := report.WriteText(&verbose, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bin/tool", "share/config.json"} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose text does not contain %q:\n%s", want, verbose.String())
		}
	}
}

func TestDocumentSummaryGroupsUnknownCommandsBySDKAndFile(t *testing.T) {
	t.Parallel()

	result := fixtureResult()
	location := result.SDKs[0].Hooks[0].Analysis.Operations[0].Location
	unknown := func(name string) analysis.Operation {
		return analysis.Operation{
			Kind:       analysis.OperationCommand,
			Command:    analysis.Value{Resolution: analysis.Resolved, Literal: name},
			Resolution: analysis.Resolved,
			Location:   location,
		}
	}
	result.SDKs[0].Hooks[0].Analysis.Operations = append(
		result.SDKs[0].Hooks[0].Analysis.Operations,
		unknown("workshop"),
		unknown("workshopctl"),
		unknown("latra-unknown-fixture"),
		analysis.Operation{Kind: analysis.OperationPipeline, Resolution: analysis.Resolved, Location: location, Children: []analysis.Operation{
			unknown("latra-unknown-fixture"), unknown("another-unknown-fixture"),
		}},
	)

	summary := report.NewDocument(result).Summary.UnknownCommands
	if summary.Count != 3 || len(summary.BySDK) != 1 {
		t.Fatalf("unknown command summary = %#v", summary)
	}
	sdkSummary := summary.BySDK[0]
	if sdkSummary.SDKName != "example" || sdkSummary.Count != 3 || len(sdkSummary.Files) != 1 {
		t.Fatalf("SDK unknown command summary = %#v", sdkSummary)
	}
	fileSummary := sdkSummary.Files[0]
	if fileSummary.FilePath != "hooks/setup-project" || fileSummary.Count != 3 ||
		!slices.Equal(fileSummary.CommandNames, []report.CountedName{{Name: "another-unknown-fixture", Count: 1}, {Name: "latra-unknown-fixture", Count: 2}}) {
		t.Errorf("file unknown command summary = %#v", fileSummary)
	}
}

func TestDocumentSummaryCountsRepeatedOperationsAndCapabilities(t *testing.T) {
	t.Parallel()

	result := fixtureResult()
	hook := &result.SDKs[0].Hooks[0]
	hook.Analysis.Operations = append(hook.Analysis.Operations, hook.Analysis.Operations[0])
	hook.Analysis.Capabilities = append(hook.Analysis.Capabilities, hook.Analysis.Capabilities[0])

	summary := report.NewDocument(result).Summary
	if !slices.Equal(summary.Operations.BySDK[0].OperationKinds, []report.CountedName{{Name: "command-invocation", Count: 2}}) {
		t.Errorf("operation counts = %#v", summary.Operations.BySDK[0].OperationKinds)
	}
	if !slices.Equal(summary.Capabilities.BySDK[0].CapabilityNames, []report.CountedName{{Name: "network-download", Count: 2}}) {
		t.Errorf("capability counts = %#v", summary.Capabilities.BySDK[0].CapabilityNames)
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
					Context:    analysis.ContextFor("setup-project"),
					Operations: []analysis.Operation{{ID: "op-0001", Kind: analysis.OperationCommand, Command: command, Arguments: []analysis.Value{target}, Resolution: analysis.Resolved, Location: location}},
					Relations:  []analysis.Relation{},
					Capabilities: []analysis.Capability{{
						Kind: "network-download", RuleID: "command.curl-download", RuleSource: "embedded-default",
						Operation: analysis.OperationCommand, OperationID: "op-0001",
						Target: command, Resolution: analysis.Resolved, Location: location,
					}},
				},
			}},
		}},
	}
}
