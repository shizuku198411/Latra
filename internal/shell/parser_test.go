package shell_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/shizuku198411/Latra/internal/shell"
	"mvdan.cc/sh/v3/syntax"
)

func TestParseBashConstructs(t *testing.T) {
	t.Parallel()

	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "hooks", "bash-constructs.sh"))
	if err != nil {
		t.Fatal(err)
	}
	result := shell.NewParser().Parse(content, "fixture/setup-project")
	if result.Status != shell.StatusParsed {
		t.Fatalf("status = %q, want %q; diagnostics: %#v", result.Status, shell.StatusParsed, result.Diagnostics)
	}
	if result.Program == nil {
		t.Fatal("program is nil")
	}
	if result.Program.Name != "fixture/setup-project" {
		t.Errorf("program name = %q", result.Program.Name)
	}
	if len(result.Diagnostics) != 0 {
		t.Errorf("diagnostics = %#v, want none", result.Diagnostics)
	}

	wantContent, err := os.ReadFile(filepath.Join("..", "..", "testdata", "hooks", "bash-constructs.nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]int
	if err := json.Unmarshal(wantContent, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.NodeTypes, want) {
		t.Errorf("node types = %#v, want %#v", result.NodeTypes, want)
	}
	if !reflect.DeepEqual(result.Source, content) {
		t.Error("source was not retained")
	}
}

func TestLocationOf(t *testing.T) {
	t.Parallel()

	result := shell.NewParser().Parse([]byte("echo hello\nprintf world\n"), "fixture/setup-base")
	if result.Status != shell.StatusParsed {
		t.Fatalf("parse failed: %#v", result.Diagnostics)
	}
	var firstCall *syntax.CallExpr
	syntax.Walk(result.Program, func(node syntax.Node) bool {
		if firstCall == nil {
			firstCall, _ = node.(*syntax.CallExpr)
		}
		return true
	})
	if firstCall == nil {
		t.Fatal("CallExpr not found")
	}
	location := shell.LocationOf("fixture/setup-base", firstCall)
	want := shell.Location{
		Path:        "fixture/setup-base",
		StartLine:   1,
		StartColumn: 1,
		EndLine:     1,
		EndColumn:   11,
	}
	if location != want {
		t.Errorf("location = %#v, want %#v", location, want)
	}
}

func TestParseRecoveredSyntax(t *testing.T) {
	t.Parallel()

	result := shell.NewParser().Parse([]byte("(foo |"), "fixture/setup-base")
	if result.Status != shell.StatusRecovered {
		t.Fatalf("status = %q, want %q; diagnostics: %#v", result.Status, shell.StatusRecovered, result.Diagnostics)
	}
	if !result.Recovered {
		t.Error("Recovered is false")
	}
	if result.Program == nil {
		t.Error("recovered program is nil")
	}
	if len(result.Diagnostics) == 0 {
		t.Error("recovered parse has no diagnostics")
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code != "syntax-recovered" || diagnostic.Location.StartLine == 0 {
			t.Errorf("unexpected diagnostic: %#v", diagnostic)
		}
	}
}

func TestParseSyntaxError(t *testing.T) {
	t.Parallel()

	result := shell.NewParser().Parse([]byte("echo ${unterminated\n"), "fixture/check-health")
	if result.Status != shell.StatusFailed {
		t.Fatalf("status = %q, want %q", result.Status, shell.StatusFailed)
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one", result.Diagnostics)
	}
	diagnostic := result.Diagnostics[0]
	if diagnostic.Code != "syntax-error" || diagnostic.Location.StartLine != 1 || diagnostic.Location.StartColumn == 0 {
		t.Errorf("unexpected diagnostic: %#v", diagnostic)
	}
}

func TestParseInvalidUTF8(t *testing.T) {
	t.Parallel()

	result := shell.NewParser().Parse([]byte{'e', 'c', 'h', 'o', ' ', 0xff}, "fixture/save-state")
	if result.Status != shell.StatusFailed {
		t.Fatalf("status = %q, want %q", result.Status, shell.StatusFailed)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "invalid-utf8" {
		t.Fatalf("unexpected diagnostics: %#v", result.Diagnostics)
	}
	if result.Diagnostics[0].Location.StartColumn != 6 {
		t.Errorf("column = %d, want 6", result.Diagnostics[0].Location.StartColumn)
	}
}
