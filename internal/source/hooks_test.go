package source_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
	"github.com/shizuku198411/Latra/internal/source"
)

func TestParseHooks(t *testing.T) {
	t.Parallel()

	project := filepath.Join("..", "..", "testdata", "project-sdks", "valid-project")
	result, err := source.Scan(project, sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := source.ParseHooks(result, shell.NewParser()); err != nil {
		t.Fatal(err)
	}

	parsedHooks := 0
	for _, item := range result.SDKs {
		for _, hook := range item.Hooks {
			parsedHooks++
			if hook.Parse == nil || hook.Parse.Program == nil {
				t.Errorf("%s/%s has no AST", item.Name, hook.Name)
				continue
			}
			if hook.Parse.Status != shell.StatusParsed {
				t.Errorf("%s/%s status = %q", item.Name, hook.Name, hook.Parse.Status)
			}
			if hook.Analysis == nil || hook.Analysis.Context.Name != string(hook.Name) {
				t.Errorf("%s/%s has no analysis context: %#v", item.Name, hook.Name, hook.Analysis)
			}
		}
	}
	if parsedHooks != 8 {
		t.Errorf("parsed hook count = %d, want 8", parsedHooks)
	}
}

func TestParseHooksResolvesSDKLocalInclude(t *testing.T) {
	t.Parallel()

	result := &source.Result{SDKs: []sdk.SDK{{
		Name: "fixture", State: sdk.StateResolved,
		Files: []sdk.File{{Path: "lib/payload.sh", Type: sdk.FileRegular, Mode: fs.FileMode(0o644), Size: 48, Digest: "payload-digest", Content: []byte("printf payload > /project/.github/workflows/ci.yml\n")}},
		Hooks: []sdk.Hook{{Name: sdk.HookSetupProject, Path: "hooks/setup-project", Content: []byte("source \"$SDK/lib/payload.sh\"\n")}},
	}}}
	if err := source.ParseHooks(result, shell.NewParser()); err != nil {
		t.Fatal(err)
	}
	hook := result.SDKs[0].Hooks[0]
	if hook.Analysis == nil {
		t.Fatal("missing include analysis")
	}
	var controlWrite, dynamic bool
	for _, capability := range hook.Analysis.Capabilities {
		controlWrite = controlWrite || capability.Kind == "project-write" && capability.NormalizedTarget.Literal == "/project/.github/workflows/ci.yml"
		dynamic = dynamic || capability.Kind == "dynamic-execution"
	}
	if !controlWrite || dynamic {
		t.Errorf("resolved include capabilities: %#v", hook.Analysis.Capabilities)
	}
	var included bool
	for _, relation := range hook.Analysis.Relations {
		included = included || relation.Kind == analysis.RelationInclude && relation.Digest == "payload-digest"
	}
	if !included {
		t.Errorf("missing include relation: %#v", hook.Analysis.Relations)
	}
}

func TestParseHooksStopsIncludeCycle(t *testing.T) {
	t.Parallel()

	result := &source.Result{SDKs: []sdk.SDK{{
		Name: "fixture", State: sdk.StateResolved,
		Files: []sdk.File{
			{Path: "lib/a.sh", Type: sdk.FileRegular, Size: 18, Digest: "a", Content: []byte("source $SDK/lib/b.sh\n")},
			{Path: "lib/b.sh", Type: sdk.FileRegular, Size: 18, Digest: "b", Content: []byte("source $SDK/lib/a.sh\n")},
		},
		Hooks: []sdk.Hook{{Name: sdk.HookSetupProject, Path: "hooks/setup-project", Content: []byte("source $SDK/lib/a.sh\n")}},
	}}}
	if err := source.ParseHooks(result, shell.NewParser()); err != nil {
		t.Fatal(err)
	}
	var cycle bool
	for _, diagnostic := range result.SDKs[0].Diagnostics {
		cycle = cycle || diagnostic.Code == "include-cycle"
	}
	if !cycle {
		t.Errorf("missing cycle diagnostic: %#v", result.SDKs[0].Diagnostics)
	}
}

func TestParseHooksBuildsStateLifecycleRelation(t *testing.T) {
	t.Parallel()

	result := &source.Result{SDKs: []sdk.SDK{{
		Name: "fixture", State: sdk.StateResolved,
		Hooks: []sdk.Hook{
			{Name: sdk.HookSaveState, Path: "hooks/save-state", Content: []byte("cp /project/tool.sh \"$SDK_STATE_DIR/tool.sh\"\n")},
			{Name: sdk.HookRestoreState, Path: "hooks/restore-state", Content: []byte("cp \"$SDK_STATE_DIR/tool.sh\" /project/scripts/tool.sh\n")},
		},
	}}}
	if err := source.ParseHooks(result, shell.NewParser()); err != nil {
		t.Fatal(err)
	}
	relations := result.SDKs[0].LifecycleRelations
	if len(relations) != 1 || relations[0].Kind != "state-flow" || relations[0].StatePath.Literal != "/tool.sh" || relations[0].Resolution != analysis.PartiallyResolved {
		t.Fatalf("lifecycle relations = %#v", relations)
	}
	if relations[0].Limitation == "" {
		t.Error("state relation must describe revision/content limitation")
	}
}

func TestParseHooksReportsIncompleteSource(t *testing.T) {
	t.Parallel()

	result := &source.Result{SDKs: []sdk.SDK{{
		Name: "fixture",
		Hooks: []sdk.Hook{{
			Name:    sdk.HookSetupBase,
			Path:    "hooks/setup-base",
			Content: []byte("echo ${unterminated\n"),
		}},
	}}}
	err := source.ParseHooks(result, shell.NewParser())
	if err == nil {
		t.Fatal("expected incomplete parse error")
	}
	if result.SDKs[0].Hooks[0].Parse == nil || result.SDKs[0].Hooks[0].Parse.Status != shell.StatusFailed {
		t.Fatalf("parse result was not retained: %#v", result.SDKs[0].Hooks[0].Parse)
	}
}
