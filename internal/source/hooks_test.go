package source_test

import (
	"path/filepath"
	"testing"

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
