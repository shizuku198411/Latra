package finding

import (
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/findingconfig"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

func TestHookMatchesAllContextConstraints(t *testing.T) {
	t.Parallel()

	result := analysis.Result{Context: analysis.ContextFor(string(sdk.HookCheckHealth))}
	hook := sdk.Hook{Name: sdk.HookCheckHealth, Analysis: &result}
	rule := findingconfig.Rule{Matcher: findingconfig.Matcher{
		HookNames:        []string{string(sdk.HookCheckHealth)},
		RunAsRoot:        boolPointer(true),
		ProjectMounted:   boolPointer(true),
		InterfacesActive: boolPointer(true),
		StateMounted:     boolPointer(false),
		ContextDependent: boolPointer(false),
	}}
	if !hookMatches(&hook, rule) {
		t.Fatal("check-health did not match its complete context")
	}

	rule.Matcher.StateMounted = boolPointer(true)
	if hookMatches(&hook, rule) {
		t.Fatal("context constraints were not combined with AND semantics")
	}
}

func TestHookMatchesContextFailsClosedWithoutAnalysis(t *testing.T) {
	t.Parallel()

	hook := sdk.Hook{Name: sdk.HookSetupProject}
	rule := findingconfig.Rule{Matcher: findingconfig.Matcher{ProjectMounted: boolPointer(true)}}
	if hookMatches(&hook, rule) {
		t.Fatal("hook without analysis matched a context-constrained rule")
	}

	rule.Matcher.ProjectMounted = nil
	if !hookMatches(&hook, rule) {
		t.Fatal("hook without analysis did not match an unconstrained rule")
	}
}

func TestHookMatchesContextDependentStateHook(t *testing.T) {
	t.Parallel()

	result := analysis.Result{Context: analysis.ContextFor(string(sdk.HookSaveState))}
	hook := sdk.Hook{Name: sdk.HookSaveState, Analysis: &result}
	rule := findingconfig.Rule{Matcher: findingconfig.Matcher{
		RunAsRoot:        boolPointer(true),
		StateMounted:     boolPointer(true),
		ContextDependent: boolPointer(true),
	}}
	if !hookMatches(&hook, rule) {
		t.Fatal("save-state did not match its context-dependent state context")
	}
}

func TestContextualAbsenceCapabilityIsEvaluatedPerHook(t *testing.T) {
	t.Parallel()

	parsed := shell.Result{Status: shell.StatusParsed}
	result := analysis.Result{Context: analysis.ContextFor(string(sdk.HookSetupProject))}
	item := sdk.SDK{Hooks: []sdk.Hook{{Name: sdk.HookSetupProject, Parse: &parsed, Analysis: &result}}}
	rule := findingconfig.Rule{Matcher: findingconfig.Matcher{
		Type: "absence-capability", Capabilities: []string{"dynamic-execution"},
		ProjectMounted: boolPointer(true),
	}}
	matches := matchAbsence(item, rule)
	if len(matches) != 1 || matches[0].hook == nil || matches[0].hook.Name != sdk.HookSetupProject {
		t.Fatalf("matches = %#v", matches)
	}

	item.Hooks[0].Analysis.Context.ProjectMounted = false
	if matches := matchAbsence(item, rule); len(matches) != 0 {
		t.Fatalf("context-mismatched absence finding = %#v", matches)
	}
}

func boolPointer(value bool) *bool { return &value }
