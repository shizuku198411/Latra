package analysis_test

import (
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/shell"
)

func TestAnalyzeCommandsAndValues(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
url="https://example.invalid/install.sh"
curl "$url"
[ -n "$url" ]
sudo env MODE=test /usr/bin/printf '%s' "$url"
"$DYNAMIC" argument
`)
	operations := flatten(result.Operations)

	curl := findCommand(t, operations, "curl")
	if curl.Arguments[0].Resolution != analysis.Resolved || curl.Arguments[0].Literal != "https://example.invalid/install.sh" {
		t.Errorf("curl argument = %#v", curl.Arguments[0])
	}
	testCommand := findCommand(t, operations, "[")
	if testCommand.Command.Resolution != analysis.Resolved {
		t.Errorf("test command = %#v", testCommand.Command)
	}
	printf := findCommand(t, operations, "printf")
	if len(printf.Wrappers) != 2 || printf.Wrappers[0] != "sudo" || printf.Wrappers[1] != "env" {
		t.Errorf("wrappers = %#v", printf.Wrappers)
	}
	if printf.Command.Literal != "printf" {
		t.Errorf("normalized command = %#v", printf.Command)
	}
	if operations[len(operations)-1].Command.Resolution != analysis.Unknown {
		t.Errorf("dynamic command resolution = %q", operations[len(operations)-1].Command.Resolution)
	}
	assertCapability(t, result.Capabilities, "network-download")
	assertCapability(t, result.Capabilities, "dynamic-execution")
}

func TestAnalyzeControlFlowAndCandidates(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
if test -n "$MODE"; then
  target=one
else
  target=two
fi
printf '%s' "$target"
`)
	operation := findCommand(t, flatten(result.Operations), "printf")
	value := operation.Arguments[1]
	if value.Resolution != analysis.PartiallyResolved {
		t.Fatalf("resolution = %q, want %q; value: %#v", value.Resolution, analysis.PartiallyResolved, value)
	}
	if len(value.Candidates) != 2 || value.Candidates[0] != "one" || value.Candidates[1] != "two" {
		t.Errorf("candidates = %#v", value.Candidates)
	}
}

func TestAnalyzeFlowAndSpecialOperations(t *testing.T) {
	t.Parallel()

	result := analyze(t, "check-health", `
producer | consumer > /project/output
reader < /root/.ssh/id_ed25519
value="$(nested "$(inner)")"
source ./helpers.sh
eval "$GENERATED"
bash -c 'echo generated'
build() { echo ok; }
build
cat <(printf data)
cat "$SDK_STATE_DIR/saved"
printf data | tee "$SDK_STATE_DIR/output"
`)
	operations := flatten(result.Operations)
	for _, kind := range []analysis.OperationKind{
		analysis.OperationPipeline,
		analysis.OperationRedirectRead,
		analysis.OperationRedirectWrite,
		analysis.OperationCommandSubstitution,
		analysis.OperationProcessSubstitution,
		analysis.OperationSource,
		analysis.OperationEval,
		analysis.OperationFunctionDeclaration,
		analysis.OperationFunctionInvocation,
	} {
		if !hasOperation(operations, kind) {
			t.Errorf("operation %q not found: %#v", kind, operations)
		}
	}
	pipeline := firstOperation(t, result.Operations, analysis.OperationPipeline)
	if len(pipeline.Children) < 2 || len(pipeline.Children[0].Outputs) == 0 || len(pipeline.Children[1].Inputs) == 0 {
		t.Errorf("pipeline flow = %#v", pipeline.Children)
	}
	for _, capability := range []string{
		"project-write", "credential-read", "code-execution", "dynamic-execution", "state-read", "state-write",
	} {
		assertCapability(t, result.Capabilities, capability)
	}
}

func TestContextForLifecycleHooks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		root       bool
		project    bool
		interfaces bool
		state      bool
		dependent  bool
	}{
		{name: "setup-base", root: true},
		{name: "setup-project", project: true, interfaces: true},
		{name: "check-health", root: true, project: true, interfaces: true},
		{name: "save-state", root: true, state: true, dependent: true},
		{name: "restore-state", root: true, project: true, interfaces: true, state: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := analysis.ContextFor(test.name)
			if context.RunAsRoot != test.root || context.ProjectMounted != test.project ||
				context.InterfacesActive != test.interfaces || context.StateMounted != test.state ||
				context.ContextDependent != test.dependent {
				t.Errorf("context = %#v", context)
			}
		})
	}
}

func TestClassifyPath(t *testing.T) {
	t.Parallel()

	tests := map[string]analysis.PathClass{
		"/project/source":               analysis.PathProject,
		"/home/workshop/.aws/config":    analysis.PathSensitive,
		"/root/.ssh/id_ed25519":         analysis.PathSensitive,
		"/var/lib/workshop/state/data":  analysis.PathState,
		"/etc/systemd/system/x.service": analysis.PathPersistence,
		"/dev/sda":                      analysis.PathDevice,
		"/tmp/result":                   analysis.PathTemporary,
		"/var/lib/workshop/sdk/x/file":  analysis.PathSDK,
		"relative/path":                 analysis.PathUnknown,
	}
	for path, want := range tests {
		value := analysis.Value{Resolution: analysis.Resolved, Literal: path}
		if got := analysis.ClassifyPath(value); got != want {
			t.Errorf("ClassifyPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func analyze(t *testing.T, hook, source string) analysis.Result {
	t.Helper()
	parsed := shell.NewParser().Parse([]byte(source), "fixture/"+hook)
	if parsed.Status != shell.StatusParsed {
		t.Fatalf("parse failed: %#v", parsed.Diagnostics)
	}
	return analysis.Analyze(hook, &parsed)
}

func flatten(operations []analysis.Operation) []analysis.Operation {
	var flattened []analysis.Operation
	for _, operation := range operations {
		flattened = append(flattened, operation)
		flattened = append(flattened, flatten(operation.Children)...)
	}
	return flattened
}

func findCommand(t *testing.T, operations []analysis.Operation, command string) analysis.Operation {
	t.Helper()
	for _, operation := range operations {
		if operation.Command.Literal == command {
			return operation
		}
	}
	t.Fatalf("command %q not found", command)
	return analysis.Operation{}
}

func firstOperation(t *testing.T, operations []analysis.Operation, kind analysis.OperationKind) analysis.Operation {
	t.Helper()
	for _, operation := range operations {
		if operation.Kind == kind {
			return operation
		}
	}
	t.Fatalf("operation %q not found", kind)
	return analysis.Operation{}
}

func hasOperation(operations []analysis.Operation, kind analysis.OperationKind) bool {
	for _, operation := range operations {
		if operation.Kind == kind {
			return true
		}
	}
	return false
}

func assertCapability(t *testing.T, capabilities []analysis.Capability, kind string) {
	t.Helper()
	for _, capability := range capabilities {
		if capability.Kind == kind {
			return
		}
	}
	t.Errorf("capability %q not found: %#v", kind, capabilities)
}
