package finding_test

import (
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/sdk"
)

func TestCrossSDKProjectArtifactExecution(t *testing.T) {
	t.Parallel()

	writer := analyzedSDK(t, "cp /tmp/tool /project/.cache/tool\n", sdk.HookSetupProject)
	writer.Name = "writer"
	writer.Declarations = []sdk.Declaration{{Definition: ".workshop/dev.yaml", Workshop: "dev", Order: 0}}
	runner := analyzedSDK(t, "/project/.cache/tool --check\n", sdk.HookSetupProject)
	runner.Name = "runner"
	runner.Declarations = []sdk.Declaration{{Definition: ".workshop/dev.yaml", Workshop: "dev", Order: 1}}

	findings, relations := finding.AnalyzeComposition([]sdk.SDK{runner, writer}) // inventory/display order is intentionally reversed
	got := findFinding(findings, "risk.cross-sdk-project-artifact-execution")
	if got == nil || got.Severity != "high" || len(got.Evidence) != 2 {
		t.Fatalf("composition finding = %#v; relations = %#v", got, relations)
	}
	if got.Evidence[0].SDK != "writer" || got.Evidence[1].SDK != "runner" || got.Evidence[1].NormalizedValue != "/project/.cache/tool" {
		t.Errorf("composition evidence = %#v", got.Evidence)
	}
	if len(relations) != 1 || relations[0].FromOrder != 0 || relations[0].ToOrder != 1 {
		t.Errorf("composition relations = %#v", relations)
	}
}

func TestCrossSDKCompositionRequiresForwardOrderAndSameWorkshop(t *testing.T) {
	t.Parallel()

	writer := analyzedSDK(t, "cp /tmp/tool /project/.cache/tool\n", sdk.HookSetupProject)
	writer.Name = "writer"
	runner := analyzedSDK(t, "/project/.cache/tool --check\n", sdk.HookSetupProject)
	runner.Name = "runner"

	tests := []struct {
		name              string
		writerDeclaration sdk.Declaration
		runnerDeclaration sdk.Declaration
	}{
		{name: "reversed", writerDeclaration: sdk.Declaration{Definition: ".workshop/dev.yaml", Workshop: "dev", Order: 1}, runnerDeclaration: sdk.Declaration{Definition: ".workshop/dev.yaml", Workshop: "dev", Order: 0}},
		{name: "different definition", writerDeclaration: sdk.Declaration{Definition: ".workshop/a.yaml", Workshop: "a", Order: 0}, runnerDeclaration: sdk.Declaration{Definition: ".workshop/b.yaml", Workshop: "b", Order: 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer.Declarations = []sdk.Declaration{test.writerDeclaration}
			runner.Declarations = []sdk.Declaration{test.runnerDeclaration}
			findings, relations := finding.AnalyzeComposition([]sdk.SDK{writer, runner})
			if got := findFinding(findings, "risk.cross-sdk-project-artifact-execution"); got != nil || len(relations) != 0 {
				t.Errorf("invalid composition matched: finding=%#v relations=%#v", got, relations)
			}
		})
	}
}
