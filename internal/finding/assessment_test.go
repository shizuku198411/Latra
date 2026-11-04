package finding_test

import (
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/sdk"
)

func TestAssessmentKeepsRiskAndAssuranceIndependent(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "printf profile > /etc/profile.d/example.sh\n", sdk.HookSetupBase)
	findings := finding.AnalyzeSDK(item)
	assessment := finding.AssessSDK(item, findings)
	if assessment.Risk.Score != 25 || assessment.Risk.Level != "medium" {
		t.Errorf("risk = %#v", assessment.Risk)
	}
	if assessment.Assurance.Score == 0 {
		t.Errorf("assurance = %#v", assessment.Assurance)
	}
	if assessment.ReviewPriority.Score != assessment.Risk.Score {
		t.Errorf("review priority = %#v, risk = %#v", assessment.ReviewPriority, assessment.Risk)
	}
}

func TestCriticalFindingSetsReviewPriorityFloor(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "printf ok\n", sdk.HookSetupProject)
	findings := []finding.Finding{{
		ID: "risk.fixture", Kind: finding.KindRisk, Family: "remote-execution", Severity: "critical",
		Confidence: "high", Weight: 85, Scope: finding.Scope{SDK: item.Name},
		Evidence: []finding.Evidence{{Type: "metadata", ID: "fixture"}}, Message: "fixture",
	}}
	assessment := finding.AssessSDK(item, findings)
	if assessment.Risk.Score < 80 || assessment.ReviewPriority.Level != "critical" || assessment.Classification != "high-priority-review" {
		t.Fatalf("assessment = %#v", assessment)
	}
}

func TestCoveragePenaltyRaisesReviewPriority(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "latra-unknown-fixture\n", sdk.HookSetupProject)
	assessment := finding.AssessSDK(item, finding.AnalyzeSDK(item))
	if assessment.Coverage.Level != "insufficient" || assessment.Coverage.Score != 60 {
		t.Fatalf("coverage = %#v", assessment.Coverage)
	}
	if assessment.ReviewPriority.Score != 40 || assessment.Classification != "insufficient-evidence" {
		t.Fatalf("assessment = %#v", assessment)
	}
}

func TestAssessmentAggregatesRiskLocationsByRule(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "first-unknown\nsecond-unknown\n", sdk.HookSetupBase)
	assessment := finding.AssessSDK(item, finding.AnalyzeSDK(item))
	if len(assessment.KeyRisks) != 1 {
		t.Fatalf("key risks = %#v", assessment.KeyRisks)
	}
	highlight := assessment.KeyRisks[0]
	if highlight.ID != "risk.unknown-command-root" || highlight.Occurrences != 2 || highlight.Score != 44 {
		t.Errorf("highlight = %#v", highlight)
	}
	if len(highlight.Scopes) != 2 || highlight.Scopes[0].Location == nil || highlight.Scopes[0].Location.Path == "" {
		t.Errorf("scopes = %#v", highlight.Scopes)
	}
}
