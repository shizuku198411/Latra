package finding_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

// These fixtures retain the v0.2.2 operation-location baseline while requiring
// Phase 1 value-level locations to identify the exact AST word.
type accuracyEvidenceExpectation struct {
	FindingID         string
	EvidenceID        string
	Value             string
	Resolution        analysis.Resolution
	OperationLocation shell.Location
	TargetLocation    shell.Location
	Reason            string
}

type accuracyFixture struct {
	Name             string
	File             string
	Hook             sdk.HookName
	ExpectedFindings []string
	Evidence         []accuracyEvidenceExpectation
	Reason           string
}

type accuracyMetrics struct {
	TruePositive, FalsePositive, FalseNegative int
	ExactValueLocations, LocationTargets       int
}

func TestAnalysisEvidenceAccuracyBaseline(t *testing.T) {
	t.Parallel()

	const fixturePath = "fixture/hooks/"
	fixtures := []accuracyFixture{
		{
			Name: "literal redirect target", File: "profile-literal.sh", Hook: sdk.HookSetupBase,
			ExpectedFindings: []string{"risk.profile-environment-write"},
			Reason:           "A declarative setup-base write to a literal profile path is a low-risk profile environment write, not generic persistence.",
			Evidence: []accuracyEvidenceExpectation{{
				FindingID: "risk.profile-environment-write", EvidenceID: "persistence", Value: "/etc/profile.d/go.sh", Resolution: analysis.Resolved,
				OperationLocation: shell.Location{Path: fixturePath + "setup-base", StartLine: 1, StartColumn: 35},
				TargetLocation:    shell.Location{Path: fixturePath + "setup-base", StartLine: 1, StartColumn: 37, EndLine: 1, EndColumn: 57},
				Reason:            "The current evidence starts at the redirect operator; precise highlighting should start at the path word.",
			}},
		},
		{
			Name: "quoted redirect target", File: "profile-quoted-target.sh", Hook: sdk.HookSetupBase,
			ExpectedFindings: []string{"risk.profile-environment-write"},
			Reason:           "Quoting a fully literal profile target must preserve the same finding and resolved value.",
			Evidence: []accuracyEvidenceExpectation{{
				FindingID: "risk.profile-environment-write", EvidenceID: "persistence", Value: "/etc/profile.d/go.sh", Resolution: analysis.Resolved,
				OperationLocation: shell.Location{Path: fixturePath + "setup-base", StartLine: 1, StartColumn: 35},
				TargetLocation:    shell.Location{Path: fixturePath + "setup-base", StartLine: 1, StartColumn: 37, EndLine: 1, EndColumn: 59},
				Reason:            "The target is the quoted syntax.Word, while current evidence starts at the redirect operator.",
			}},
		},
		{
			Name: "multiline git clone", File: "remote-multiline.sh", Hook: sdk.HookSetupProject,
			ExpectedFindings: []string{"risk.remote-content-to-project"},
			Reason:           "A resolved remote clone into the mounted project must retain both the download and project-write evidence.",
			Evidence: []accuracyEvidenceExpectation{
				{
					FindingID: "risk.remote-content-to-project", EvidenceID: "network-download", Value: "git", Resolution: analysis.Resolved,
					OperationLocation: shell.Location{Path: fixturePath + "setup-project", StartLine: 1, StartColumn: 1},
					TargetLocation:    shell.Location{Path: fixturePath + "setup-project", StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 4},
					Reason:            "The command word and operation begin at the same source position in this baseline fixture.",
				},
				{
					FindingID: "risk.remote-content-to-project", EvidenceID: "project-write", Value: "opensbi", Resolution: analysis.Resolved,
					OperationLocation: shell.Location{Path: fixturePath + "setup-project", StartLine: 1, StartColumn: 1},
					TargetLocation:    shell.Location{Path: fixturePath + "setup-project", StartLine: 4, StartColumn: 3, EndLine: 4, EndColumn: 10},
					Reason:            "The destination is on a continuation line, but current evidence only identifies the containing command.",
				},
			},
		},
		{
			Name: "clone outside project", File: "remote-outside-project.sh", Hook: sdk.HookSetupProject,
			Reason: "A remote clone into /tmp is not a remote-content-to-project flow.",
		},
		{
			Name: "disconnected project write", File: "disconnected-project-write.sh", Hook: sdk.HookSetupProject,
			Reason: "A later local write must not be connected to an earlier unrelated download.",
		},
	}

	relevant := map[string]bool{
		"risk.profile-environment-write": true,
		"risk.persistence-write":         true,
		"risk.remote-content-to-project": true,
	}
	metrics := accuracyMetrics{}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "accuracy", fixture.File))
			if err != nil {
				t.Fatal(err)
			}
			item := analyzedSDK(t, string(content), fixture.Hook)
			findings := finding.AnalyzeSDK(item)
			expected := stringSet(fixture.ExpectedFindings)
			actual := map[string]bool{}
			for _, got := range findings {
				if got.Kind == finding.KindRisk && relevant[got.ID] {
					actual[got.ID] = true
				}
			}
			for id := range relevant {
				switch {
				case expected[id] && actual[id]:
					metrics.TruePositive++
				case !expected[id] && actual[id]:
					metrics.FalsePositive++
					t.Errorf("unexpected finding %q: %s", id, fixture.Reason)
				case expected[id] && !actual[id]:
					metrics.FalseNegative++
					t.Errorf("missing finding %q: %s", id, fixture.Reason)
				}
			}
			for _, want := range fixture.Evidence {
				got := findAccuracyEvidence(findings, want)
				if got == nil {
					t.Errorf("missing evidence %s/%s value %q: %s", want.FindingID, want.EvidenceID, want.Value, want.Reason)
					continue
				}
				if got.Resolution != want.Resolution || got.Location == nil || !sameLocationStart(*got.Location, want.OperationLocation) {
					t.Errorf("evidence baseline = %#v, want resolution=%s location=%#v: %s", got, want.Resolution, want.OperationLocation, want.Reason)
				}
				metrics.LocationTargets++
				if got.ValueLocation != nil && *got.ValueLocation == want.TargetLocation {
					metrics.ExactValueLocations++
				} else {
					t.Errorf("value location = %#v, want %#v: %s", got.ValueLocation, want.TargetLocation, want.Reason)
				}
			}
		})
	}

	// Finding accuracy remains unchanged while all directly represented values
	// now carry their exact AST-derived source word range.
	want := accuracyMetrics{TruePositive: 3, FalsePositive: 0, FalseNegative: 0, ExactValueLocations: 4, LocationTargets: 4}
	if metrics != want {
		t.Fatalf("accuracy metrics = %#v, want %#v", metrics, want)
	}
	t.Logf("baseline: TP=%d FP=%d FN=%d exact-value-locations=%d/%d", metrics.TruePositive, metrics.FalsePositive, metrics.FalseNegative, metrics.ExactValueLocations, metrics.LocationTargets)
}

func TestExpandedFindingValueDoesNotReceiveFabricatedLocation(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "TARGET=/etc/profile.d/go.sh\nprintf 'export GO_ROOT=/opt/go\\n' > \"$TARGET\"\n", sdk.HookSetupBase)
	got := findFinding(finding.AnalyzeSDK(item), "risk.profile-environment-write")
	if got == nil || len(got.Evidence) != 1 {
		t.Fatalf("profile finding = %#v", got)
	}
	if got.Evidence[0].Value != "/etc/profile.d/go.sh" || got.Evidence[0].Resolution != analysis.Resolved {
		t.Fatalf("expanded evidence = %#v", got.Evidence[0])
	}
	if got.Evidence[0].ValueLocation != nil {
		t.Fatalf("expanded value received a fabricated source range: %#v", got.Evidence[0].ValueLocation)
	}
}

func findAccuracyEvidence(findings []finding.Finding, want accuracyEvidenceExpectation) *finding.Evidence {
	for index := range findings {
		if findings[index].ID != want.FindingID {
			continue
		}
		for evidenceIndex := range findings[index].Evidence {
			evidence := &findings[index].Evidence[evidenceIndex]
			if evidence.ID == want.EvidenceID && evidence.Value == want.Value {
				return evidence
			}
		}
	}
	return nil
}

func sameLocationStart(got, want shell.Location) bool {
	return got.Path == want.Path && got.StartLine == want.StartLine && got.StartColumn == want.StartColumn
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
