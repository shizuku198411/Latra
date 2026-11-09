package cli

import (
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/shell"
)

func TestTUIRiskAnnotationsMatchSDKFileAndLine(t *testing.T) {
	document := &report.Document{Assessment: finding.Assessment{BySDK: []finding.SDKAssessment{{SDK: "go", KeyRisks: []finding.RiskHighlight{{
		ID: "risk.profile-environment-write", Title: "Shell environment profile is written during base setup", Severity: "low", Score: 10,
		Scopes: []finding.RiskScope{
			{SDK: "go", Location: &shell.Location{Path: "go/sdk/hooks/setup-base", StartLine: 1, StartColumn: 11}, Value: "/etc/profile.d/go.sh"},
			{SDK: "go", Location: &shell.Location{Path: "go/sdk/hooks/setup-base", StartLine: 1, StartColumn: 11}, Value: "/etc/profile.d/go.sh"},
			{SDK: "other", Location: &shell.Location{Path: "other/sdk/hooks/setup-base", StartLine: 1}, Value: "ignored"},
			{SDK: "go", Location: nil, Value: "ignored"},
		},
	}}}}}}
	if got := risksForPreview(document, "go", "sdk/hooks/other"); len(got) != 0 {
		t.Fatalf("wrong file: %+v", got)
	}
	if got := risksForPreview(document, "other", "sdk/hooks/setup-base"); len(got) != 0 {
		t.Fatalf("wrong SDK: %+v", got)
	}
	risks := risksForPreview(document, "go", "sdk/hooks/setup-base")
	if len(risks[1]) != 1 {
		t.Fatalf("deduplication failed: %+v", risks)
	}
	preview := &tuiPreview{Lines: []string{"    1  cat <<EOF >/etc/profile.d/go.sh", "    2  export PATH=foo"}}
	rows := tuiPreviewRows(preview, risks, 100, 10)
	if len(rows) != 3 {
		t.Fatalf("rows: %#v", rows)
	}
	if !strings.Contains(rows[0], "#Risk > Shell environment profile is written during base setup, low, score=10/100") {
		t.Fatalf("labels: %#v", rows)
	}
	if !strings.Contains(rows[1], "\x1b[36m/etc/profile.d/go.sh\x1b[0m") {
		t.Fatalf("highlight: %q", rows[1])
	}
	if strings.Contains(rows[2], "\x1b[36m") {
		t.Fatalf("unrelated line colored: %q", rows[2])
	}
	preview.Scroll = 1
	rows = tuiPreviewRows(preview, risks, 100, 10)
	if len(rows) != 1 || !strings.Contains(rows[0], "2  export") {
		t.Fatalf("source-line scrolling: %#v", rows)
	}
}

func TestTUIRiskRowsRespectViewportAndMissingValue(t *testing.T) {
	preview := &tuiPreview{Lines: []string{"    1  echo $name", "    2  echo done"}}
	risks := map[int][]tuiRisk{1: {{ID: "risk.example", Title: "Example", Severity: "high", Score: 40, Value: "/not-in-source"}}}
	rows := tuiPreviewRows(preview, risks, 24, 4)
	if len(rows) != 3 {
		t.Fatalf("viewport overflow: %v", rows)
	}
	if strings.Contains(rows[1], "\x1b[31m") {
		t.Fatalf("unmatched evidence highlighted: %q", rows[1])
	}
	for _, row := range rows {
		if len([]rune(strings.ReplaceAll(row, "\x1b[0m", ""))) > 100 {
			t.Fatalf("unexpected line length: %q", row)
		}
	}
}

func TestTUITreeRisksInheritStrongestDescendant(t *testing.T) {
	document := &report.Document{Assessment: finding.Assessment{BySDK: []finding.SDKAssessment{
		{SDK: "go", KeyRisks: []finding.RiskHighlight{
			{Severity: "low", Scopes: []finding.RiskScope{{SDK: "go", Location: &shell.Location{Path: "go/sdk/hooks/setup-base", StartLine: 1}}}},
			{Severity: "high", Scopes: []finding.RiskScope{{SDK: "go", Location: &shell.Location{Path: "sdk/hooks/check-health", StartLine: 3}}}},
			{Severity: "medium", Scopes: []finding.RiskScope{{SDK: "go", Location: &shell.Location{Path: "go/meta/config", StartLine: 2}}}},
			{Severity: "critical", Scopes: []finding.RiskScope{{SDK: "other", Location: &shell.Location{Path: "go/sdk/hooks/setup-base", StartLine: 1}}}},
			{Severity: "critical", Scopes: []finding.RiskScope{{SDK: "go", Location: nil}}},
		}},
		{SDK: "other", KeyRisks: []finding.RiskHighlight{{Severity: "critical", Scopes: []finding.RiskScope{{SDK: "other", Location: &shell.Location{Path: "other/sdk/hooks/check-health", StartLine: 1}}}}}},
	}}}
	levels := tuiTreeRisks(document, "go")
	for name, want := range map[string]string{
		"sdk/hooks/setup-base":   "low",
		"sdk/hooks/check-health": "high",
		"sdk/hooks":              "high",
		"sdk":                    "high",
		"meta/config":            "medium",
		"meta":                   "medium",
	} {
		if levels[name] != want {
			t.Errorf("%s: got %q, want %q", name, levels[name], want)
		}
	}
	if _, ok := levels["sdk/hooks/setup-project"]; ok {
		t.Fatal("unaffected file was highlighted")
	}
	if got := tuiTreeRisks(document, "missing"); len(got) != 0 {
		t.Fatalf("unexpected risk for missing SDK: %v", got)
	}
	if got := tuiTreeRisks(nil, "go"); got != nil {
		t.Fatalf("unscanned tree should not be highlighted: %v", got)
	}
}
