package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
	"github.com/shizuku198411/Latra/internal/source"
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

func TestTUIRiskLabelShowsEvidenceDerivation(t *testing.T) {
	document := &report.Document{Assessment: finding.Assessment{BySDK: []finding.SDKAssessment{{SDK: "go", KeyRisks: []finding.RiskHighlight{{
		ID: "risk.fixture", Title: "Conditional endpoint requires review", Severity: "medium", Score: 25,
		Scopes: []finding.RiskScope{{SDK: "go", Location: &shell.Location{Path: "go/hooks/setup-project", StartLine: 1},
			Expression: "$URL", Resolution: analysis.Unknown, Derivation: finding.EvidenceUnresolved}},
	}}}}}}
	rows := tuiPreviewRows(&tuiPreview{Lines: []string{"    1  curl \"$URL\""}}, risksForPreview(document, "go", "hooks/setup-project"), 120, 4)
	if len(rows) < 1 || !strings.Contains(rows[0], "evidence=unresolved, resolution=Unknown") {
		t.Fatalf("evidence label = %#v", rows)
	}
}

func TestScanJSONEvidenceAndTUIAnnotationShareOperationLocation(t *testing.T) {
	const content = "git clone \\\n  --depth=1 \\\n  https://example.invalid/opensbi.git \\\n  opensbi\n"
	parsed := shell.NewParser().Parse([]byte(content), "fixture/hooks/setup-project")
	if parsed.Status != shell.StatusParsed {
		t.Fatalf("parse = %#v", parsed.Diagnostics)
	}
	result := analysis.Analyze(string(sdk.HookSetupProject), &parsed)
	document := report.NewDocument(&source.Result{Kind: source.InputProjectSDK, Root: "/fixture", SDKs: []sdk.SDK{{
		Name: "fixture", Source: sdk.SourceProject, State: sdk.StateResolved,
		Hooks: []sdk.Hook{{Name: sdk.HookSetupProject, Path: "fixture/hooks/setup-project", Parse: &parsed, Analysis: &result}},
	}}})

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded report.Document
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	annotations := risksForPreview(&decoded, "fixture", "hooks/setup-project")
	if len(annotations[1]) != 1 || len(annotations[4]) != 1 {
		t.Fatalf("JSON evidence did not produce exact line annotations: %#v", annotations)
	}
	for _, item := range decoded.SDKs {
		for _, got := range item.Findings {
			if got.ID != "risk.remote-content-to-project" {
				continue
			}
			for _, evidence := range got.Evidence {
				if evidence.Location == nil || evidence.Location.Path != "fixture/hooks/setup-project" || evidence.Location.StartLine != 1 || evidence.Location.StartColumn != 1 {
					t.Fatalf("JSON evidence location = %#v", evidence.Location)
				}
				if evidence.ValueLocation == nil {
					t.Fatalf("JSON value location missing for %#v", evidence)
				}
			}
			preview := &tuiPreview{Lines: []string{
				"    1  git clone \\",
				"    2    --depth=1 \\",
				"    3    https://example.invalid/opensbi.git \\",
				"    4    opensbi",
			}}
			rows := tuiPreviewRows(preview, annotations, 120, 8)
			if strings.Count(strings.Join(rows, "\n"), "#Risk >") != 1 {
				t.Fatalf("risk label count changed: %#v", rows)
			}
			if !strings.Contains(rows[1], "\x1b[33mgit\x1b[0m clone") || !strings.Contains(rows[len(rows)-1], "\x1b[33mopensbi\x1b[0m") {
				t.Fatalf("exact multiline highlights missing: %#v", rows)
			}
			if strings.Contains(rows[3], "\x1b[33mopensbi\x1b[0m.git") {
				t.Fatalf("same text in URL was incorrectly highlighted: %q", rows[3])
			}
			return
		}
	}
	t.Fatal("risk.remote-content-to-project was not reported")
}

func TestTUISemanticGapLabelsMatchOperationLocation(t *testing.T) {
	document := &report.Document{
		SDKs: []report.SDK{{Name: "rust", Hooks: []report.Hook{{
			Name: sdk.HookSetupBase,
			Operations: []analysis.Operation{{
				ID: "op-0004", Location: shell.Location{Path: "rust/sdk/hooks/setup-base", StartLine: 9},
			}},
		}}}},
		Assessment: finding.Assessment{BySDK: []finding.SDKAssessment{{
			SDK: "rust",
			Coverage: finding.Coverage{Semantics: finding.SemanticCoverage{Gaps: []finding.SemanticGap{{
				Code: "external-include", Dimension: "included-sources", Severity: "critical",
				Hook: sdk.HookSetupBase, OperationID: "op-0004",
				Message: "source is not a statically resolvable SDK-local include",
			}}}},
		}}},
	}
	annotations := risksForPreview(document, "rust", "sdk/hooks/setup-base")
	if len(annotations[9]) != 1 {
		t.Fatalf("semantic annotations = %#v", annotations)
	}
	lines := make([]string, 9)
	lines[8] = "    9  . /etc/profile.d/rust.sh"
	rows := tuiPreviewRows(&tuiPreview{Lines: lines, Scroll: 8}, annotations, 120, 3)
	if len(rows) != 2 || !strings.Contains(rows[0], "#Semantic Gap > [included-sources/external-include]") {
		t.Fatalf("semantic label rows = %#v", rows)
	}
	levels := tuiTreeRisks(document, "rust")
	if levels["sdk/hooks/setup-base"] != "critical" || levels["sdk/hooks"] != "critical" {
		t.Fatalf("semantic tree levels = %#v", levels)
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

func TestTUIRiskSameLineMultipleValuesAndContinuedCommand(t *testing.T) {
	document := &report.Document{Assessment: finding.Assessment{BySDK: []finding.SDKAssessment{{SDK: "kernel-dev-base", KeyRisks: []finding.RiskHighlight{{
		ID: "risk.remote-content-to-project", Title: "Remote content is written into the Workshop project", Severity: "medium", Score: 25,
		Scopes: []finding.RiskScope{
			{SDK: "kernel-dev-base", Location: &shell.Location{Path: "hooks/setup-project", StartLine: 13, StartColumn: 3}, Value: "git"},
			{SDK: "kernel-dev-base", Location: &shell.Location{Path: "hooks/setup-project", StartLine: 13, StartColumn: 3}, Value: "opensbi"},
		},
	}}}}}}
	lines := make([]string, 19)
	for i := range lines {
		lines[i] = " "
	}
	lines[12] = "   13    git clone \\"
	lines[13] = "   14      --depth=1 \\"
	lines[14] = "   15      --branch=\"${OPENSBI_VERSION}\" \\"
	lines[15] = "   16      --single-branch \\"
	lines[16] = "   17      \"${OPENSBI_URL}\" \\"
	lines[17] = "   18      opensbi"
	lines[18] = "   19  fi"
	annotations := risksForPreview(document, "kernel-dev-base", "hooks/setup-project")
	preview := &tuiPreview{Lines: lines, Scroll: 12}
	rows := tuiPreviewRows(preview, annotations, 120, 20)
	labels := 0
	for _, row := range rows {
		if strings.Contains(row, "#Risk >") {
			labels++
		}
	}
	if labels != 1 {
		t.Fatalf("want one label, got %d: %#v", labels, rows)
	}
	if !strings.Contains(rows[1], "\x1b[33mgit\x1b[0m") {
		t.Fatalf("first evidence not highlighted: %q", rows[1])
	}
	if !strings.Contains(rows[6], "\x1b[33mopensbi\x1b[0m") {
		t.Fatalf("continued-line evidence not highlighted: %q", rows[6])
	}
	preview.Scroll = 17
	rows = tuiPreviewRows(preview, annotations, 120, 3)
	if len(rows) != 2 || !strings.Contains(rows[0], "\x1b[33mopensbi\x1b[0m") {
		t.Fatalf("continued-line highlight lost after scrolling: %#v", rows)
	}
}

func TestTUIRiskMultipleValuesOneLine(t *testing.T) {
	preview := &tuiPreview{Lines: []string{"    1  git clone opensbi"}}
	risks := map[int][]tuiRisk{1: {
		{ID: "same", Title: "Remote content", Severity: "medium", Score: 25, Value: "git"},
		{ID: "same", Title: "Remote content", Severity: "medium", Score: 25, Value: "opensbi"},
	}}
	rows := tuiPreviewRows(preview, risks, 100, 5)
	if len(rows) != 2 || strings.Count(rows[0], "#Risk >") != 1 || !strings.Contains(rows[1], "\x1b[33mgit\x1b[0m") || !strings.Contains(rows[1], "\x1b[33mopensbi\x1b[0m") {
		t.Fatalf("expected one label and two highlighted values: %#v", rows)
	}
}

func TestTUIFallbackBaselineHighlightsDuplicateTextOccurrences(t *testing.T) {
	preview := &tuiPreview{Lines: []string{"    1  printf opensbi; install opensbi /project/bin/tool"}}
	annotations := map[int][]tuiRisk{1: {{
		ID: "risk.fixture", Title: "Fixture", Severity: "medium", Score: 25, Value: "opensbi",
	}}}
	rows := tuiPreviewRows(preview, annotations, 120, 3)
	if len(rows) != 2 {
		t.Fatalf("fallback rows = %#v", rows)
	}
	// v0.2.2 has no value-level source range, so the conservative string
	// fallback highlights both identical occurrences. Phase 1 should replace
	// this baseline only when an AST-derived ValueLocation is available.
	if got := strings.Count(rows[1], "\x1b[33mopensbi\x1b[0m"); got != 2 {
		t.Fatalf("duplicate fallback highlights = %d, want 2: %q", got, rows[1])
	}
}

func TestTUIValueLocationHighlightsOnlySelectedDuplicate(t *testing.T) {
	preview := &tuiPreview{Lines: []string{"    1  printf opensbi; install opensbi /project/bin/tool"}}
	annotations := map[int][]tuiRisk{1: {{
		ID: "risk.fixture", Title: "Fixture", Severity: "medium", Score: 25, Value: "opensbi",
		ValueLocation: &shell.Location{Path: "fixture", StartLine: 1, StartColumn: 25, EndLine: 1, EndColumn: 32},
	}}}
	rows := tuiPreviewRows(preview, annotations, 120, 3)
	if len(rows) != 2 || !strings.Contains(rows[1], "printf opensbi; install \x1b[33mopensbi\x1b[0m") {
		t.Fatalf("exact duplicate highlight = %#v", rows)
	}
	if got := strings.Count(rows[1], "\x1b[33mopensbi\x1b[0m"); got != 1 {
		t.Fatalf("exact duplicate highlight count = %d, want 1: %q", got, rows[1])
	}
}

func TestTUIValueLocationAccountsForDisplayedTabExpansion(t *testing.T) {
	preview := &tuiPreview{
		Lines:       []string{"    1      install opensbi"},
		SourceLines: []string{"\tinstall opensbi"},
	}
	annotations := map[int][]tuiRisk{1: {{
		ID: "risk.fixture", Title: "Fixture", Severity: "medium", Score: 25, Value: "opensbi",
		ValueLocation: &shell.Location{Path: "fixture", StartLine: 1, StartColumn: 10, EndLine: 1, EndColumn: 17},
	}}}
	rows := tuiPreviewRows(preview, annotations, 120, 3)
	if len(rows) != 2 || !strings.Contains(rows[1], "install \x1b[33mopensbi\x1b[0m") {
		t.Fatalf("tab-adjusted highlight = %#v", rows)
	}
}
