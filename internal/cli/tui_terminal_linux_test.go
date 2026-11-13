//go:build linux

package cli

import (
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/sdk"
)

func TestTUISDKListReviewPriorityAligned(t *testing.T) {
	document := &report.Document{Assessment: finding.Assessment{BySDK: []finding.SDKAssessment{
		{SDK: "kernel-dev-base", ReviewPriority: finding.Score{Score: 76, Level: "high"}},
		{SDK: "rust", ReviewPriority: finding.Score{Score: 10, Level: "low"}},
	}}}
	project := tuiSDKListLine(tuiSDK{Name: "kernel-dev-base", Source: "project", Status: "local"}, document, 110)
	store := tuiSDKListLine(tuiSDK{Name: "rust", Source: "store", Status: "cached", Channel: "latest/stable"}, document, 110)
	const label = "Review Priority: "
	projectColumn := strings.Index(project, label)
	storeColumn := strings.Index(store, label)
	if projectColumn < 0 || storeColumn < 0 || projectColumn != storeColumn {
		t.Fatalf("priority columns differ: project=%d, store=%d\n%s\n%s", projectColumn, storeColumn, project, store)
	}
}

func TestWorkshopSDKPriorityUsesDeclarationIdentity(t *testing.T) {
	doc := &report.Document{Assessment: finding.Assessment{BySDK: []finding.SDKAssessment{
		{SDK: "same", Declarations: []sdk.Declaration{{Definition: "other.yaml", Order: 0}}, ReviewPriority: finding.Score{Score: 99, Level: "critical"}},
		{SDK: "same", Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 1}}, ReviewPriority: finding.Score{Score: 42, Level: "medium"}},
	}}}
	score := workshopSDKScore(doc, "dev.yaml", 1)
	if score == nil || score.Score != 42 {
		t.Fatalf("wrong score: %+v", score)
	}
	if workshopSDKScore(doc, "dev.yaml", 0) != nil || workshopSDKScore(nil, "dev.yaml", 1) != nil {
		t.Fatal("unexpected score for missing SDK or scan")
	}
	line, colored := tuiScoreLine("   same   store   cached", score, 80)
	if !colored || !strings.Contains(line, "Review Priority: ") || !strings.Contains(line, "\x1b[33m42/100") {
		t.Fatalf("unexpected output: %q", line)
	}
	if line, colored = tuiScoreLine("   same   store   cached", score, 20); colored || strings.Contains(line, "\x1b[") {
		t.Fatalf("narrow output: %q", line)
	}
}

func TestTUIExplorerHeaderScanStatusSurvivesNavigation(t *testing.T) {
	model := tuiExplorer{SDKs: []tuiSDK{{Name: "go"}}, Scanning: true, ScanStatus: "Scanning..."}
	model.Message = "Temporary navigation message"
	model.move(1)
	if !strings.Contains(tuiExplorerHeader(&model), "SDKs: 1  (read-only, auto-fetch missing SDKs)  Scanning...") {
		t.Fatalf("missing scan status in header: %q", tuiExplorerHeader(&model))
	}
	if strings.Contains(tuiExplorerHeader(&model), model.Message) && model.Message != "" {
		t.Fatalf("navigation message leaked into header: %q", tuiExplorerHeader(&model))
	}
	model.finishScan(&report.Document{}, nil)
	if !strings.Contains(tuiExplorerHeader(&model), "Scan complete") {
		t.Fatalf("completed status missing: %q", tuiExplorerHeader(&model))
	}
}
