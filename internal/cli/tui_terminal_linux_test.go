//go:build linux

package cli

import (
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/report"
)

func TestTUISDKListReviewPriority(t *testing.T) {
	item := tuiSDK{Name: "go", Source: "store", Status: "cached", Channel: "1.27/stable"}
	document := &report.Document{Assessment: finding.Assessment{BySDK: []finding.SDKAssessment{
		{SDK: "go", ReviewPriority: finding.Score{Score: 10, Level: "low"}},
	}}}
	line := tuiSDKListLine(item, document, 110)
	if !strings.Contains(line, "Review Priority: \x1b[36m10/100\x1b[0m") {
		t.Fatalf("wrong priority or CLI color: %q", line)
	}
	if strings.Contains(tuiSDKListLine(item, nil, 110), "Review Priority") {
		t.Fatal("score displayed before scanning")
	}
	if strings.Contains(tuiSDKListLine(item, document, 40), "Review Priority") {
		t.Fatal("narrow terminal should preserve SDK information")
	}
	if strings.Contains(tuiSDKListLine(tuiSDK{Name: "rust"}, document, 110), "Review Priority") {
		t.Fatal("SDK without an assessment must not inherit another SDK score")
	}
}
