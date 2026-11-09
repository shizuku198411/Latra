//go:build linux

package cli

import (
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/report"
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
