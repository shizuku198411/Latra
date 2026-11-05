package finding_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/findingconfig"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

func TestEveryEmbeddedFindingHasMatchingSDKFixture(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "findings")
	config := findingconfig.MustDefault()
	wantDirectories := make([]string, 0, len(config.Rules))
	for _, rule := range config.Rules {
		rule := rule
		fixtureName := strings.ReplaceAll(rule.ID, ".", "-")
		wantDirectories = append(wantDirectories, fixtureName)
		t.Run(rule.ID, func(t *testing.T) {
			t.Parallel()
			item := loadFindingFixture(t, filepath.Join(root, fixtureName), fixtureName)
			applyExternalFindingState(&item, rule.ID)
			findings := finding.AnalyzeSDK(item)
			if got := findFinding(findings, rule.ID); got == nil {
				t.Fatalf("fixture %q did not emit %q; findings = %#v", fixtureName, rule.ID, findings)
			}
		})
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var gotDirectories []string
	for _, entry := range entries {
		if entry.IsDir() {
			gotDirectories = append(gotDirectories, entry.Name())
		}
	}
	sort.Strings(wantDirectories)
	sort.Strings(gotDirectories)
	if strings.Join(gotDirectories, "\n") != strings.Join(wantDirectories, "\n") {
		t.Fatalf("finding fixture directories do not match embedded rules\n got: %v\nwant: %v", gotDirectories, wantDirectories)
	}
}

func loadFindingFixture(t *testing.T, directory, name string) sdk.SDK {
	t.Helper()
	item, err := sdk.Read(directory, name, sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	parser := shell.NewParser()
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		parsed := parser.Parse(hook.Content, filepath.ToSlash(filepath.Join(item.Name, hook.Path)))
		hook.Parse = &parsed
		analyzed := analysis.Analyze(string(hook.Name), &parsed)
		hook.Analysis = &analyzed
	}
	return *item
}

func applyExternalFindingState(item *sdk.SDK, findingID string) {
	switch findingID {
	case "assurance.archive-digest-recorded":
		item.Source = sdk.SourceStore
		item.State = sdk.StateResolved
		item.Digest = "sha3-384:finding-fixture"
	case "risk.unresolved-sdk":
		item.State = sdk.StateNotResolved
	case "risk.resource-limit-exceeded":
		item.State = sdk.StateInvalidArtifact
		item.Diagnostics = append(item.Diagnostics, sdk.Diagnostic{
			Code: "resource-limit", Severity: sdk.SeverityError, Phase: "inventory",
			Message: "finding fixture resource-limit exceeded",
		})
	}
}
