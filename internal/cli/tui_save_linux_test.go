package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
)

func TestSaveReviewedRules(t *testing.T) {
	project := t.TempDir()
	path := filepath.Join(project, finding.SuppressionPath)
	r := finding.SuppressionRule{ID: "one", SDK: "demo", Hook: "setup-project", Risk: "risk.persistence-write", Lines: []int{29}}
	save := func(reason string) error { return saveReviewedRules(project, []finding.SuppressionRule{r}, reason) }
	if err := save("   "); err == nil {
		t.Fatal("accepted empty reason")
	}
	if err := save(" サービスを配置する "); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	original := "# project decisions\n" + read()
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	r.ID = "two"
	if err := save("duplicate"); err == nil || read() != original {
		t.Fatal("overlap modified file")
	}
	r.Lines = []int{33}
	if err := save("enable service"); err != nil {
		t.Fatal(err)
	}
	result := read()
	if !strings.Contains(result, "\n\n    - id: two") {
		t.Fatalf("missing blank line between rules: %s", result)
	}
	rules, err := finding.ParseSuppression([]byte(result))
	if err != nil || len(rules) != 2 || rules[0].Reason != "サービスを配置する" || rules[1].Reason != "enable service" || !strings.Contains(result, "# project decisions") {
		t.Fatalf("updated rules: %s (%v)", result, err)
	}
	for _, existing := range []string{strings.Replace(original, "line: [29]", "", 1), "invalid: [yaml"} {
		if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
			t.Fatal(err)
		}
		if err := save("another"); err == nil || read() != existing {
			t.Fatal("unexpected replacement")
		}
	}
}

func TestDeleteReviewedRule(t *testing.T) {
	project := t.TempDir()
	r := finding.SuppressionRule{ID: "one", SDK: "demo", Hook: "setup-project", Risk: "risk.persistence-write", Reason: "expected", Lines: []int{29, 33}}
	if err := saveReviewedRules(project, []finding.SuppressionRule{r}, r.Reason); err != nil {
		t.Fatal(err)
	}
	stale := r
	stale.Reason = "old"
	if err := deleteReviewedRule(project, stale); err == nil {
		t.Fatal("deleted modified rule")
	}
	if err := deleteReviewedRule(project, r); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(project, finding.SuppressionPath))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := finding.ParseSuppression(data)
	if err != nil || len(rules) != 0 {
		t.Fatalf("rules after delete: %s (%v)", data, err)
	}
}
