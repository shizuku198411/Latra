package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
)

func TestRiskConditionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		expr  string
		score int
		level string
		want  bool
	}{
		{"risk>=0", 0, "info", true}, {"risk>0", 0, "info", false}, {"risk>80", 80, "critical", false}, {"risk>=80", 80, "critical", true}, {"risk>100", 100, "critical", false}, {"risk>=100", 100, "critical", true}, {"risk>=high", 49, "medium", false}, {"risk>=high", 50, "high", true}, {"risk>=high", 80, "critical", true}, {"risk>=critical", 79, "high", false}, {"risk>=critical", 80, "critical", true},
	} {
		c, err := parseRiskCondition(tc.expr)
		if err != nil || c.matches(finding.ScoredAxis{Score: tc.score, Level: tc.level}) != tc.want {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	for _, args := range [][]string{{"--fail-on"}, {"--fail-on=risk>=101"}, {"--fail-on=risk=-1"}, {"--fail-on=risk>high"}, {"--fail-on=priority=high"}, {"--fail-on=risk>=unknown"}, {"--fail-on=risk>=high", "--fail-on=risk>10"}} {
		if code := runScan(args, &bytes.Buffer{}, &bytes.Buffer{}, Dependencies{}); code != exitUsage {
			t.Errorf("%v: %d", args, code)
		}
	}
}

func TestScanRiskGate(t *testing.T) {
	root := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	summary := filepath.Join(t.TempDir(), "summary")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	run := func(expr string, want int) string {
		t.Helper()
		var out, diag bytes.Buffer
		code := runScan([]string{"--project", root, "--format=json", "--fail-on", expr}, &out, &diag, Dependencies{})
		if code != want || !json.Valid(out.Bytes()) {
			t.Fatalf("code=%d stderr=%s", code, &diag)
		}
		data, err := os.ReadFile(summary)
		if err != nil || !strings.Contains(string(data), "### Latra scan") {
			t.Fatalf("summary: %s %v", data, err)
		}
		return diag.String()
	}
	write("workshop.yaml", "name: dev\nbase: ubuntu@24.04\n")
	if !strings.Contains(run("risk>=0", 0), "0 SDKs evaluated") {
		t.Fatal("missing empty result")
	}
	write("workshop.yaml", "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: project-one\n  - name: project-two\n")
	for _, name := range []string{"one", "two"} {
		write(".workshop/"+name+"/sdk.yaml", "name: "+name+"\n")
		write(".workshop/"+name+"/hooks/setup-project", "#!/bin/bash\nsystemctl --user enable --now demo.service\n")
	}
	if got := run("risk>0", 1); !strings.Contains(got, "2 of 2") || !strings.Contains(got, "  one ") || !strings.Contains(got, "  two ") {
		t.Fatal(got)
	}
	write(".latra/suppression_rule.yaml", "version: 1\nrules:\n  - id: accepted\n    sdk: one\n    risk: risk.persistence-write\n    hook: setup-project\n    reason: expected\n")
	if got := run("risk>0", 1); !strings.Contains(got, "1 of 2") || !strings.Contains(got, "  two ") {
		t.Fatal(got)
	}
	write(".latra/suppression_rule.yaml", "invalid: [")
	if got := run("risk>0", 1); !strings.Contains(got, "2 of 2") {
		t.Fatal(got)
	}
}
