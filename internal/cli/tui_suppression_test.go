package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/report"
	"go.yaml.in/yaml/v3"
)

func TestReviewedPersistenceWorkflow(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("workshop.yaml", "name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: project-example\n")
	write(".workshop/example/sdk.yaml", "name: example\n")
	file := "hooks/setup-project"
	hook := ".workshop/example/" + file
	body := "#!/bin/bash\ninstall -D --mode=644 \"$SDK/files/setup-tap0.service\" \\\n  \"$HOME/.config/systemd/user/setup-tap0.service\"\nsystemctl --user enable --now setup-tap0.service\n"
	write(hook, body)
	scan := func() *report.Document {
		t.Helper()
		d, err := scanExplorer(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	raw := scan()
	const risk = "risk.persistence-write"
	m := tuiExplorer{Scan: raw, SDKs: []tuiSDK{{Name: "example"}}, Preview: &tuiPreview{Path: file, SourceLines: strings.Split(body, "\n")}}
	m.selectPreviewRisk(true)
	first := m.Preview.SelectedRisk
	m.selectPreviewRisk(true)
	if m.Preview.SelectedRisk == first {
		t.Fatal("next did not move the risk cursor")
	}
	m.selectPreviewRisk(false)
	if m.Preview.SelectedRisk != first || first.Line != 2 || first.ID != risk {
		t.Fatalf("previous risk: %+v", m.Preview.SelectedRisk)
	}
	m.previewSuppression(60)
	if m.Preview.Previous == nil {
		t.Fatalf("template missing: %s findings=%+v", m.Message, raw.SDKs[0].Findings)
	}
	view := m.Preview.Lines
	if len(view) < 4 || !strings.HasPrefix(view[0], "    2  install") || !strings.Contains(view[1], "setup-tap0.service") || view[2] != strings.Repeat("─", 59) {
		t.Fatalf("command review: %q", view)
	}
	rules, err := finding.ParseSuppression([]byte(strings.Join(view[3:], "\n")))
	if err != nil {
		t.Fatal(err)
	}
	var rule finding.SuppressionRule
	for _, r := range rules {
		if r.Risk == risk {
			rule = r
		}
	}
	if !reflect.DeepEqual(rule.Lines, []int{2}) {
		t.Fatalf("command rule: %+v", rule)
	}
	rule.Reason = "Reviewed service installation"
	save := func() {
		data, err := yaml.Marshal(finding.SuppressionConfig{Version: 1, Rules: []finding.SuppressionRule{rule}})
		if err != nil {
			t.Fatal(err)
		}
		write(finding.SuppressionPath, string(data))
	}
	save()
	partial := scan()
	if partial.Suppressions[0].Count != 1 || partial.Suppressions[0].Status != "applied" {
		t.Fatalf("partial: %+v", partial.Suppressions)
	}
	left := 0
	for _, r := range partial.Assessment.BySDK[0].KeyRisks {
		if r.ID == risk {
			left = r.Occurrences
		}
	}
	if left != 1 || !reflect.DeepEqual(partial.Assessment.Coverage, raw.Assessment.Coverage) || !reflect.DeepEqual(partial.Assessment.Assurance, raw.Assessment.Assurance) {
		t.Fatal("expected one remaining persistence finding and preserved coverage/assurance")
	}
	if a := risksForPreview(partial, "example", file); len(a[2]) == 0 || !strings.Contains(a[2][len(a[2])-1].Title, rule.Reason) {
		t.Fatalf("annotations: %+v", a)
	}
	result, err := scanAndParse(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, verbose := range []bool{false, true} {
		var out bytes.Buffer
		if err := writeReport(scanOptions{output: "-", format: report.FormatText, verbose: verbose}, &out, report.NewDocument(result)); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "Suppressed: 1") || strings.Contains(out.String(), rule.Reason) != verbose {
			t.Fatalf("CLI output: %s", out.String())
		}
	}
	write(hook, body+"# changed\n")
	edited := scan()
	if edited.Suppressions[0].Count != 1 || !reflect.DeepEqual(edited.Assessment.Risk, partial.Assessment.Risk) {
		t.Fatal("unrelated edit changed a line suppression")
	}
	rule.Lines = []int{2, 4}
	save()
	if got := scan().Suppressions[0].Count; got != 2 {
		t.Fatalf("multi-line rule matched %d findings", got)
	}
	rule.Lines = nil
	save()
	all := scan()
	if all.Suppressions[0].Count != 2 {
		t.Fatalf("hook rule: %+v", all.Suppressions)
	}
	for _, r := range all.Assessment.KeyRisks {
		if r.ID == risk {
			t.Fatal("suppressed persistence highlight")
		}
	}
	data, err := os.ReadFile(filepath.Join(root, finding.SuppressionPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"[]", "[2, 0]", "2"} {
		if _, err := finding.ParseSuppression(append(data, []byte("      line: "+value+"\n")...)); err == nil {
			t.Fatalf("accepted invalid line: %s", value)
		}
	}
	write(finding.SuppressionPath, "version: 1\nrules: []\ntypo: true\n")
	d := scan()
	if !reflect.DeepEqual(d.Assessment.Risk, raw.Assessment.Risk) || len(d.Suppressions) != 0 {
		t.Fatal("invalid config changed risk assessment")
	}
	m.finishScan(d, nil)
	if !strings.Contains(m.ScanStatus, "Suppression rules ignored") {
		t.Fatalf("Explorer status: %s", m.ScanStatus)
	}
	result, err = scanAndParse(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := report.WriteTextSummary(&out, result); err != nil || !strings.Contains(out.String(), "Suppression rules ignored") || !strings.Contains(out.String(), "Assessment") {
		t.Fatalf("compact output: %s (%v)", out.String(), err)
	}
}
