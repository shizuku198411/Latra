package cli

import (
	"fmt"
	"strings"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/shell"
	"go.yaml.in/yaml/v3"
)

// Generate rule templates for the selected risk occurrence.
func (m *tuiExplorer) previewSuppression(width int) {
	p := m.Preview
	if p == nil || p.DetailKind != "" {
		return
	}
	if m.Scanning {
		m.Message = "Scan in progress"
		return
	}
	if p.SelectedRisk.ID == "" {
		m.Message = "Select a risk with j/k first"
		return
	}
	if m.Scan == nil {
		m.Message = "Scan result unavailable"
		return
	}
	config := finding.SuppressionConfig{Version: 1}
	first, last := p.SelectedRisk.Line, p.SelectedRisk.Line
	var deleteRule *finding.SuppressionRule
	if p.SelectedRisk.RuleID != "" {
		for _, r := range m.Scan.Suppressions {
			if r.ID == p.SelectedRisk.RuleID {
				rule := r.SuppressionRule
				deleteRule = &rule
				config.Rules = append(config.Rules, rule)
				break
			}
		}
		if deleteRule == nil {
			m.Message = "Suppression rule unavailable"
			return
		}
	} else {
		seen := make(map[string]bool)
		for _, item := range m.Scan.SDKs {
			if item.Name != m.SDKs[m.SelectedSDK].Name {
				continue
			}
			for _, f := range item.Findings {
				if f.ID != p.SelectedRisk.ID || f.Kind != finding.KindRisk || f.Scope.Hook == "" || f.SuppressedBy != "" {
					continue
				}
				r := finding.SuppressionRule{Risk: f.ID, SDK: item.Name, Hook: f.Scope.Hook, Reason: "Describe why this risk is expected"}
				r.ID = fmt.Sprintf("%s-%s-%s", item.Name, f.Scope.Hook, f.ID)
				atLine := false
				for _, e := range f.Evidence {
					for _, loc := range []*shell.Location{e.Location, e.ValueLocation} {
						if loc != nil && tuiRiskPath(loc.Path, item.Name) == p.Path && loc.StartLine == p.SelectedRisk.Line {
							atLine = true
						}
					}
				}
				if !atLine {
					continue
				}
				if f.CommandLine == 0 {
					continue
				}
				first = min(first, f.CommandLine)
				loc := tuiScanOperationLocation(m.Scan, item.Name, f.Scope.Hook, f.Evidence[0].OperationID)
				if loc != nil && tuiRiskPath(loc.Path, item.Name) == p.Path {
					last = max(last, loc.EndLine)
				}
				r.Lines = []int{f.CommandLine}
				r.ID += fmt.Sprintf("-%d", f.CommandLine)
				if !seen[r.ID] {
					config.Rules = append(config.Rules, r)
					seen[r.ID] = true
				}
			}
		}
	}
	var lines []string
	for n := first; n <= min(last, len(p.SourceLines)); n++ {
		lines = append(lines, fmt.Sprintf("%5d  %s", n, safeTUILabel(strings.ReplaceAll(p.SourceLines[n-1], "\t", "    "))))
	}
	lines = append(lines, strings.Repeat("─", max(1, width-1)))
	if len(config.Rules) == 0 {
		m.Preview = &tuiPreview{Previous: p, DetailKind: "Risk review", Path: p.SelectedRisk.ID, Status: "Read-only", Lines: append(lines, p.SelectedRisk.ID, fmt.Sprintf("%s:%d", safeTUILabel(p.Path), p.SelectedRisk.Line), "This finding cannot be attributed to a single command.")}
		m.Message = ""
		return
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		m.Message = err.Error()
		return
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		// YAML's escaped newline keeps long IDs copyable on
		// narrower terminals without introducing whitespace into the value.
		key, value, ok := strings.Cut(line, ": ")
		indent := strings.Repeat(" ", len(line)-len(strings.TrimLeft(line, " "))+4)
		chunk := width - len(indent) - 3
		if ok && len(line) >= width && chunk >= 8 && !strings.ContainsAny(value, " \\\"") && len(key)+4 < width {
			lines = append(lines, key+": \"\\")
			for len(value) > chunk {
				lines = append(lines, indent+value[:chunk]+"\\")
				value = value[chunk:]
			}
			lines = append(lines, indent+value+"\"")
		} else {
			lines = append(lines, safeTUILabel(line))
		}

	}
	m.Preview = &tuiPreview{DetailKind: "Rule templates", Path: finding.SuppressionPath, Status: "Press a to add the displayed rules", Rules: config.Rules, Lines: lines, Previous: p}
	if deleteRule != nil {
		m.Preview.DeleteRule = deleteRule
		m.Preview.Rules = nil
		m.Preview.DetailKind = "Suppression rule"
		m.Preview.Status = "Press d to delete this entire rule"
	}
	m.Message = ""
}
