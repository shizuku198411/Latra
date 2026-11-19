// Project suppression rules record reviewed risks without changing scan evidence.
package finding

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/shizuku198411/Latra/internal/findingconfig"
	"github.com/shizuku198411/Latra/internal/sdk"
	"go.yaml.in/yaml/v3"
)

const SuppressionPath = ".latra/suppression_rule.yaml"

type SuppressionConfig struct {
	Version int               `yaml:"version"`
	Rules   []SuppressionRule `yaml:"rules"`
}

type SuppressionRule struct {
	ID     string       `yaml:"id" json:"id"`
	Risk   string       `yaml:"risk" json:"risk"`
	SDK    string       `yaml:"sdk" json:"sdk"`
	Hook   sdk.HookName `yaml:"hook" json:"hook"`
	Reason string       `yaml:"reason" json:"reason"`
	Lines  []int        `yaml:"line,omitempty,flow" json:"line,omitempty"`
}

func ParseSuppression(data []byte) ([]SuppressionRule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var config SuppressionConfig
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("expected one YAML document")
	}
	if config.Version != 1 || config.Rules == nil {
		return nil, fmt.Errorf("expected version: 1 and a rules list")
	}
	known := make(map[string]bool)
	for _, rule := range findingconfig.MustDefault().Rules {
		known[rule.ID] = rule.Kind == string(KindRisk)
	}
	ids := make(map[string]bool)
	for i, rule := range config.Rules {
		if strings.TrimSpace(rule.ID) == "" || ids[rule.ID] || !known[rule.Risk] || strings.TrimSpace(rule.SDK) == "" || !slices.Contains(sdk.HookNames, rule.Hook) || strings.TrimSpace(rule.Reason) == "" {
			return nil, fmt.Errorf("rule %d: expected unique id, known risk and hook, sdk and reason", i+1)
		}
		ids[rule.ID] = true
		if rule.Lines != nil && (len(rule.Lines) == 0 || slices.Min(rule.Lines) < 1) {
			return nil, fmt.Errorf("rule %q: line must be a non-empty list of positive integers", rule.ID)
		}
	}
	return config.Rules, nil
}

type SuppressionResult struct {
	SuppressionRule
	Count  int    `json:"count"`
	Status string `json:"status"`
}

// ApplySuppressions annotates raw findings and returns the assessment input.
// If rules overlap, the first matching rule owns the finding.
func ApplySuppressions(findings []Finding, rules []SuppressionResult) []Finding {
	if len(rules) == 0 {
		return findings
	}
	active := make([]Finding, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		if f.Kind == KindRisk {
			for j := range rules {
				r := &rules[j]
				if r.Risk != f.ID || r.SDK != f.Scope.SDK || r.Hook != f.Scope.Hook {
					continue
				}
				if r.Lines != nil && !slices.Contains(r.Lines, f.CommandLine) {
					continue
				}
				f.SuppressedBy = r.ID
				r.Count++
				r.Status = "applied"
				break
			}
		}
		if f.SuppressedBy == "" {
			active = append(active, *f)
		}
	}
	return active
}
