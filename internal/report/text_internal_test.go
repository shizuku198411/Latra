package report

import (
	"strings"
	"testing"
)

func TestAssessmentScoreColorDirection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		level    string
		positive bool
		color    string
	}{
		{name: "critical risk", level: "critical", color: ansiBrightRed},
		{name: "high risk", level: "high", color: ansiRed},
		{name: "medium risk", level: "medium", color: ansiYellow},
		{name: "low risk", level: "low", color: ansiCyan},
		{name: "no risk", level: "info", color: ansiGreen},
		{name: "high assurance", level: "high", positive: true, color: ansiGreen},
		{name: "medium assurance", level: "medium", positive: true, color: ansiYellow},
		{name: "low assurance", level: "low", positive: true, color: ansiRed},
		{name: "no assurance", level: "info", positive: true, color: ansiBrightRed},
		{name: "sufficient coverage", level: "sufficient", positive: true, color: ansiGreen},
		{name: "insufficient coverage", level: "insufficient", positive: true, color: ansiBrightRed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := formatAssessmentScore(50, test.level, test.positive, true)
			if !strings.HasPrefix(got, test.color) || !strings.HasSuffix(got, ansiReset) {
				t.Errorf("formatAssessmentScore() = %q, want color prefix %q and reset", got, test.color)
			}
		})
	}
}

func TestAssessmentScoreColorCanBeDisabled(t *testing.T) {
	t.Parallel()

	if got := formatAssessmentScore(80, "critical", false, false); got != "80/100 (critical)" {
		t.Errorf("formatAssessmentScore() = %q", got)
	}
}

func TestAssessmentBarUsesScoreWidthAndColor(t *testing.T) {
	t.Parallel()

	if got := formatAssessmentBar(50, "medium", false, false); got != "[██████████░░░░░░░░░░]" {
		t.Errorf("formatAssessmentBar() = %q", got)
	}
	got := formatAssessmentBar(80, "high", true, true)
	if !strings.HasPrefix(got, ansiWhite+"["+ansiGreen) ||
		!strings.Contains(got, ansiWhite+"░░░░]") ||
		!strings.HasSuffix(got, "]"+ansiReset) {
		t.Errorf("colored assessment bar = %q", got)
	}
}

func TestAssuranceDisplayLevelsUsePositiveLanguage(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"high":   "strong",
		"medium": "moderate",
		"low":    "limited",
		"info":   "none",
	}
	for level, want := range tests {
		if got := assuranceDisplayLevel(level); got != want {
			t.Errorf("assuranceDisplayLevel(%q) = %q, want %q", level, got, want)
		}
	}
}
