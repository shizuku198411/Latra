package cli

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shizuku198411/Latra/internal/report"
)

// tuiRisk is a view-only annotation. Source lines and their numbering remain unchanged.
type tuiRisk struct {
	ID, Title, Severity, Value string
	Score                      int
}

// risksForPreview reuses the scanner's already aggregated KeyRisks and their
// evidence locations. A scope without an exact source location is not annotated.
func risksForPreview(document *report.Document, sdkName, file string) map[int][]tuiRisk {
	if document == nil {
		return nil
	}
	annotations := make(map[int][]tuiRisk)
	for _, assessment := range document.Assessment.BySDK {
		if assessment.SDK != sdkName {
			continue
		}
		for _, risk := range assessment.KeyRisks {
			for _, scope := range risk.Scopes {
				if scope.SDK != sdkName || scope.Location == nil || scope.Location.StartLine < 1 {
					continue
				}
				locationPath := tuiRiskPath(scope.Location.Path, sdkName)
				if locationPath != path.Clean(file) {
					continue
				}
				item := tuiRisk{ID: risk.ID, Title: risk.Title, Severity: risk.Severity, Score: risk.Score, Value: scope.Value}
				// Multiple evidence objects for one finding can point to the same line.
				duplicate := false
				for _, existing := range annotations[scope.Location.StartLine] {
					if existing == item {
						duplicate = true
						break
					}
				}
				if !duplicate {
					annotations[scope.Location.StartLine] = append(annotations[scope.Location.StartLine], item)
				}
			}
		}
		break
	}
	return annotations
}

// tuiRiskPath resolves the scanner's SDK-prefixed paths to Explorer paths.
// Both preview annotations and tree markers must use identical matching.
func tuiRiskPath(locationPath, sdkName string) string {
	return path.Clean(strings.TrimPrefix(path.Clean(locationPath), sdkName+"/"))
}

// tuiTreeRisks indexes only findings backed by an exact file location.
// A directory inherits the most severe risk anywhere below it, without
// reading the SDK's filesystem or expanding nodes in the Explorer.
func tuiTreeRisks(document *report.Document, sdkName string) map[string]string {
	if document == nil {
		return nil
	}
	levels := make(map[string]string)
	for _, assessment := range document.Assessment.BySDK {
		if assessment.SDK != sdkName {
			continue
		}
		for _, risk := range assessment.KeyRisks {
			for _, scope := range risk.Scopes {
				if scope.SDK != sdkName || scope.Location == nil || scope.Location.StartLine < 1 {
					continue
				}
				file := tuiRiskPath(scope.Location.Path, sdkName)
				if file == "." || file == ".." || strings.HasPrefix(file, "../") || path.IsAbs(file) {
					continue
				}
				for current := file; current != "."; current = path.Dir(current) {
					if tuiRiskSeverityRank(risk.Severity) > tuiRiskSeverityRank(levels[current]) {
						levels[current] = risk.Severity
					}
				}
			}
		}
		break
	}
	return levels
}

func tuiRiskSeverityRank(level string) int {
	switch level {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// tuiPreviewRows counts terminal rows, not source lines. Scroll remains a source
// line index, so inserted risk labels cannot change navigation semantics.
func tuiPreviewRows(preview *tuiPreview, annotations map[int][]tuiRisk, width, height int) []string {
	rows := make([]string, 0, height)
	if preview == nil || height <= 0 {
		return rows
	}
	// Carry evidence values across shell lines ending in a continuation slash.
	// Rebuild from the start so scrolling into the middle of a command still
	// highlights values from findings attached to its first line.
	var continued []tuiRisk
	for i, code := range preview.Lines {
		if i >= preview.Scroll && len(rows) >= height {
			break
		}
		atLine := annotations[i+1]
		active := append(append([]tuiRisk(nil), continued...), atLine...)
		if i >= preview.Scroll {
			// A finding may have several evidence values on the same line.
			// Display its label once, but retain every value for highlighting.
			seen := make(map[string]bool)
			for _, risk := range atLine {
				key := risk.ID + "\x00" + risk.Title + "\x00" + risk.Severity + fmt.Sprint(risk.Score)
				if seen[key] {
					continue
				}
				seen[key] = true
				label := fmt.Sprintf(" #Risk > %s, %s, score=%d/100", risk.Title, risk.Severity, risk.Score)
				rows = append(rows, report.ColorReviewPriority(fitLine(safeTUILabel(label), width), risk.Severity))
				if len(rows) == height {
					break
				}
			}
			if len(rows) == height {
				break
			}
			if len(code) >= 7 {
				code = code[:7] + highlightTUIRiskValues(code[7:], active)
			}
			rows = append(rows, fitTUIANSI(" "+code, width))
		}
		if len(code) >= 7 && strings.HasSuffix(strings.TrimSpace(code[7:]), "\\") {
			continued = active
		} else {
			continued = nil
		}
	}
	return rows
}

// highlightTUIRiskValues colors every distinct evidence value present in a
// source line, without allowing overlapping matches to corrupt ANSI sequences.
func highlightTUIRiskValues(contents string, risks []tuiRisk) string {
	type match struct {
		start, end int
		severity   string
	}
	var matches []match
	for _, risk := range risks {
		value := strings.ReplaceAll(risk.Value, "\t", "    ")
		if value == "" {
			continue
		}
		for offset := 0; offset < len(contents); {
			index := strings.Index(contents[offset:], value)
			if index < 0 {
				break
			}
			start := offset + index
			matches = append(matches, match{start, start + len(value), risk.Severity})
			offset = start + len(value)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].start != matches[j].start {
			return matches[i].start < matches[j].start
		}
		if matches[i].end != matches[j].end {
			return matches[i].end > matches[j].end
		}
		return tuiRiskSeverityRank(matches[i].severity) > tuiRiskSeverityRank(matches[j].severity)
	})
	var result strings.Builder
	last := 0
	for _, m := range matches {
		if m.start < last {
			continue
		}
		result.WriteString(contents[last:m.start])
		result.WriteString(report.ColorReviewPriority(contents[m.start:m.end], m.severity))
		last = m.end
	}
	result.WriteString(contents[last:])
	return result.String()
}

func safeTUILabel(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\x1b' {
			return ' '
		}
		return r
	}, s)
}

// fitTUIANSI truncates visible characters while preserving SGR color escapes.
// Never split an escape sequence, and reset attributes after a truncated line.
func fitTUIANSI(s string, width int) string {
	if width <= 0 {
		return ""
	}
	var b strings.Builder
	visible := 0
	for i := 0; i < len(s) && visible < width; {
		if strings.HasPrefix(s[i:], "\x1b[") {
			if end := strings.IndexByte(s[i:], 'm'); end >= 0 && end < 32 {
				sequence := s[i : i+end+1]
				b.WriteString(sequence)
				i += end + 1
				continue
			}
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == '\x1b' || unicode.IsControl(r) {
			i += n
			continue
		}
		b.WriteRune(r)
		visible++
		i += n
	}
	b.WriteString("\x1b[0m")
	return b.String()
}
