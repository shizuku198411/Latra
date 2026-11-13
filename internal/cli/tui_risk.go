package cli

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

// tuiRisk is a view-only annotation. Source lines and their numbering remain unchanged.
type tuiRisk struct {
	Kind, ID, Title, Severity, Value string
	Score                            int
	Resolution                       analysis.Resolution
	Derivation                       finding.EvidenceDerivation
	ValueLocation                    *shell.Location
	HighlightOnly                    bool
}

type tuiHighlightMatch struct {
	start, end int
	severity   string
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
		labels := make(map[string]bool)
		for _, risk := range assessment.KeyRisks {
			derivation, resolution := tuiRiskEvidenceState(risk.Scopes)
			for _, scope := range risk.Scopes {
				if scope.SDK != sdkName {
					continue
				}
				location := scope.ValueLocation
				if location == nil {
					location = scope.Location
				}
				if location == nil || location.StartLine < 1 {
					continue
				}
				locationPath := tuiRiskPath(location.Path, sdkName)
				if locationPath != path.Clean(file) {
					continue
				}
				labelKey := risk.ID + "\x00" + risk.Title + "\x00" + risk.Severity
				value := scope.Value
				if value == "" {
					value = scope.Expression
				}
				item := tuiRisk{Kind: "risk", ID: risk.ID, Title: risk.Title, Severity: risk.Severity, Score: risk.Score, Value: value,
					Resolution: resolution, Derivation: derivation,
					ValueLocation: scope.ValueLocation, HighlightOnly: labels[labelKey]}
				// Multiple evidence objects for one finding can point to the same line.
				duplicate := false
				for _, existing := range annotations[location.StartLine] {
					if sameTUIRiskEvidence(existing, item) {
						duplicate = true
						break
					}
				}
				if !duplicate {
					annotations[location.StartLine] = append(annotations[location.StartLine], item)
					labels[labelKey] = true
				}
			}
		}
		for _, gap := range assessment.Coverage.Semantics.Gaps {
			location := tuiSemanticGapLocation(document, sdkName, gap.Hook, gap.OperationID)
			if location == nil || location.StartLine < 1 || tuiRiskPath(location.Path, sdkName) != path.Clean(file) {
				continue
			}
			item := tuiRisk{Kind: "semantic-gap", ID: gap.Dimension + "/" + gap.Code, Title: gap.Message, Severity: gap.Severity}
			annotations[location.StartLine] = append(annotations[location.StartLine], item)
		}
		break
	}
	return annotations
}

func tuiRiskEvidenceState(scopes []finding.RiskScope) (finding.EvidenceDerivation, analysis.Resolution) {
	derivation := finding.EvidenceDerivation("")
	resolution := analysis.Resolution("")
	derivationRank := map[finding.EvidenceDerivation]int{
		finding.EvidenceDirect: 1, finding.EvidenceInferred: 2, finding.EvidenceUnresolved: 3,
	}
	resolutionRank := map[analysis.Resolution]int{
		analysis.Resolved: 1, analysis.PartiallyResolved: 2, analysis.Unknown: 3,
	}
	for _, scope := range scopes {
		if derivationRank[scope.Derivation] > derivationRank[derivation] {
			derivation = scope.Derivation
		}
		if resolutionRank[scope.Resolution] > resolutionRank[resolution] {
			resolution = scope.Resolution
		}
	}
	return derivation, resolution
}

func sameTUIRiskEvidence(left, right tuiRisk) bool {
	if left.Kind != right.Kind || left.ID != right.ID || left.Title != right.Title || left.Severity != right.Severity || left.Value != right.Value || left.Score != right.Score ||
		left.Resolution != right.Resolution || left.Derivation != right.Derivation {
		return false
	}
	if left.ValueLocation == nil || right.ValueLocation == nil {
		return left.ValueLocation == nil && right.ValueLocation == nil
	}
	return *left.ValueLocation == *right.ValueLocation
}

func tuiSemanticGapLocation(document *report.Document, sdkName string, hook sdk.HookName, operationID string) *shell.Location {
	if operationID == "" {
		return nil
	}
	for _, item := range document.SDKs {
		if item.Name != sdkName {
			continue
		}
		for _, itemHook := range item.Hooks {
			if hook != "" && itemHook.Name != hook {
				continue
			}
			if location := tuiOperationLocation(itemHook.Operations, operationID); location != nil {
				return location
			}
		}
		break
	}
	return nil
}

func tuiOperationLocation(operations []analysis.Operation, operationID string) *shell.Location {
	for _, operation := range operations {
		if operation.ID == operationID {
			location := operation.Location
			return &location
		}
		if location := tuiOperationLocation(operation.Children, operationID); location != nil {
			return location
		}
	}
	return nil
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
				if scope.SDK != sdkName {
					continue
				}
				location := scope.ValueLocation
				if location == nil {
					location = scope.Location
				}
				if location == nil || location.StartLine < 1 {
					continue
				}
				file := tuiRiskPath(location.Path, sdkName)
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
		for _, gap := range assessment.Coverage.Semantics.Gaps {
			location := tuiSemanticGapLocation(document, sdkName, gap.Hook, gap.OperationID)
			if location == nil || location.StartLine < 1 {
				continue
			}
			addTUITreeLevel(levels, tuiRiskPath(location.Path, sdkName), gap.Severity)
		}
		break
	}
	return levels
}

func addTUITreeLevel(levels map[string]string, file, level string) {
	if file == "." || file == ".." || strings.HasPrefix(file, "../") || path.IsAbs(file) {
		return
	}
	for current := file; current != "."; current = path.Dir(current) {
		if tuiRiskSeverityRank(level) > tuiRiskSeverityRank(levels[current]) {
			levels[current] = level
		}
	}
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
				if risk.HighlightOnly {
					continue
				}
				key := risk.Kind + "\x00" + risk.ID + "\x00" + risk.Title + "\x00" + risk.Severity + fmt.Sprint(risk.Score)
				if seen[key] {
					continue
				}
				seen[key] = true
				label := fmt.Sprintf(" #Risk > %s, %s, score=%d/100", risk.Title, risk.Severity, risk.Score)
				if risk.Derivation != "" {
					label += fmt.Sprintf(", evidence=%s", risk.Derivation)
				}
				if risk.Resolution != "" && risk.Resolution != analysis.Resolved {
					label += fmt.Sprintf(", resolution=%s", risk.Resolution)
				}
				if risk.Kind == "semantic-gap" {
					label = fmt.Sprintf(" #Semantic Gap > [%s] %s", risk.ID, risk.Title)
				}
				rows = append(rows, report.ColorReviewPriority(fitLine(safeTUILabel(label), width), risk.Severity))
				if len(rows) == height {
					break
				}
			}
			if len(rows) == height {
				break
			}
			if len(code) >= 7 {
				source := code[7:]
				if i < len(preview.SourceLines) {
					source = preview.SourceLines[i]
				}
				code = code[:7] + highlightTUIRiskValuesAtLine(code[7:], source, active, i+1)
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

func highlightTUIRiskValuesAtLine(contents, source string, risks []tuiRisk, line int) string {
	var exact []tuiHighlightMatch
	var fallback []tuiRisk
	for _, risk := range risks {
		location := risk.ValueLocation
		if location == nil {
			fallback = append(fallback, risk)
			continue
		}
		if line < location.StartLine || line > location.EndLine || location.EndLine < location.StartLine {
			continue
		}
		start, end := 0, len(contents)
		if line == location.StartLine {
			start = tuiDisplayOffset(source, location.StartColumn-1)
		}
		if line == location.EndLine {
			end = tuiDisplayOffset(source, location.EndColumn-1)
		}
		if start < 0 || end <= start || start >= len(contents) || end > len(contents) {
			continue
		}
		exact = append(exact, tuiHighlightMatch{start: start, end: end, severity: risk.Severity})
	}
	styled := highlightTUIRanges(contents, exact)
	if len(fallback) == 0 {
		return styled
	}
	return highlightTUIRiskValues(styled, fallback)
}

func tuiDisplayOffset(source string, sourceOffset int) int {
	if sourceOffset < 0 || sourceOffset > len(source) {
		return -1
	}
	return len(strings.ReplaceAll(source[:sourceOffset], "\t", "    "))
}

func highlightTUIRanges(contents string, ranges []tuiHighlightMatch) string {
	if len(ranges) == 0 {
		return contents
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		return ranges[i].end > ranges[j].end
	})
	var result strings.Builder
	last := 0
	for _, item := range ranges {
		if item.start < last {
			continue
		}
		result.WriteString(contents[last:item.start])
		result.WriteString(report.ColorReviewPriority(contents[item.start:item.end], item.severity))
		last = item.end
	}
	result.WriteString(contents[last:])
	return result.String()
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
