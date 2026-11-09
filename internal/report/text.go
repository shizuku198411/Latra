// Package report renders Latra scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
	"github.com/shizuku198411/Latra/internal/source"
)

const (
	ansiReset     = "\x1b[0m"
	ansiRed       = "\x1b[31m"
	ansiGreen     = "\x1b[32m"
	ansiYellow    = "\x1b[33m"
	ansiCyan      = "\x1b[36m"
	ansiWhite     = "\x1b[37m"
	ansiBrightRed = "\x1b[91m"
)

// TextOptions controls terminal-specific text rendering.
type TextOptions struct {
	Color bool
}

// WriteText renders the complete SDK inventory in a deterministic format.
func WriteText(writer io.Writer, result *source.Result) error {
	return WriteTextWithOptions(writer, result, TextOptions{})
}

// WriteTextWithOptions renders the complete SDK inventory with explicit text options.
func WriteTextWithOptions(writer io.Writer, result *source.Result, options TextOptions) error {
	document := NewDocument(result)
	if _, err := fmt.Fprintf(writer, "Input\n  Kind: %s\n  Root: %s\n", document.Input.Kind, document.Input.Root); err != nil {
		return err
	}
	if len(document.Workshops) > 0 {
		if _, err := fmt.Fprintln(writer, "\nWorkshops"); err != nil {
			return err
		}
		for _, workshop := range document.Workshops {
			if _, err := fmt.Fprintf(writer, "  %s\n    Definition: %s\n    Base: %s\n", workshop.Name, workshop.Definition, workshop.Base); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(writer, "\nSDKs"); err != nil {
		return err
	}
	for _, item := range document.SDKs {
		if err := writeSDK(writer, item); err != nil {
			return err
		}
	}
	if err := writeSummary(writer, document.Summary, document.Assessment, false); err != nil {
		return err
	}
	if err := writeObservations(writer, document, true); err != nil {
		return err
	}
	if err := writeAssessment(writer, document.Assessment, options.Color); err != nil {
		return err
	}
	return writeDocumentDiagnostics(writer, document.Diagnostics)
}

// WriteTextSummary renders input, Workshop definitions, and the summary only.
func WriteTextSummary(writer io.Writer, result *source.Result) error {
	return WriteTextSummaryWithOptions(writer, result, TextOptions{})
}

// WriteTextSummaryWithOptions renders the compact representation with explicit text options.
func WriteTextSummaryWithOptions(writer io.Writer, result *source.Result, options TextOptions) error {
	document := NewDocument(result)
	if _, err := fmt.Fprintf(writer, "Input\n  Kind: %s\n  Root: %s\n", document.Input.Kind, document.Input.Root); err != nil {
		return err
	}
	if len(document.Workshops) > 0 {
		if _, err := fmt.Fprintln(writer, "\nWorkshops"); err != nil {
			return err
		}
		for _, workshop := range document.Workshops {
			if _, err := fmt.Fprintf(writer, "  %s\n    Definition: %s\n    Base: %s\n", workshop.Name, workshop.Definition, workshop.Base); err != nil {
				return err
			}
		}
	}
	if err := writeSummary(writer, document.Summary, document.Assessment, true); err != nil {
		return err
	}
	if err := writeObservations(writer, document, false); err != nil {
		return err
	}
	if err := writeAssessment(writer, document.Assessment, options.Color); err != nil {
		return err
	}
	return writeDocumentDiagnostics(writer, document.Diagnostics)
}

func writeObservations(writer io.Writer, document Document, verbose bool) error {
	if _, err := fmt.Fprintf(writer, "\nObservations\n  Project Access: %d", document.Summary.Observations.Count); err != nil {
		return err
	}
	reads, writes := 0, 0
	for _, item := range document.Summary.Observations.BySDK {
		reads += item.ProjectAccess.Reads
		writes += item.ProjectAccess.Writes
	}
	if _, err := fmt.Fprintf(writer, " (%d reads, %d writes)\n", reads, writes); err != nil {
		return err
	}
	if !verbose {
		if _, err := fmt.Fprintln(writer, "  By SDK:"); err != nil {
			return err
		}
		wrote := false
		for _, item := range document.Summary.Observations.BySDK {
			if item.Count == 0 {
				continue
			}
			wrote = true
			if _, err := fmt.Fprintf(writer, "    %s: %d (%d reads, %d writes)\n", item.SDKName, item.Count, item.ProjectAccess.Reads, item.ProjectAccess.Writes); err != nil {
				return err
			}
		}
		if !wrote {
			_, err := fmt.Fprintln(writer, "    -")
			return err
		}
		return nil
	}
	if document.Summary.Observations.Count == 0 {
		_, err := fmt.Fprintln(writer, "    -")
		return err
	}
	for _, item := range document.SDKs {
		var observations []finding.Finding
		for _, itemFinding := range item.Findings {
			if itemFinding.Kind == finding.KindObservation {
				observations = append(observations, itemFinding)
			}
		}
		if len(observations) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(writer, "    %s:\n", item.Name); err != nil {
			return err
		}
		for _, access := range []struct {
			id, label string
		}{{"observation.project-read", "Read"}, {"observation.project-write", "Write"}} {
			var matching []finding.Finding
			for _, observation := range observations {
				if observation.ID == access.id {
					matching = append(matching, observation)
				}
			}
			if len(matching) == 0 {
				continue
			}
			if _, err := fmt.Fprintf(writer, "      %s:\n", access.label); err != nil {
				return err
			}
			for _, observation := range matching {
				for _, evidence := range observation.Evidence {
					value := evidence.NormalizedValue
					if value == "" {
						value = evidence.Value
					}
					file := "-"
					if evidence.Location != nil {
						location := *evidence.Location
						for _, hook := range item.Hooks {
							if hook.Name == observation.Scope.Hook {
								location.Path = hook.Path
								break
							}
						}
						file = locationString(location)
					}
					if _, err := fmt.Fprintf(writer, "        sdk=%s file=%s hook=%s value=%q raw=%q resolution=%s\n",
						item.Name, file, observation.Scope.Hook, value, evidence.Value, evidence.Resolution); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func writeAssessment(writer io.Writer, assessment finding.Assessment, color bool) error {
	if _, err := fmt.Fprintf(writer, "\nAssessment\n  Classification: %s\n", assessment.Classification); err != nil {
		return err
	}
	if err := writeAssessmentScores(writer, assessment.ReviewPriority, assessment.Risk, assessment.Assurance, assessment.Coverage, "  ", color); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "  By SDK:"); err != nil {
		return err
	}
	if len(assessment.BySDK) == 0 {
		_, err := fmt.Fprintln(writer, "    -")
		return err
	}
	for _, item := range assessment.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s: %s\n", item.SDK, item.Classification); err != nil {
			return err
		}
		if err := writeAssessmentScores(writer, item.ReviewPriority, item.Risk, item.Assurance, item.Coverage, "      ", color); err != nil {
			return err
		}
		if err := writeKeyRisks(writer, item.KeyRisks, "      "); err != nil {
			return err
		}
	}
	return nil
}

func writeAssessmentScores(writer io.Writer, priority finding.Score, risk, assurance finding.ScoredAxis, coverage finding.Coverage, indent string, color bool) error {
	items := []struct {
		label     string
		score     int
		level     string
		positive  bool
		assurance bool
	}{
		{label: "Review Priority:", score: priority.Score, level: priority.Level},
		{label: "Risk:", score: risk.Score, level: risk.Level},
		{label: "Assurance:", score: assurance.Score, level: assurance.Level, positive: true, assurance: true},
		{label: "Coverage:", score: coverage.Score, level: coverage.Level, positive: true},
	}
	for _, item := range items {
		displayLevel := item.level
		if item.assurance {
			displayLevel = assuranceDisplayLevel(item.level)
		}
		value := fmt.Sprintf("%d/100 (%s)", item.score, displayLevel)
		padding := strings.Repeat(" ", max(0, 22-len(value)))
		if _, err := fmt.Fprintf(writer, "%s%-16s %s%s %s\n", indent, item.label,
			formatAssessmentScoreDisplay(item.score, item.level, displayLevel, item.positive, color), padding,
			formatAssessmentBar(item.score, item.level, item.positive, color)); err != nil {
			return err
		}
	}
	return nil
}

func assuranceDisplayLevel(level string) string {
	switch level {
	case "high":
		return "strong"
	case "medium":
		return "moderate"
	case "low":
		return "limited"
	default:
		return "none"
	}
}

func formatAssessmentBar(score int, level string, positive, color bool) string {
	const width = 20
	score = max(0, min(100, score))
	filled := (score*width + 50) / 100
	filledBar := strings.Repeat("█", filled)
	emptyBar := strings.Repeat("░", width-filled)
	if !color {
		return "[" + filledBar + emptyBar + "]"
	}
	code := negativeScoreColor(level)
	if positive {
		code = positiveScoreColor(level)
	}
	return ansiWhite + "[" + code + filledBar + ansiWhite + emptyBar + "]" + ansiReset
}

func formatAssessmentScore(score int, level string, positive bool, color bool) string {
	return formatAssessmentScoreDisplay(score, level, level, positive, color)
}

func formatAssessmentScoreDisplay(score int, level, displayLevel string, positive bool, color bool) string {
	value := fmt.Sprintf("%d/100 (%s)", score, displayLevel)
	if !color {
		return value
	}
	code := negativeScoreColor(level)
	if positive {
		code = positiveScoreColor(level)
	}
	return code + value + ansiReset
}

// ColorReviewPriority applies the same risk-level colors as the CLI assessment output.
// The caller supplies the text so compact views can omit the parenthesized level.
func ColorReviewPriority(value, level string) string {
	return negativeScoreColor(level) + value + ansiReset
}

// ColorReviewPrioritySelected uses the CLI risk palette as a background for
// the selected Explorer row, with white foreground text.
func ColorReviewPrioritySelected(value, level string) string {
	background := "\x1b[42m" // info / default: green
	switch negativeScoreColor(level) {
	case ansiBrightRed:
		background = "\x1b[101m"
	case ansiRed:
		background = "\x1b[41m"
	case ansiYellow:
		background = "\x1b[43m"
	case ansiCyan:
		background = "\x1b[46m"
	}
	return background + ansiWhite + value + ansiReset
}

func negativeScoreColor(level string) string {
	switch level {
	case "critical":
		return ansiBrightRed
	case "high":
		return ansiRed
	case "medium":
		return ansiYellow
	case "low":
		return ansiCyan
	default:
		return ansiGreen
	}
}

func positiveScoreColor(level string) string {
	switch level {
	case "high", "sufficient":
		return ansiGreen
	case "medium":
		return ansiYellow
	case "low":
		return ansiRed
	default:
		return ansiBrightRed
	}
}

func writeKeyRisks(writer io.Writer, highlights []finding.RiskHighlight, indent string) error {
	if _, err := fmt.Fprintln(writer, indent+"Key Risks:"); err != nil {
		return err
	}
	if len(highlights) == 0 {
		_, err := fmt.Fprintln(writer, indent+"  -")
		return err
	}
	for _, highlight := range highlights {
		if _, err := fmt.Fprintf(writer, "%s  %s: %s [%s, score=%d, occurrences=%d]\n", indent, highlight.ID, highlight.Title, highlight.Severity, highlight.Score, highlight.Occurrences); err != nil {
			return err
		}
		for _, scope := range highlight.Scopes {
			if _, err := fmt.Fprintf(writer, "%s    sdk=%s", indent, scope.SDK); err != nil {
				return err
			}
			if scope.Location != nil {
				filePath := strings.TrimPrefix(scope.Location.Path, scope.SDK+"/")
				if _, err := fmt.Fprintf(writer, " file=%s:%d:%d", filePath, scope.Location.StartLine, scope.Location.StartColumn); err != nil {
					return err
				}
			}
			if scope.Hook != "" {
				if _, err := fmt.Fprintf(writer, " hook=%s", scope.Hook); err != nil {
					return err
				}
			}
			if scope.Value != "" {
				if _, err := fmt.Fprintf(writer, " value=%q", scope.Value); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeSummary(writer io.Writer, summary Summary, assessment finding.Assessment, compactFiles bool) error {
	if _, err := fmt.Fprintf(writer, "\nSummary\n  SDKs: %d (%d resolved, %d unresolved)\n    Resolved: %s\n    Unresolved: %s\n",
		summary.SDKs.Count, summary.SDKs.Resolved, summary.SDKs.Unresolved,
		formatSummaryItems(summary.SDKs.SDKNames.Resolved),
		formatSummaryItems(summary.SDKs.SDKNames.Unresolved)); err != nil {
		return err
	}
	filesLabel := fmt.Sprintf("  Files: %d", summary.Files.Count)
	if summary.Files.ContentSkipped > 0 {
		filesLabel += fmt.Sprintf(" (%d content skipped)", summary.Files.ContentSkipped)
	}
	if _, err := fmt.Fprintln(writer, filesLabel); err != nil {
		return err
	}
	for _, item := range summary.Files.BySDK {
		filePaths := item.FilePaths
		omitted := 0
		if compactFiles {
			filePaths, omitted = compactSummaryFiles(item.FilePaths, item.Count)
		}
		formatted := formatSummaryItems(filePaths)
		if omitted > 0 {
			formatted += fmt.Sprintf(", ... and more files (%d)", omitted)
		}
		itemLabel := fmt.Sprintf("%s (%d", item.SDKName, item.Count)
		if item.ContentSkipped > 0 {
			itemLabel += fmt.Sprintf(", %d content skipped", item.ContentSkipped)
		}
		itemLabel += ")"
		if _, err := fmt.Fprintf(writer, "    %s: %s\n", itemLabel, formatted); err != nil {
			return err
		}
		if item.ContentSkipped > 0 {
			skipped := item.SkippedFiles
			omittedSkipped := 0
			if compactFiles && len(skipped) > 5 {
				skipped, omittedSkipped = skipped[:5], len(skipped)-5
			}
			formattedSkipped := formatSkippedFiles(skipped)
			if omittedSkipped > 0 {
				formattedSkipped += fmt.Sprintf(", ... and more skipped files (%d)", omittedSkipped)
			}
			if _, err := fmt.Fprintf(writer, "      Content skipped: %s\n", formattedSkipped); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(writer, "  Hooks: %d\n", summary.Hooks.Count); err != nil {
		return err
	}
	for _, item := range summary.Hooks.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s (%d): %s\n", item.SDKName, item.Count, formatSummaryItems(item.HookNames)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "  Operations: %d\n", summary.Operations.Count); err != nil {
		return err
	}
	for _, item := range summary.Operations.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s (%d): %s\n", item.SDKName, item.Count, formatCountedItems(item.OperationKinds)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "  Capabilities: %d\n", summary.Capabilities.Count); err != nil {
		return err
	}
	for _, item := range summary.Capabilities.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s (%d): %s\n", item.SDKName, item.Count, formatCountedItems(item.CapabilityNames)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "  Unknown Commands: %d\n", summary.UnknownCommands.Count); err != nil {
		return err
	}
	for _, item := range summary.UnknownCommands.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s (%d)\n", item.SDKName, item.Count); err != nil {
			return err
		}
		for _, file := range item.Files {
			if _, err := fmt.Fprintf(writer, "      %s (%d): %s\n", file.FilePath, file.Count, formatCountedItems(file.CommandNames)); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(writer, "  Findings: %d (%d risk, %d assurance)\n", summary.Findings.Count, summary.Findings.Risk, summary.Findings.Assurance); err != nil {
		return err
	}
	assessments := make(map[string]finding.SDKAssessment, len(assessment.BySDK))
	for _, item := range assessment.BySDK {
		assessments[item.SDK] = item
	}
	if _, err := fmt.Fprintln(writer, "    High-priority risks:"); err != nil {
		return err
	}
	highPriorityCount := 0
	for _, item := range summary.Findings.BySDK {
		sdkAssessment, ok := assessments[item.SDKName]
		if !ok || (sdkAssessment.Risk.Level != "high" && sdkAssessment.Risk.Level != "critical") {
			continue
		}
		riskIDs := make([]CountedName, 0, len(item.FindingIDs))
		for _, findingID := range item.FindingIDs {
			if strings.HasPrefix(findingID.Name, "risk.") {
				riskIDs = append(riskIDs, findingID)
			}
		}
		highPriorityCount++
		if _, err := fmt.Fprintf(writer, "      %s (%s): %s\n", item.SDKName, sdkAssessment.Risk.Level, formatCountedItems(riskIDs)); err != nil {
			return err
		}
	}
	if highPriorityCount == 0 {
		if _, err := fmt.Fprintln(writer, "      -"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "  Diagnostics: %d: %s\n", summary.Diagnostics.Count, formatCountedItems(summary.Diagnostics.DiagnosticCodes))
	return err
}

func compactSummaryFiles(filePaths []string, total int) ([]string, int) {
	selected := make([]string, 0, len(filePaths))
	for _, filePath := range filePaths {
		if filePath == "sdk.yaml" || filePath == "meta/sdk.yaml" || isHookPath(filePath) {
			selected = append(selected, filePath)
		}
	}
	omitted := total - len(selected)
	if omitted < 0 {
		omitted = 0
	}
	return selected, omitted
}

func isHookPath(filePath string) bool {
	prefix := "hooks/"
	if strings.HasPrefix(filePath, "sdk/hooks/") {
		prefix = "sdk/hooks/"
	} else if !strings.HasPrefix(filePath, prefix) {
		return false
	}
	name := strings.TrimPrefix(filePath, prefix)
	for _, hookName := range sdk.HookNames {
		if name == string(hookName) {
			return true
		}
	}
	return false
}

func formatCountedItems(items []CountedName) string {
	if len(items) == 0 {
		return "-"
	}
	formatted := make([]string, 0, len(items))
	for _, item := range items {
		formatted = append(formatted, fmt.Sprintf("%s (%d)", item.Name, item.Count))
	}
	return strings.Join(formatted, ", ")
}

func formatSummaryItems(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ", ")
}

func formatSkippedFiles(files []SkippedFileSummary) string {
	formatted := make([]string, 0, len(files))
	for _, file := range files {
		formatted = append(formatted, fmt.Sprintf("%s (%s, %d bytes)", file.FilePath, file.Reason, file.Size))
	}
	return strings.Join(formatted, ", ")
}

func writeSDK(writer io.Writer, item SDK) error {
	if _, err := fmt.Fprintf(writer, "  %s\n    Source: %s\n    State: %s\n", item.Name, item.Source, item.State); err != nil {
		return err
	}
	if item.Channel != "" {
		if _, err := fmt.Fprintf(writer, "    Channel: %s\n", item.Channel); err != nil {
			return err
		}
	}
	for _, diagnostic := range item.Diagnostics {
		if _, err := fmt.Fprintf(writer, "    Diagnostic: [%s] %s (%s): %s\n",
			diagnostic.Severity, diagnostic.Code, diagnostic.Phase, diagnostic.Message); err != nil {
			return err
		}
	}
	if err := writeFindings(writer, item.Findings); err != nil {
		return err
	}
	if item.State != sdk.StateResolved {
		return nil
	}
	if _, err := fmt.Fprintf(writer, "    Digest: %s\n    Metadata: %s\n", item.Digest, item.MetadataPath); err != nil {
		return err
	}
	if err := writeMetadata(writer, item); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "    Files: %d\n", len(item.Files)); err != nil {
		return err
	}
	for _, file := range item.Files {
		if _, err := fmt.Fprintf(writer, "      %s: %s", file.Path, file.Type); err != nil {
			return err
		}
		if file.Size > 0 {
			if _, err := fmt.Fprintf(writer, " (%d bytes)", file.Size); err != nil {
				return err
			}
		}
		if file.Digest != "" {
			if _, err := fmt.Fprintf(writer, " %s", file.Digest); err != nil {
				return err
			}
		}
		if file.ContentStatus == "skipped" {
			if _, err := fmt.Fprintf(writer, " content=skipped reason=%s", file.SkipReason); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
		if file.Content != nil {
			if err := writeFileContent(writer, file); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(writer, "    Hooks:"); err != nil {
		return err
	}
	if len(item.Hooks) == 0 {
		_, err := fmt.Fprintln(writer, "      -")
		return err
	}
	for _, hook := range item.Hooks {
		if err := writeHook(writer, hook); err != nil {
			return err
		}
	}
	return nil
}

func writeFindings(writer io.Writer, findings []finding.Finding) error {
	if _, err := fmt.Fprintf(writer, "    Findings: %d\n", len(findings)); err != nil {
		return err
	}
	for _, itemFinding := range findings {
		level := itemFinding.Severity
		if itemFinding.Kind == "assurance" {
			level = itemFinding.Strength
		} else if itemFinding.Kind == "observation" {
			level = "unscored"
		}
		if _, err := fmt.Fprintf(writer, "      %s [%s/%s, confidence=%s] %s", itemFinding.ID, itemFinding.Kind, level, itemFinding.Confidence, itemFinding.Title); err != nil {
			return err
		}
		if itemFinding.Scope.Hook != "" {
			if _, err := fmt.Fprintf(writer, " (hook=%s)", itemFinding.Scope.Hook); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
		for _, evidence := range itemFinding.Evidence {
			if _, err := fmt.Fprintf(writer, "        Evidence: %s %s", evidence.Type, evidence.ID); err != nil {
				return err
			}
			if evidence.OperationID != "" {
				if _, err := fmt.Fprintf(writer, " operation=%s", evidence.OperationID); err != nil {
					return err
				}
			}
			if evidence.FromOperationID != "" || evidence.ToOperationID != "" {
				if _, err := fmt.Fprintf(writer, " flow=%s->%s", evidence.FromOperationID, evidence.ToOperationID); err != nil {
					return err
				}
			}
			if evidence.Location != nil {
				if _, err := fmt.Fprintf(writer, " at %s", locationString(*evidence.Location)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeDocumentDiagnostics(writer io.Writer, diagnostics []DocumentDiagnostic) error {
	if len(diagnostics) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, "\nDiagnostics"); err != nil {
		return err
	}
	for _, diagnostic := range diagnostics {
		context := diagnostic.SDK
		if diagnostic.Hook != "" {
			context += "/" + string(diagnostic.Hook)
		}
		phase := ""
		if diagnostic.Phase != "" {
			phase = " (" + diagnostic.Phase + ")"
		}
		if _, err := fmt.Fprintf(writer, "  %s: [%s] %s%s: %s\n",
			context, diagnostic.Severity, diagnostic.Code, phase, diagnostic.Message); err != nil {
			return err
		}
	}
	return nil
}

func writeFileContent(writer io.Writer, file File) error {
	if _, err := fmt.Fprintf(writer, "        Content (%s):\n", file.ContentEncoding); err != nil {
		return err
	}
	content := *file.Content
	if file.ContentEncoding == "utf-8" {
		content = safeText(content)
	}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if _, err := fmt.Fprintf(writer, "          | %s\n", line); err != nil {
			return err
		}
	}
	return nil
}

func safeText(content string) string {
	var safe strings.Builder
	for _, character := range content {
		switch {
		case character == '\n' || character == '\t':
			safe.WriteRune(character)
		case unicode.IsGraphic(character) || character == ' ':
			safe.WriteRune(character)
		default:
			fmt.Fprintf(&safe, "\\u%04x", character)
		}
	}
	return safe.String()
}

func writeMetadata(writer io.Writer, item SDK) error {
	if item.Metadata == nil {
		return nil
	}
	metadata := item.Metadata
	if _, err := fmt.Fprintf(writer, "      Name: %s\n", metadata.Name); err != nil {
		return err
	}
	for _, field := range []struct{ name, value string }{
		{"Version", metadata.Version}, {"Base", metadata.Base}, {"Architecture", metadata.Architecture},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(writer, "      %s: %s\n", field.name, field.value); err != nil {
				return err
			}
		}
	}
	if err := writeInterfaces(writer, "Plugs", metadata.Plugs); err != nil {
		return err
	}
	return writeInterfaces(writer, "Slots", metadata.Slots)
}

func writeInterfaces(writer io.Writer, label string, interfaces map[string]any) error {
	if _, err := fmt.Fprintf(writer, "      %s: %d\n", label, len(interfaces)); err != nil {
		return err
	}
	names := make([]string, 0, len(interfaces))
	for name := range interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		encoded, err := json.Marshal(interfaces[name])
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "        %s: %s\n", name, encoded); err != nil {
			return err
		}
	}
	return nil
}

func writeHook(writer io.Writer, hook Hook) error {
	if _, err := fmt.Fprintf(writer, "      %s: %s (%d bytes)", hook.Name, hook.Path, hook.Size); err != nil {
		return err
	}
	if hook.Parse != nil {
		if _, err := fmt.Fprintf(writer, " [%s, %d AST nodes]", hook.Parse.Status, countNodes(hook.Parse.NodeTypes)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer); err != nil {
		return err
	}
	if hook.Context != nil {
		if _, err := fmt.Fprintf(writer, "        Context: root=%t project=%t interfaces=%t state=%t",
			hook.Context.RunAsRoot, hook.Context.ProjectMounted, hook.Context.InterfacesActive, hook.Context.StateMounted); err != nil {
			return err
		}
		if hook.Context.ContextDependent {
			if _, err := fmt.Fprint(writer, " context-dependent=true"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "        Operations: %d\n", countOperations(hook.Operations)); err != nil {
		return err
	}
	for _, operation := range hook.Operations {
		if err := writeOperation(writer, operation, "          "); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "        Relations: %d\n", len(hook.Relations)); err != nil {
		return err
	}
	for _, relation := range hook.Relations {
		if _, err := fmt.Fprintf(writer, "          %s [%s] %s -> %s", relation.Kind, relation.Resolution,
			relation.FromOperationID, relation.ToOperationID); err != nil {
			return err
		}
		if relation.Name != "" {
			if _, err := fmt.Fprintf(writer, " name=%q", relation.Name); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "        Capabilities: %d\n", len(hook.Capabilities)); err != nil {
		return err
	}
	for _, capability := range hook.Capabilities {
		if _, err := fmt.Fprintf(writer, "          %s [%s] operation=%s rule=%s source=%s at %s target=%s\n",
			capability.Kind, capability.Resolution, capability.OperationID, capability.RuleID, capability.RuleSource,
			locationString(capability.Location), formatValue(capability.Target)); err != nil {
			return err
		}
	}
	if hook.Parse != nil && len(hook.Parse.Diagnostics) > 0 {
		if _, err := fmt.Fprintf(writer, "        Diagnostics: %d\n", len(hook.Parse.Diagnostics)); err != nil {
			return err
		}
		for _, diagnostic := range hook.Parse.Diagnostics {
			if _, err := fmt.Fprintf(writer, "          %s %s at %s: %s\n",
				diagnostic.Severity, diagnostic.Code, locationString(diagnostic.Location), diagnostic.Message); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeOperation(writer io.Writer, operation analysis.Operation, indent string) error {
	if _, err := fmt.Fprintf(writer, "%s%s %s [%s] at %s", indent, operation.ID, operation.Kind, operation.Resolution, locationString(operation.Location)); err != nil {
		return err
	}
	if operation.Name != "" {
		if _, err := fmt.Fprintf(writer, " name=%q", operation.Name); err != nil {
			return err
		}
	}
	if operation.Command.Resolution != "" {
		if _, err := fmt.Fprintf(writer, " command=%s", formatValue(operation.Command)); err != nil {
			return err
		}
	}
	if len(operation.Wrappers) > 0 {
		if _, err := fmt.Fprintf(writer, " wrappers=%q", operation.Wrappers); err != nil {
			return err
		}
	}
	if len(operation.Arguments) > 0 {
		arguments := make([]string, 0, len(operation.Arguments))
		for _, argument := range operation.Arguments {
			arguments = append(arguments, formatValue(argument))
		}
		if _, err := fmt.Fprintf(writer, " args=[%s]", strings.Join(arguments, ", ")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer); err != nil {
		return err
	}
	for _, input := range operation.Inputs {
		if _, err := fmt.Fprintf(writer, "%s  input %s=%s\n", indent, input.Kind, formatValue(input.Value)); err != nil {
			return err
		}
	}
	for _, output := range operation.Outputs {
		if _, err := fmt.Fprintf(writer, "%s  output %s=%s\n", indent, output.Kind, formatValue(output.Value)); err != nil {
			return err
		}
	}
	for _, child := range operation.Children {
		if err := writeOperation(writer, child, indent+"  "); err != nil {
			return err
		}
	}
	return nil
}

func formatValue(value analysis.Value) string {
	if value.Resolution == analysis.Resolved {
		return fmt.Sprintf("%q", value.Literal)
	}
	if len(value.Candidates) > 0 {
		return fmt.Sprintf("%s%q", value.Resolution, value.Candidates)
	}
	parts := make([]string, 0, len(value.Parts))
	for _, part := range value.Parts {
		switch part.Kind {
		case analysis.PartVariableReference:
			parts = append(parts, "${"+part.Name+"}")
		default:
			if part.Text != "" {
				parts = append(parts, part.Text)
			} else {
				parts = append(parts, "<"+string(part.Kind)+">")
			}
		}
	}
	if len(parts) == 0 {
		return string(value.Resolution)
	}
	return fmt.Sprintf("%s(%q)", value.Resolution, strings.Join(parts, ""))
}

func locationString(location shell.Location) string {
	return fmt.Sprintf("%s:%d:%d", location.Path, location.StartLine, location.StartColumn)
}

func countNodes(nodeTypes map[string]int) int {
	var count int
	for _, value := range nodeTypes {
		count += value
	}
	return count
}
