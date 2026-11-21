package report

import (
	"encoding/json"
	"io"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/source"
)

// WriteJSON writes one complete, indented JSON document.
func WriteJSON(writer io.Writer, result *source.Result) error {
	return encodeJSON(writer, NewDocumentWithOptions(result, DocumentOptions{IncludeTopology: true}))
}

func encodeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// WriteJSONSummary writes metadata and the project-wide summary without SDK details.
func WriteJSONSummary(writer io.Writer, result *source.Result) error {
	return jsonSummaryDocument(writer, NewDocumentWithOptions(result, DocumentOptions{}))
}

func jsonSummaryDocument(writer io.Writer, document Document) error {
	compact := struct {
		Suppressions  []finding.SuppressionResult `json:"suppressions,omitempty"`
		SchemaVersion string                      `json:"schemaVersion"`
		Scanner       Scanner                     `json:"scanner"`
		FindingDB     finding.Database            `json:"findingDatabase"`
		Input         Input                       `json:"input"`
		Workshops     []source.Workshop           `json:"workshops"`
		Summary       Summary                     `json:"summary"`
		Assessment    finding.Assessment          `json:"assessment"`
		Diagnostics   []DocumentDiagnostic        `json:"diagnostics"`
	}{
		Suppressions:  document.Suppressions,
		SchemaVersion: document.SchemaVersion,
		Scanner:       document.Scanner,
		FindingDB:     document.FindingDB,
		Input:         document.Input,
		Workshops:     document.Workshops,
		Summary:       document.Summary,
		Assessment:    document.Assessment,
		Diagnostics:   document.Diagnostics,
	}
	return encodeJSON(writer, compact)
}
