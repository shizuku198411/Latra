package report

import (
	"encoding/json"
	"io"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/source"
)

// WriteJSON writes one complete, indented JSON document.
func WriteJSON(writer io.Writer, result *source.Result) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(NewDocument(result))
}

// WriteJSONSummary writes metadata and the project-wide summary without SDK details.
func WriteJSONSummary(writer io.Writer, result *source.Result) error {
	document := NewDocument(result)
	compact := struct {
		SchemaVersion string               `json:"schemaVersion"`
		Scanner       Scanner              `json:"scanner"`
		FindingDB     finding.Database     `json:"findingDatabase"`
		Input         Input                `json:"input"`
		Workshops     []source.Workshop    `json:"workshops"`
		Summary       Summary              `json:"summary"`
		Assessment    finding.Assessment   `json:"assessment"`
		Diagnostics   []DocumentDiagnostic `json:"diagnostics"`
	}{
		SchemaVersion: document.SchemaVersion,
		Scanner:       document.Scanner,
		FindingDB:     document.FindingDB,
		Input:         document.Input,
		Workshops:     document.Workshops,
		Summary:       document.Summary,
		Assessment:    document.Assessment,
		Diagnostics:   document.Diagnostics,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(compact)
}
