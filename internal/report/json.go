package report

import (
	"encoding/json"
	"io"

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
		SchemaVersion string            `json:"schemaVersion"`
		Scanner       Scanner           `json:"scanner"`
		Input         Input             `json:"input"`
		Workshops     []source.Workshop `json:"workshops"`
		Summary       Summary           `json:"summary"`
	}{
		SchemaVersion: document.SchemaVersion,
		Scanner:       document.Scanner,
		Input:         document.Input,
		Workshops:     document.Workshops,
		Summary:       document.Summary,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(compact)
}
