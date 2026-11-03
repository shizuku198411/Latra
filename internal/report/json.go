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
