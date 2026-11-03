package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shizuku198411/Latra/internal/source"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Write serializes a scan result in the selected format.
func Write(writer io.Writer, format Format, result *source.Result) error {
	switch format {
	case FormatText:
		return WriteText(writer, result)
	case FormatJSON:
		return WriteJSON(writer, result)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

// WriteSummary serializes the compact stdout representation.
func WriteSummary(writer io.Writer, format Format, result *source.Result) error {
	switch format {
	case FormatText:
		return WriteTextSummary(writer, result)
	case FormatJSON:
		return WriteJSONSummary(writer, result)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

// WriteFile atomically replaces path only after complete serialization.
func WriteFile(path string, format Format, result *source.Result) (returnErr error) {
	return writeFile(path, func(writer io.Writer) error {
		return Write(writer, format, result)
	})
}

// WriteSummaryFile atomically writes the compact report representation.
func WriteSummaryFile(path string, format Format, result *source.Result) (returnErr error) {
	return writeFile(path, func(writer io.Writer) error {
		return WriteSummary(writer, format, result)
	})
}

func writeFile(path string, serialize func(io.Writer) error) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".latra-report-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := serialize(temporary); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporary = nil
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return nil
}
