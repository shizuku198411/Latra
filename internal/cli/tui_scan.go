package cli

import (
	"context"

	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/source"
)

// scanExplorer uses exactly the same resolution and analysis pipeline as latra scan.
// The full report retains findings, evidence locations, and per-SDK assessments
// for subsequent Explorer views.
func scanExplorer(project string, resolver source.StoreResolver) (*report.Document, error) {
	result, err := scanAndParse(context.Background(), project, resolver)
	if result == nil {
		return nil, err
	}
	document := report.NewDocumentWithOptions(result, report.DocumentOptions{})
	return &document, err
}

func (m *tuiExplorer) finishScan(document *report.Document, err error) {
	m.Scanning = false
	if document != nil {
		m.Scan = document
		if err != nil {
			m.ScanStatus = "Scan incomplete: " + err.Error()
		} else {
			m.ScanStatus = "Scan complete"
		}
	} else if err != nil {
		// Preserve the last successful scan when a new attempt fails.
		m.ScanStatus = "Scan failed: " + err.Error()
	}
}
