package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestScanProgressCompletesOnOneLine(t *testing.T) {
	var output bytes.Buffer
	progress := startScanProgress(&output, true)
	progress.stop(true)

	text := output.String()
	if !strings.HasPrefix(text, scanProgressLabel+" |") {
		t.Errorf("progress output = %q", text)
	}
	if !strings.HasSuffix(text, "\r"+scanProgressLabel+" completed!\n") {
		t.Errorf("completed progress output = %q", text)
	}
}

func TestScanProgressReportsFailure(t *testing.T) {
	var output bytes.Buffer
	progress := startScanProgress(&output, true)
	progress.stop(false)

	if !strings.HasSuffix(output.String(), "\r"+scanProgressLabel+" failed!\n") {
		t.Errorf("failed progress output = %q", output.String())
	}
}

func TestDisabledScanProgressWritesNothing(t *testing.T) {
	var output bytes.Buffer
	progress := startScanProgress(&output, false)
	progress.stop(true)

	if output.Len() != 0 {
		t.Errorf("disabled progress output = %q", output.String())
	}
}
