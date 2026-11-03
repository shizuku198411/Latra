package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/cli"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "help by default",
			wantCode:   0,
			wantStdout: "Usage:\n  latra <command>",
		},
		{
			name:       "explicit help",
			args:       []string{"help"},
			wantCode:   0,
			wantStdout: "Latra statically analyzes",
		},
		{
			name:       "version",
			args:       []string{"version"},
			wantCode:   0,
			wantStdout: "latra dev (commit: unknown, built: unknown)\n",
		},
		{
			name:       "scan placeholder",
			args:       []string{"scan"},
			wantCode:   1,
			wantStderr: "latra: scan is not implemented yet\n",
		},
		{
			name:       "unknown command",
			args:       []string{"unknown"},
			wantCode:   2,
			wantStderr: "latra: unknown command \"unknown\"",
		},
		{
			name:       "version rejects arguments",
			args:       []string{"version", "extra"},
			wantCode:   2,
			wantStderr: "latra: \"version\" does not accept arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := cli.Run(tt.args, &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("Run() code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
