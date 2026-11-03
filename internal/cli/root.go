// Package cli implements Latra's command-line interface.
package cli

import (
	"fmt"
	"io"

	"github.com/shizuku198411/Latra/internal/buildinfo"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// Run executes the command using the supplied streams and returns a process exit code.
// User-facing command output is written to stdout. Diagnostics are written to stderr.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stdout)
		return exitOK
	}

	switch args[0] {
	case "help", "-h", "--help":
		if len(args) != 1 {
			return usageError(stderr, "%q does not accept arguments", args[0])
		}
		writeUsage(stdout)
		return exitOK
	case "version", "-v", "--version":
		if len(args) != 1 {
			return usageError(stderr, "%q does not accept arguments", args[0])
		}
		fmt.Fprintln(stdout, buildinfo.Current().String())
		return exitOK
	case "scan":
		fmt.Fprintln(stderr, "latra: scan is not implemented yet")
		return exitError
	default:
		return usageError(stderr, "unknown command %q", args[0])
	}
}

func usageError(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "latra: "+format+"\n", args...)
	fmt.Fprintln(stderr, "Run 'latra help' for usage.")
	return exitUsage
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, `Latra statically analyzes Canonical Workshop SDKs without executing hooks.

Usage:
  latra <command>

Commands:
  scan       Analyze a Workshop project or project SDK (not implemented yet)
  version    Print build version information
  help       Show this help`)
}
