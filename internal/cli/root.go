// Package cli implements Latra's command-line interface.
package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/shizuku198411/Latra/internal/buildinfo"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
	"github.com/shizuku198411/Latra/internal/source"
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
		return runScan(args[1:], stdout, stderr)
	default:
		return usageError(stderr, "unknown command %q", args[0])
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	options, err := parseScanOptions(args)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	result, err := source.Scan(options.path, sdk.DefaultLimits())
	if err != nil {
		fmt.Fprintf(stderr, "latra: scan failed: %v\n", err)
		return exitError
	}
	parseErr := source.ParseHooks(result, shell.NewParser())
	if parseErr != nil && options.output != "-" {
		fmt.Fprintf(stderr, "latra: scan incomplete: %v\n", parseErr)
		return exitError
	}
	if err := writeReport(options, stdout, result); err != nil {
		fmt.Fprintf(stderr, "latra: write report: %v\n", err)
		return exitError
	}
	if parseErr != nil {
		fmt.Fprintf(stderr, "latra: scan incomplete: %v\n", parseErr)
		return exitError
	}
	return exitOK
}

type scanOptions struct {
	path    string
	format  report.Format
	output  string
	noColor bool
	quiet   bool
}

func parseScanOptions(args []string) (scanOptions, error) {
	options := scanOptions{format: report.FormatText, output: "-"}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--format":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("--format requires a value")
			}
			options.format = report.Format(args[index])
		case strings.HasPrefix(argument, "--format="):
			options.format = report.Format(strings.TrimPrefix(argument, "--format="))
		case argument == "--output" || argument == "-o":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("%s requires a value", argument)
			}
			options.output = args[index]
		case strings.HasPrefix(argument, "--output="):
			options.output = strings.TrimPrefix(argument, "--output=")
		case argument == "--no-color":
			options.noColor = true
		case argument == "--quiet":
			options.quiet = true
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown scan option %q", argument)
		case options.path == "":
			options.path = argument
		default:
			return options, fmt.Errorf("scan requires exactly one PROJECT_OR_PROJECT_SDK path")
		}
	}
	if options.path == "" {
		return options, fmt.Errorf("scan requires exactly one PROJECT_OR_PROJECT_SDK path")
	}
	if options.format != report.FormatText && options.format != report.FormatJSON {
		return options, fmt.Errorf("invalid format %q; use text or json", options.format)
	}
	if options.output == "" {
		return options, fmt.Errorf("output path must not be empty")
	}
	return options, nil
}

func writeReport(options scanOptions, stdout io.Writer, result *source.Result) error {
	if options.output == "-" {
		return report.Write(stdout, options.format, result)
	}
	return report.WriteFile(options.output, options.format, result)
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

Scan:
  latra scan <PROJECT_OR_PROJECT_SDK> [--format text|json] [--output PATH|-]

Options:
  --format text|json  Report format (default: text)
  --output, -o PATH   Write report to PATH or stdout with - (default: -)
  --no-color          Disable terminal colors
  --quiet             Suppress non-error status output

Commands:
  scan       Inspect a Workshop project or project SDK
  version    Print build version information
  help       Show this help`)
}
