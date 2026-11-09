// Package cli implements Latra's command-line interface.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/shizuku198411/Latra/internal/buildinfo"
	"github.com/shizuku198411/Latra/internal/knowledge"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/sdkcache"
	"github.com/shizuku198411/Latra/internal/sdkstore"
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
	dependencies := Dependencies{CacheRoot: sdkcache.DefaultRoot}
	if len(args) > 0 && (args[0] == "scan" || args[0] == "explorer") {
		store, err := sdkstore.NewClient(sdkstore.Config{})
		if err != nil {
			fmt.Fprintf(stderr, "latra: initialize SDK Store client: %v\n", err)
			return exitError
		}
		dependencies.StoreResolver = store
	}
	return RunWithDependencies(args, stdout, stderr, dependencies)
}

// Dependencies contains replaceable external services used by the CLI.
type Dependencies struct {
	StoreResolver    source.StoreResolver
	CacheRoot        string
	WorkingDirectory string
}

// RunWithDependencies executes the CLI with explicitly supplied external services.
func RunWithDependencies(args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
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
	case "explorer":
		return runTUI(args[1:], stdout, stderr, dependencies)
	case "scan":
		return runScan(args[1:], stdout, stderr, dependencies)
	case "db":
		return runDB(args[1:], stdout, stderr)
	case "file":
		return runFile(args[1:], stdout, stderr, dependencies)
	case "hook":
		return runHook(args[1:], stdout, stderr, dependencies)
	case "cache":
		return runCache(args[1:], stdout, stderr, dependencies)
	default:
		return usageError(stderr, "unknown command %q", args[0])
	}
}

type dbOptions struct {
	query  knowledge.Query
	format knowledge.Format
	output string
}

func runDB(args []string, stdout, stderr io.Writer) int {
	options, err := parseDBOptions(args)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	catalog := knowledge.Default()
	if options.output == "-" {
		if err := knowledge.Write(stdout, options.format, catalog, options.query); err != nil {
			fmt.Fprintf(stderr, "latra: query database: %v\n", err)
			return exitError
		}
		return exitOK
	}
	if err := knowledge.WriteFile(options.output, options.format, catalog, options.query); err != nil {
		fmt.Fprintf(stderr, "latra: write database output: %v\n", err)
		return exitError
	}
	return exitOK
}

func parseDBOptions(args []string) (dbOptions, error) {
	options := dbOptions{format: knowledge.FormatText, output: "-"}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--format":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("--format requires a value")
			}
			options.format = knowledge.Format(args[index])
		case strings.HasPrefix(argument, "--format="):
			options.format = knowledge.Format(strings.TrimPrefix(argument, "--format="))
		case argument == "--output" || argument == "-o":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("%s requires a value", argument)
			}
			options.output = args[index]
		case strings.HasPrefix(argument, "--output="):
			options.output = strings.TrimPrefix(argument, "--output=")
		case argument == "--capability":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("--capability requires a value")
			}
			options.query.Capability = args[index]
		case strings.HasPrefix(argument, "--capability="):
			options.query.Capability = strings.TrimPrefix(argument, "--capability=")
		case argument == "--command":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("--command requires a value")
			}
			options.query.Command = args[index]
		case strings.HasPrefix(argument, "--command="):
			options.query.Command = strings.TrimPrefix(argument, "--command=")
		case argument == "--verbose":
			options.query.Verbose = true
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown db option %q", argument)
		case options.query.Entity == "":
			options.query.Entity = argument
		case options.query.Name == "":
			options.query.Name = argument
		default:
			return options, fmt.Errorf("db accepts at most an entity and a name")
		}
	}
	if options.query.Entity != "" && options.query.Entity != "capabilities" && options.query.Entity != "commands" {
		return options, fmt.Errorf("invalid db entity %q; use capabilities or commands", options.query.Entity)
	}
	if options.query.Entity == "" && (options.query.Name != "" || options.query.Capability != "" || options.query.Command != "") {
		return options, fmt.Errorf("db filters require capabilities or commands")
	}
	if options.query.Entity == "capabilities" && options.query.Capability != "" {
		return options, fmt.Errorf("--capability is only valid with db commands")
	}
	if options.query.Entity == "commands" && options.query.Command != "" {
		return options, fmt.Errorf("--command is only valid with db capabilities")
	}
	if options.format != knowledge.FormatText && options.format != knowledge.FormatJSON {
		return options, fmt.Errorf("invalid format %q; use text or json", options.format)
	}
	if options.output == "" {
		return options, fmt.Errorf("output path must not be empty")
	}
	return options, nil
}

func runScan(args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	options, err := parseScanOptions(args)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	if options.path == "" {
		options.path = dependencies.WorkingDirectory
		if options.path == "" {
			options.path = "."
		}
	}
	progress := startScanProgress(stderr, !options.quiet && isTerminalWriter(stderr))
	result, parseErr := scanAndParse(context.Background(), options.path, dependencies.StoreResolver)
	if result == nil {
		progress.stop(false)
		fmt.Fprintf(stderr, "latra: scan failed: %v\n", parseErr)
		return exitError
	}
	if parseErr != nil && options.output != "-" {
		progress.stop(false)
		fmt.Fprintf(stderr, "latra: scan incomplete: %v\n", parseErr)
		return exitError
	}
	progress.stop(true)
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

// scanAndParse is shared by the scan command and the interactive Explorer.
// A hook parse error retains the partially analyzed result for reporting.
func scanAndParse(ctx context.Context, path string, resolver source.StoreResolver) (*source.Result, error) {
	result, err := source.ScanWithResolver(ctx, path, sdk.DefaultLimits(), resolver)
	if err != nil {
		return nil, err
	}
	return result, source.ParseHooks(result, shell.NewParser())
}

type scanOptions struct {
	path    string
	format  report.Format
	output  string
	noColor bool
	quiet   bool
	verbose bool
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
		case argument == "--project":
			index++
			if index >= len(args) || args[index] == "" {
				return options, fmt.Errorf("--project requires a path")
			}
			if options.path != "" {
				return options, fmt.Errorf("scan accepts only one project path")
			}
			options.path = args[index]
		case strings.HasPrefix(argument, "--project="):
			path := strings.TrimPrefix(argument, "--project=")
			if path == "" {
				return options, fmt.Errorf("--project requires a path")
			}
			if options.path != "" {
				return options, fmt.Errorf("scan accepts only one project path")
			}
			options.path = path
		case argument == "--no-color":
			options.noColor = true
		case argument == "--quiet":
			options.quiet = true
		case argument == "--verbose":
			options.verbose = true
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown scan option %q", argument)
		case options.path == "":
			options.path = argument
		default:
			return options, fmt.Errorf("scan accepts only one project path")
		}
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
		if options.format == report.FormatText {
			textOptions := report.TextOptions{Color: !options.noColor && os.Getenv("NO_COLOR") == "" && isTerminalWriter(stdout)}
			if !options.verbose {
				return report.WriteTextSummaryWithOptions(stdout, result, textOptions)
			}
			return report.WriteTextWithOptions(stdout, result, textOptions)
		}
		if !options.verbose {
			return report.WriteSummary(stdout, options.format, result)
		}
		return report.Write(stdout, options.format, result)
	}
	if !options.verbose {
		return report.WriteSummaryFile(options.output, options.format, result)
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
  latra scan [PROJECT_OR_PROJECT_SDK] [--project PATH] [--format text|json] [--output PATH|-]

Explorer:
  latra explorer [--project PATH]

Database:
  latra db
  latra db capabilities [CAPABILITY] [--command COMMAND]
  latra db commands [COMMAND] [--capability CAPABILITY]

SDK content:
  latra file <SDK> <FILE> [--project PATH|--channel CHANNEL] [--revision REVISION]
  latra hook <SDK> <HOOK> [--project PATH|--channel CHANNEL] [--revision REVISION]

Cache:
  latra cache list
  latra cache clean [--project PATH]
  latra cache clean --all

Options:
  --format text|json  Report format (default: text)
  --output, -o PATH   Write report to PATH or stdout with - (default: -)
  --no-color          Disable terminal colors
  --quiet             Suppress non-error status output
  --verbose           Include complete SDK, file, hook, and analysis details

Content selection:
  --project PATH      Use PATH as the Workshop project or SDK (default: .)
  --channel CHANNEL   Override the Workshop-declared Store channel
  --revision REVISION Select a cached revision within the resolved channel

Commands:
  explorer   Browse Workshop SDKs in an interactive terminal
  scan       Inspect a Workshop project or project SDK
  db         Inspect embedded capabilities, commands, and rules
  file       Print an SDK file or describe its binary format
  hook       Print a cached SDK Workshop hook
  cache      Remove cached SDK Store artifacts
  version    Print build version information
  help       Show this help`)
}
