package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/shizuku198411/Latra/internal/sdkcache"
	"github.com/shizuku198411/Latra/internal/source"
)

type cacheCleanOptions struct {
	project string
	all     bool
}

func runCache(args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	if len(args) > 0 && args[0] == "list" {
		if len(args) != 1 {
			return usageError(stderr, "cache list does not accept arguments")
		}
		return runCacheList(stdout, stderr, dependencies)
	}
	options, err := parseCacheCleanOptions(args)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	cacheRoot := dependencies.CacheRoot
	if cacheRoot == "" {
		cacheRoot = sdkcache.DefaultRoot
	}
	if options.all {
		count, err := sdkcache.RemoveAll(cacheRoot)
		if err != nil {
			fmt.Fprintf(stderr, "latra: clean cache: %v\n", err)
			return exitError
		}
		fmt.Fprintf(stdout, "Removed all Latra cache entries (%d).\n", count)
		return exitOK
	}

	project := options.project
	if project == "" {
		project = dependencies.WorkingDirectory
		if project == "" {
			project = "."
		}
	}
	names, err := source.StoreSDKNames(project)
	if err != nil {
		fmt.Fprintf(stderr, "latra: clean cache: inspect Workshop project: %v\n", err)
		return exitError
	}
	removed, err := sdkcache.RemoveSDKs(cacheRoot, names)
	if err != nil {
		fmt.Fprintf(stderr, "latra: clean cache: %v\n", err)
		return exitError
	}
	if len(removed) == 0 {
		fmt.Fprintln(stdout, "No matching SDK cache entries found.")
		return exitOK
	}
	sort.Strings(removed)
	fmt.Fprintf(stdout, "Removed SDK cache entries: %s.\n", strings.Join(removed, ", "))
	return exitOK
}

func runCacheList(stdout, stderr io.Writer, dependencies Dependencies) int {
	cacheRoot := dependencies.CacheRoot
	if cacheRoot == "" {
		cacheRoot = sdkcache.DefaultRoot
	}
	entries, err := sdkcache.List(cacheRoot)
	if err != nil {
		fmt.Fprintf(stderr, "latra: list cache: %v\n", err)
		return exitError
	}
	if len(entries) == 0 {
		fmt.Fprintln(stdout, "No SDK cache entries found.")
		return exitOK
	}
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SDK\tCHANNEL\tREVISION")
	for _, entry := range entries {
		fmt.Fprintf(w, "%s\t%s\t%d\n", entry.SDK, entry.Channel, entry.Revision)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(stderr, "latra: list cache: write output: %v\n", err)
		return exitError
	}
	return exitOK
}

func parseCacheCleanOptions(args []string) (cacheCleanOptions, error) {
	var options cacheCleanOptions
	if len(args) == 0 || args[0] != "clean" {
		return options, fmt.Errorf("cache requires the clean subcommand")
	}
	for index := 1; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--all":
			options.all = true
		case argument == "--project":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("--project requires a value")
			}
			options.project = args[index]
			if options.project == "" {
				return options, fmt.Errorf("project path must not be empty")
			}
		case strings.HasPrefix(argument, "--project="):
			options.project = strings.TrimPrefix(argument, "--project=")
			if options.project == "" {
				return options, fmt.Errorf("project path must not be empty")
			}
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown cache clean option %q", argument)
		default:
			return options, fmt.Errorf("cache clean does not accept positional arguments")
		}
	}
	if options.all && options.project != "" {
		return options, fmt.Errorf("--project cannot be used with --all")
	}
	return options, nil
}
