package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/sdkcache"
	"github.com/shizuku198411/Latra/internal/source"
)

type tuiSDK struct {
	Name, Source, Channel, Status, Workshops string
	Entry                                    sdkcache.Entry
	Error                                    string
}

// loadTUIInventory keeps the cache-only behavior for callers without a Store resolver.
func loadTUIInventory(project, cacheRoot string) (string, []tuiSDK, error) {
	return loadTUIInventoryWithResolver(project, cacheRoot, nil, nil)
}

// loadTUIInventoryWithResolver reuses scan discovery and downloads only missing Store SDKs.
// A failed Store resolution is displayed per SDK rather than aborting the explorer.
func loadTUIInventoryWithResolver(project, cacheRoot string, resolver source.StoreResolver, onDownload func(string)) (string, []tuiSDK, error) {
	absolute, err := filepath.Abs(project)
	if err != nil {
		return "", nil, err
	}
	// Unlike the generic scanner, the TUI only accepts Workshop projects.
	// Check this before scanning so an empty directory is not interpreted as an SDK.
	workshopDir, err := os.Stat(filepath.Join(absolute, ".workshop"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, fmt.Errorf("%s is not a Workshop project: .workshop directory not found", absolute)
	}
	if err != nil {
		return "", nil, fmt.Errorf("inspect .workshop: %w", err)
	}
	if !workshopDir.IsDir() {
		return "", nil, fmt.Errorf("%s is not a Workshop project: .workshop is not a directory", absolute)
	}
	result, err := source.DiscoverProject(context.Background(), absolute, sdk.DefaultLimits())
	if err != nil {
		return "", nil, err
	}
	if result.Kind != source.InputProject {
		return "", nil, fmt.Errorf("%s is an SDK directory, not a Workshop project", absolute)
	}
	if cacheRoot == "" {
		cacheRoot = sdkcache.DefaultRoot
	}
	entries := make([]tuiSDK, 0, len(result.SDKs))
	for _, s := range result.SDKs {
		entry := tuiSDK{Name: s.Name, Source: string(s.Source), Channel: s.Channel, Status: "unknown"}
		workshops := make([]string, 0, len(s.Declarations))
		seen := make(map[string]bool)
		for _, d := range s.Declarations {
			if !seen[d.Workshop] {
				workshops = append(workshops, d.Workshop)
				seen[d.Workshop] = true
			}
		}
		entry.Workshops = strings.Join(workshops, ", ")
		switch s.Source {
		case sdk.SourceProject:
			if resolved, err := sdkcache.ResolveProject(absolute, s.Name); err != nil {
				entry.Status = "unavailable"
			} else {
				entry.Status = "local"
				entry.Entry = resolved
			}
		case sdk.SourceStore:
			if resolved, err := sdkcache.Resolve(cacheRoot, sdkcache.Selection{SDK: s.Name, Channel: s.Channel}); err != nil {
				entry.Status = "not cached"
				if resolver != nil {
					if len(s.Declarations) == 0 {
						entry.Status, entry.Error = "failed", "missing Workshop declaration for Store SDK"
					} else {
						if onDownload != nil {
							onDownload(s.Name)
						}
						_, downloadErr := resolver.Resolve(context.Background(), source.StoreRequest{
							Name: s.Name, Channel: s.Channel, Base: s.Declarations[0].Base,
						}, sdk.DefaultLimits())
						if downloadErr != nil {
							entry.Status, entry.Error = "failed", downloadErr.Error()
						} else if cached, cacheErr := sdkcache.Resolve(cacheRoot, sdkcache.Selection{SDK: s.Name, Channel: s.Channel}); cacheErr != nil {
							entry.Status, entry.Error = "failed", cacheErr.Error()
						} else {
							entry.Status, entry.Entry = "cached", cached
						}
					}
				}
			} else {
				entry.Status = "cached"
				entry.Entry = resolved
			}
		default:
			entry.Status = "unsupported"
		}
		entries = append(entries, entry)
	}
	return absolute, entries, nil
}

func runTUI(args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	project := dependencies.WorkingDirectory
	if project == "" {
		project = "."
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--project":
			i++
			if i == len(args) || args[i] == "" {
				return usageError(stderr, "--project requires a path")
			}
			project = args[i]
		case strings.HasPrefix(a, "--project="):
			project = strings.TrimPrefix(a, "--project=")
			if project == "" {
				return usageError(stderr, "--project requires a path")
			}
		default:
			return usageError(stderr, "unknown explorer option %q", a)
		}
	}
	absolute, entries, err := loadTUIInventoryWithResolver(project, dependencies.CacheRoot, dependencies.StoreResolver, func(name string) {
		fmt.Fprintf(stderr, "latra: explorer: downloading SDK %q...\n", name)
	})
	if err != nil {
		fmt.Fprintf(stderr, "latra: explorer: %v\n", err)
		return exitError
	}
	// TUI requires the process's own terminal, not a redirected output stream.
	if err := runTerminalExplorer(absolute, entries, dependencies.StoreResolver); err != nil {
		if errors.Is(err, errNotTerminal) {
			fmt.Fprintln(stderr, "latra: explorer requires an interactive terminal")
		} else {
			fmt.Fprintf(stderr, "latra: explorer: %v\n", err)
		}
		return exitError
	}
	_ = stdout
	return exitOK
}
