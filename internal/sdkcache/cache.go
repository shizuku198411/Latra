// Package sdkcache locates and safely reads SDKs materialized in Latra's cache.
package sdkcache

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/shizuku198411/Latra/internal/sdk"
)

const DefaultRoot = "/tmp/latra/cache"

// Selection narrows a cached SDK by channel and revision.
type Selection struct {
	SDK      string
	Channel  string
	Revision int
}

// Entry identifies one extracted Store SDK revision.
type Entry struct {
	SDK             string
	Channel         string
	Revision        int
	Root            string
	ProjectRoot     string
	ProjectRelative string
}

// List returns every complete Store SDK cache entry. An entry is complete when
// both its extracted revision directory and corresponding .sdk archive exist.
func List(cacheRoot string) ([]Entry, error) {
	root, err := validateCleanRoot(cacheRoot)
	if err != nil {
		return nil, err
	}
	sdkEntries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read SDK cache: %w", err)
	}
	entries := make([]Entry, 0)
	for _, sdkEntry := range sdkEntries {
		if !sdkEntry.IsDir() || sdk.ValidateName(sdkEntry.Name()) != nil {
			continue
		}
		sdkRoot := filepath.Join(root, sdkEntry.Name())
		err := filepath.WalkDir(sdkRoot, func(candidatePath string, candidate fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if candidatePath == sdkRoot || !candidate.IsDir() {
				return nil
			}
			revision, err := strconv.Atoi(candidate.Name())
			if err != nil || revision <= 0 {
				return nil
			}
			archiveInfo, err := os.Stat(candidatePath + ".sdk")
			if err != nil || !archiveInfo.Mode().IsRegular() {
				return filepath.SkipDir
			}
			relativeParent, err := filepath.Rel(sdkRoot, filepath.Dir(candidatePath))
			if err != nil {
				return err
			}
			channel := filepath.ToSlash(relativeParent)
			if sdk.ValidateChannel(channel) != nil {
				return filepath.SkipDir
			}
			entries = append(entries, Entry{
				SDK: sdkEntry.Name(), Channel: channel, Revision: revision, Root: candidatePath,
			})
			return filepath.SkipDir
		})
		if err != nil {
			return nil, fmt.Errorf("inspect SDK cache %q: %w", sdkEntry.Name(), err)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].SDK != entries[j].SDK {
			return entries[i].SDK < entries[j].SDK
		}
		if entries[i].Channel != entries[j].Channel {
			return entries[i].Channel < entries[j].Channel
		}
		return entries[i].Revision > entries[j].Revision
	})
	return entries, nil
}

// ResolveProject locates an in-project SDK beneath .workshop without following an escaping path.
func ResolveProject(projectRoot, name string) (Entry, error) {
	if err := sdk.ValidateName(name); err != nil {
		return Entry{}, err
	}
	absolute, err := filepath.Abs(projectRoot)
	if err != nil {
		return Entry{}, err
	}
	project, err := os.OpenRoot(absolute)
	if err != nil {
		return Entry{}, err
	}
	defer project.Close()
	relative := path.Join(".workshop", name)
	sdkRoot, err := project.OpenRoot(relative)
	if err != nil {
		return Entry{}, err
	}
	if err := sdkRoot.Close(); err != nil {
		return Entry{}, err
	}
	return Entry{
		SDK: name, Root: filepath.Join(absolute, filepath.FromSlash(relative)),
		ProjectRoot: absolute, ProjectRelative: relative,
	}, nil
}

// Resolve selects one cached SDK revision deterministically.
func Resolve(cacheRoot string, selection Selection) (Entry, error) {
	if err := sdk.ValidateName(selection.SDK); err != nil {
		return Entry{}, err
	}
	if selection.Channel != "" {
		if err := sdk.ValidateChannel(selection.Channel); err != nil {
			return Entry{}, err
		}
	}
	if selection.Revision < 0 {
		return Entry{}, fmt.Errorf("revision must not be negative")
	}

	sdkRoot := filepath.Join(cacheRoot, selection.SDK)
	var candidates []Entry
	err := filepath.WalkDir(sdkRoot, func(candidatePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if candidatePath == sdkRoot || !entry.IsDir() {
			return nil
		}
		revision, err := strconv.Atoi(entry.Name())
		if err != nil || revision <= 0 {
			return nil
		}
		archivePath := candidatePath + ".sdk"
		if info, err := os.Stat(archivePath); err != nil || !info.Mode().IsRegular() {
			return nil
		}
		relativeParent, err := filepath.Rel(sdkRoot, filepath.Dir(candidatePath))
		if err != nil {
			return err
		}
		channel := filepath.ToSlash(relativeParent)
		if err := sdk.ValidateChannel(channel); err != nil {
			return nil
		}
		if selection.Revision != 0 && revision != selection.Revision {
			return filepath.SkipDir
		}
		candidates = append(candidates, Entry{SDK: selection.SDK, Channel: channel, Revision: revision, Root: candidatePath})
		return filepath.SkipDir
	})
	if errors.Is(err, fs.ErrNotExist) {
		return Entry{}, fmt.Errorf("SDK %q was not found in cache %q", selection.SDK, cacheRoot)
	}
	if err != nil {
		return Entry{}, fmt.Errorf("inspect SDK cache: %w", err)
	}
	if len(candidates) == 0 {
		return Entry{}, fmt.Errorf("no cached revision matched SDK %q", selection.SDK)
	}
	if selection.Channel != "" {
		candidates = selectChannel(candidates, selection.Channel)
		if len(candidates) == 0 {
			return Entry{}, fmt.Errorf("no cached revision matched SDK %q channel %q", selection.SDK, selection.Channel)
		}
	}

	channels := make(map[string]struct{})
	for _, candidate := range candidates {
		channels[candidate.Channel] = struct{}{}
	}
	if len(channels) > 1 {
		names := make([]string, 0, len(channels))
		for channel := range channels {
			names = append(names, channel)
		}
		sort.Strings(names)
		return Entry{}, fmt.Errorf("SDK %q has multiple cached channels (%s); specify one with --channel", selection.SDK, strings.Join(names, ", "))
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Revision > candidates[j].Revision })
	return candidates[0], nil
}

func selectChannel(candidates []Entry, requested string) []Entry {
	filter := func(matches func(string) bool) []Entry {
		var selected []Entry
		for _, candidate := range candidates {
			if matches(candidate.Channel) {
				selected = append(selected, candidate)
			}
		}
		return selected
	}
	if exact := filter(func(channel string) bool { return channel == requested }); len(exact) > 0 {
		return exact
	}
	parts := strings.Split(requested, "/")
	risks := map[string]bool{"stable": true, "candidate": true, "beta": true, "edge": true}
	preferred := ""
	switch {
	case len(parts) == 1 && risks[parts[0]]:
		preferred = "latest/" + requested
	case len(parts) == 1:
		preferred = requested + "/stable"
	case len(parts) == 2 && risks[parts[0]]:
		preferred = "latest/" + requested
	}
	if preferred != "" {
		if selected := filter(func(channel string) bool { return channel == preferred }); len(selected) > 0 {
			return selected
		}
	}
	return filter(func(channel string) bool {
		effective := strings.Split(channel, "/")
		switch {
		case len(parts) == 1 && risks[parts[0]]:
			return len(effective) >= 2 && effective[1] == parts[0]
		case len(parts) == 1:
			return len(effective) >= 1 && effective[0] == parts[0]
		case len(parts) == 2 && risks[parts[0]]:
			return len(effective) == 3 && effective[1] == parts[0] && effective[2] == parts[1]
		default:
			return false
		}
	})
}

// OpenFile safely opens a regular file relative to a selected SDK root.
func OpenFile(entry Entry, requestedPath string) (io.ReadCloser, fs.FileInfo, error) {
	clean := path.Clean(strings.ReplaceAll(requestedPath, "\\", "/"))
	if requestedPath == "" || clean == "." || clean == ManifestPath || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil, nil, fmt.Errorf("unsafe SDK file path %q", requestedPath)
	}
	var roots []*os.Root
	var root *os.Root
	var err error
	if entry.ProjectRoot != "" {
		projectRoot, projectErr := os.OpenRoot(entry.ProjectRoot)
		if projectErr != nil {
			return nil, nil, projectErr
		}
		root, err = projectRoot.OpenRoot(entry.ProjectRelative)
		if err != nil {
			projectRoot.Close()
			return nil, nil, err
		}
		roots = append(roots, projectRoot)
	} else {
		root, err = os.OpenRoot(entry.Root)
	}
	if err != nil {
		return nil, nil, err
	}
	roots = append(roots, root)
	file, err := root.Open(clean)
	if err != nil {
		closeRoots(roots)
		if errors.Is(err, fs.ErrNotExist) {
			skipped, manifestErr := skippedFile(entry, clean)
			if manifestErr != nil {
				return nil, nil, manifestErr
			}
			if skipped != nil {
				return nil, nil, &ContentSkippedError{File: *skipped}
			}
		}
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		closeRoots(roots)
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		closeRoots(roots)
		return nil, nil, fmt.Errorf("SDK path %q is not a regular file", clean)
	}
	return &rootFile{File: file, roots: roots}, info, nil
}

type rootFile struct {
	*os.File
	roots []*os.Root
}

func (f *rootFile) Close() error {
	fileErr := f.File.Close()
	return errors.Join(fileErr, closeRoots(f.roots))
}

func closeRoots(roots []*os.Root) error {
	var errs []error
	for index := len(roots) - 1; index >= 0; index-- {
		errs = append(errs, roots[index].Close())
	}
	return errors.Join(errs...)
}

// ReadDir lists the immediate children of a directory within an SDK without
// allowing paths to escape the SDK root. It never follows a child symlink.
// Pass "." for the SDK's top-level directory.
func ReadDir(entry Entry, directory string) ([]fs.DirEntry, error) {
	clean := path.Clean(strings.ReplaceAll(directory, "\\", "/"))
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil, fmt.Errorf("unsafe SDK directory %q", directory)
	}
	var root *os.Root
	if entry.ProjectRoot != "" {
		project, err := os.OpenRoot(entry.ProjectRoot)
		if err != nil {
			return nil, err
		}
		defer project.Close()
		root, err = project.OpenRoot(entry.ProjectRelative)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		root, err = os.OpenRoot(entry.Root)
		if err != nil {
			return nil, err
		}
	}
	defer root.Close()
	// Reject a symlink in any intermediate component, rather than traversing it.
	if clean != "." {
		parts := strings.Split(clean, "/")
		for i := range parts {
			part := strings.Join(parts[:i+1], "/")
			info, err := root.Lstat(part)
			if err != nil {
				return nil, err
			}
			if !info.IsDir() {
				return nil, fmt.Errorf("SDK directory %q is not a directory", part)
			}
		}
	}
	file, err := root.Open(clean)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.ReadDir(-1)
}
