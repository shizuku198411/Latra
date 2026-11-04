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
		if selection.Channel != "" && channel != selection.Channel {
			return filepath.SkipDir
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

// OpenFile safely opens a regular file relative to a selected SDK root.
func OpenFile(entry Entry, requestedPath string) (io.ReadCloser, fs.FileInfo, error) {
	clean := path.Clean(strings.ReplaceAll(requestedPath, "\\", "/"))
	if requestedPath == "" || clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
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
