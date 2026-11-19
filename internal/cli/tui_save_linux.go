//go:build linux

package cli

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"syscall"

	"github.com/shizuku198411/Latra/internal/finding"
	"go.yaml.in/yaml/v3"
)

// Lock the directory rather than the YAML inode, which is replaced on save.
func saveReviewedRules(project string, candidates []finding.SuppressionRule, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(candidates) == 0 {
		return errors.New("A reason and at least one rule are required")
	}
	return editSuppressionFile(project, true, func(existing []finding.SuppressionRule, rules *yaml.Node) error {
		for _, candidate := range candidates {
			for _, r := range existing {
				if r.SDK == candidate.SDK && r.Hook == candidate.Hook && r.Risk == candidate.Risk {
					for _, line := range candidate.Lines {
						if len(r.Lines) == 0 || slices.Contains(r.Lines, line) {
							return fmt.Errorf("Already covered by %s (line %d)", r.ID, line)
						}
					}
				}
				if r.ID == candidate.ID {
					return fmt.Errorf("Rule ID already exists: %s", r.ID)
				}
			}
			candidate.Reason = reason
			var node yaml.Node
			if err := node.Encode(candidate); err != nil {
				return err
			}
			rules.Content = append(rules.Content, &node)
			existing = append(existing, candidate)
		}
		return nil
	})
}

func deleteReviewedRule(project string, selected finding.SuppressionRule) error {
	return editSuppressionFile(project, false, func(existing []finding.SuppressionRule, rules *yaml.Node) error {
		for i, r := range existing {
			if r.ID != selected.ID {
				continue
			}
			if !reflect.DeepEqual(r, selected) {
				return fmt.Errorf("Rule %s changed since review", r.ID)
			}
			rules.Content = slices.Delete(rules.Content, i, i+1)
			return nil
		}
		return fmt.Errorf("Rule %s no longer exists", selected.ID)
	})
}

func editSuppressionFile(project string, create bool, edit func([]finding.SuppressionRule, *yaml.Node) error) error {
	root, err := os.OpenRoot(project)
	if err != nil {
		return err
	}
	defer root.Close()
	directory, name := path.Split(finding.SuppressionPath)
	if create {
		if err := root.MkdirAll(directory, 0755); err != nil {
			return err
		}
	}
	dir, err := root.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}

	const limit = 1 << 20
	var data []byte
	mode := fs.FileMode(0600)
	info, err := dir.Lstat(name)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", name)
		}
		mode = info.Mode().Perm()
		file, err := dir.Open(name)
		if err != nil {
			return err
		}
		defer file.Close()
		data, err = io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil {
			return err
		}
		if len(data) > limit {
			return fmt.Errorf("%s exceeds size limit", name)
		}
	} else if create && errors.Is(err, fs.ErrNotExist) {
		data = []byte("version: 1\nrules: []\n")
	} else {
		return err
	}

	existing, err := finding.ParseSuppression(data)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	var rules *yaml.Node
	fields := doc.Content[0].Content
	for i := 0; i < len(fields); i += 2 {
		if fields[i].Value == "rules" {
			rules = fields[i+1]
			break
		}
	}
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return errors.New("Expected a rules sequence")
	}
	rules.Style &^= yaml.FlowStyle
	if err := edit(existing, rules); err != nil {
		return err
	}
	doc.Content[0].Style &^= yaml.FlowStyle
	data, err = yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	// Marshal indents top-level sequence entries by four spaces. Nested lists
	// and block scalar content have deeper indentation.
	lines := strings.Split(string(data), "\n")
	var spaced []string
	seenRule := false
	for _, line := range lines {
		if strings.HasPrefix(line, "    - ") || line == "    -" {
			if seenRule && spaced[len(spaced)-1] != "" {
				spaced = append(spaced, "")
			}
			seenRule = true
		}
		spaced = append(spaced, line)
	}
	data = []byte(strings.Join(spaced, "\n"))
	if len(data) > limit {
		return fmt.Errorf("%s exceeds size limit", name)
	}
	if _, err := finding.ParseSuppression(data); err != nil {
		return err
	}
	tmp := ".suppression-" + rand.Text()
	file, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer dir.Remove(tmp)
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Chmod(mode); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return dir.Rename(tmp, name)
}
