// Package sdk models and reads Canonical Workshop SDK contents.
package sdk

import (
	"io/fs"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/shell"
)

// Source identifies where an SDK declaration is resolved from.
type Source string

const (
	SourceStore   Source = "store"
	SourceProject Source = "project"
	SourceTry     Source = "try"
	SourceSystem  Source = "system"
)

// ResolutionState describes whether Latra obtained the SDK contents.
type ResolutionState string

const (
	StateResolved    ResolutionState = "Resolved"
	StateNotResolved ResolutionState = "NotResolved"
)

// HookName is a Workshop lifecycle hook recognized by Latra.
type HookName string

const (
	HookSetupBase    HookName = "setup-base"
	HookSetupProject HookName = "setup-project"
	HookCheckHealth  HookName = "check-health"
	HookSaveState    HookName = "save-state"
	HookRestoreState HookName = "restore-state"
)

// HookNames is the deterministic order used when reading and reporting hooks.
var HookNames = []HookName{
	HookSetupBase,
	HookSetupProject,
	HookCheckHealth,
	HookSaveState,
	HookRestoreState,
}

// Metadata is the runtime sdk.yaml format accepted by Workshop v0.9.9.
type Metadata struct {
	Name         string         `yaml:"name" json:"name"`
	Title        string         `yaml:"title,omitempty" json:"title,omitempty"`
	Version      string         `yaml:"version,omitempty" json:"version,omitempty"`
	Summary      string         `yaml:"summary,omitempty" json:"summary,omitempty"`
	Description  string         `yaml:"description,omitempty" json:"description,omitempty"`
	Base         string         `yaml:"base,omitempty" json:"base,omitempty"`
	Architecture string         `yaml:"architecture,omitempty" json:"architecture,omitempty"`
	Contact      StringList     `yaml:"contact,omitempty" json:"contact,omitempty"`
	Issues       StringList     `yaml:"issues,omitempty" json:"issues,omitempty"`
	SourceCode   string         `yaml:"source-code,omitempty" json:"sourceCode,omitempty"`
	Website      string         `yaml:"website,omitempty" json:"website,omitempty"`
	License      string         `yaml:"license,omitempty" json:"license,omitempty"`
	Plugs        map[string]any `yaml:"plugs,omitempty" json:"plugs,omitempty"`
	Slots        map[string]any `yaml:"slots,omitempty" json:"slots,omitempty"`
	BuiltAt      string         `yaml:"sdkcraft-started-at,omitempty" json:"sdkcraftStartedAt,omitempty"`
	Type         string         `yaml:"type,omitempty" json:"type,omitempty"`
}

// StringList accepts the scalar-or-sequence representation used by SDK metadata.
type StringList []string

// Declaration records where and how a Workshop definition requested an SDK.
type Declaration struct {
	Definition string         `json:"definition"`
	Workshop   string         `json:"workshop"`
	Base       string         `json:"base"`
	Channel    string         `json:"channel,omitempty"`
	Plugs      map[string]any `json:"plugs,omitempty"`
	Slots      map[string]any `json:"slots,omitempty"`
}

// FileType classifies entries without reading unsafe special files.
type FileType string

const (
	FileRegular   FileType = "regular"
	FileDirectory FileType = "directory"
	FileSymlink   FileType = "symlink"
	FileOther     FileType = "other"
)

// File describes one entry bundled in an SDK directory.
type File struct {
	Path       string      `json:"path"`
	Type       FileType    `json:"type"`
	Mode       fs.FileMode `json:"mode"`
	Size       int64       `json:"size,omitempty"`
	Digest     string      `json:"digest,omitempty"`
	LinkTarget string      `json:"linkTarget,omitempty"`
	Content    []byte      `json:"-"`
}

// Hook contains the source retained for later AST parsing.
type Hook struct {
	Name     HookName         `json:"name"`
	Path     string           `json:"path"`
	Content  []byte           `json:"-"`
	Digest   string           `json:"digest"`
	Size     int64            `json:"size"`
	Parse    *shell.Result    `json:"parse,omitempty"`
	Analysis *analysis.Result `json:"analysis,omitempty"`
}

// SDK is the source-resolution result consumed by later analysis stages.
type SDK struct {
	Name         string          `json:"name"`
	Source       Source          `json:"source"`
	State        ResolutionState `json:"state"`
	Channel      string          `json:"channel,omitempty"`
	Root         string          `json:"root,omitempty"`
	MetadataPath string          `json:"metadataPath,omitempty"`
	Metadata     *Metadata       `json:"metadata,omitempty"`
	Hooks        []Hook          `json:"hooks,omitempty"`
	Files        []File          `json:"files,omitempty"`
	Digest       string          `json:"digest,omitempty"`
	Declarations []Declaration   `json:"declarations,omitempty"`
}
