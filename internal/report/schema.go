package report

import (
	"encoding/base64"
	"io/fs"
	"sort"
	"unicode/utf8"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/buildinfo"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
	"github.com/shizuku198411/Latra/internal/source"
)

const SchemaVersion = "1"

// Document is the stable, versioned JSON inventory representation.
type Document struct {
	SchemaVersion string               `json:"schemaVersion"`
	Scanner       Scanner              `json:"scanner"`
	Input         Input                `json:"input"`
	Summary       Summary              `json:"summary"`
	Workshops     []source.Workshop    `json:"workshops"`
	SDKs          []SDK                `json:"sdks"`
	Diagnostics   []DocumentDiagnostic `json:"diagnostics"`
}

type Scanner struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

type Input struct {
	Kind source.InputKind `json:"kind"`
	Root string           `json:"root"`
}

type Summary struct {
	SDKs           int `json:"sdks"`
	ResolvedSDKs   int `json:"resolvedSdks"`
	UnresolvedSDKs int `json:"unresolvedSdks"`
	Files          int `json:"files"`
	Hooks          int `json:"hooks"`
	Operations     int `json:"operations"`
	Capabilities   int `json:"capabilities"`
	Diagnostics    int `json:"diagnostics"`
}

type SDK struct {
	Name         string              `json:"name"`
	Source       sdk.Source          `json:"source"`
	State        sdk.ResolutionState `json:"state"`
	Channel      string              `json:"channel,omitempty"`
	Root         string              `json:"root,omitempty"`
	Digest       string              `json:"digest,omitempty"`
	MetadataPath string              `json:"metadataPath,omitempty"`
	Metadata     *sdk.Metadata       `json:"metadata,omitempty"`
	Declarations []sdk.Declaration   `json:"declarations"`
	Files        []File              `json:"files"`
	Hooks        []Hook              `json:"hooks"`
}

type File struct {
	Path            string       `json:"path"`
	Type            sdk.FileType `json:"type"`
	Mode            fs.FileMode  `json:"mode"`
	Size            int64        `json:"size,omitempty"`
	Digest          string       `json:"digest,omitempty"`
	LinkTarget      string       `json:"linkTarget,omitempty"`
	Content         *string      `json:"content,omitempty"`
	ContentEncoding string       `json:"contentEncoding,omitempty"`
}

type Hook struct {
	Name         sdk.HookName          `json:"name"`
	Path         string                `json:"path"`
	Digest       string                `json:"digest"`
	Size         int64                 `json:"size"`
	Parse        *Parse                `json:"parse,omitempty"`
	Context      *analysis.HookContext `json:"context,omitempty"`
	Operations   []analysis.Operation  `json:"operations"`
	Capabilities []analysis.Capability `json:"capabilities"`
}

type Parse struct {
	Status      shell.ParseStatus  `json:"status"`
	Recovered   bool               `json:"recovered"`
	NodeTypes   map[string]int     `json:"nodeTypes"`
	Diagnostics []shell.Diagnostic `json:"diagnostics"`
}

type DocumentDiagnostic struct {
	SDK        string           `json:"sdk"`
	Hook       sdk.HookName     `json:"hook"`
	Diagnostic shell.Diagnostic `json:"diagnostic"`
}

// NewDocument builds a deterministic report document from a scan result.
func NewDocument(result *source.Result) Document {
	info := buildinfo.Current()
	document := Document{
		SchemaVersion: SchemaVersion,
		Scanner:       Scanner{Name: "latra", Version: info.Version, Commit: info.Commit, BuildDate: info.BuildDate},
		Input:         Input{Kind: result.Kind, Root: result.Root},
		Workshops:     append([]source.Workshop{}, result.Workshops...),
		SDKs:          []SDK{},
		Diagnostics:   []DocumentDiagnostic{},
	}
	sort.Slice(document.Workshops, func(i, j int) bool {
		if document.Workshops[i].Name != document.Workshops[j].Name {
			return document.Workshops[i].Name < document.Workshops[j].Name
		}
		return document.Workshops[i].Definition < document.Workshops[j].Definition
	})

	items := append([]sdk.SDK(nil), result.SDKs...)
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	for _, item := range items {
		reported := SDK{
			Name: item.Name, Source: item.Source, State: item.State, Channel: item.Channel,
			Root: item.Root, Digest: item.Digest, MetadataPath: item.MetadataPath, Metadata: item.Metadata,
			Declarations: append([]sdk.Declaration{}, item.Declarations...),
			Files:        reportFiles(item.Files),
			Hooks:        []Hook{},
		}
		sort.Slice(reported.Declarations, func(i, j int) bool {
			if reported.Declarations[i].Workshop != reported.Declarations[j].Workshop {
				return reported.Declarations[i].Workshop < reported.Declarations[j].Workshop
			}
			return reported.Declarations[i].Definition < reported.Declarations[j].Definition
		})
		sort.Slice(reported.Files, func(i, j int) bool { return reported.Files[i].Path < reported.Files[j].Path })
		for _, hook := range item.Hooks {
			reportedHook := Hook{
				Name: hook.Name, Path: hook.Path, Digest: hook.Digest, Size: hook.Size,
				Operations: []analysis.Operation{}, Capabilities: []analysis.Capability{},
			}
			if hook.Parse != nil {
				reportedHook.Parse = &Parse{
					Status: hook.Parse.Status, Recovered: hook.Parse.Recovered,
					NodeTypes:   cloneNodeTypes(hook.Parse.NodeTypes),
					Diagnostics: append([]shell.Diagnostic{}, hook.Parse.Diagnostics...),
				}
				for _, diagnostic := range hook.Parse.Diagnostics {
					document.Diagnostics = append(document.Diagnostics, DocumentDiagnostic{
						SDK: item.Name, Hook: hook.Name, Diagnostic: diagnostic,
					})
				}
			}
			if hook.Analysis != nil {
				context := hook.Analysis.Context
				reportedHook.Context = &context
				reportedHook.Operations = cloneAndSortOperations(hook.Analysis.Operations)
				reportedHook.Capabilities = append([]analysis.Capability{}, hook.Analysis.Capabilities...)
				sortCapabilities(reportedHook.Capabilities)
			}
			reported.Hooks = append(reported.Hooks, reportedHook)
		}
		sort.Slice(reported.Hooks, func(i, j int) bool { return reported.Hooks[i].Name < reported.Hooks[j].Name })
		document.SDKs = append(document.SDKs, reported)
	}
	sort.Slice(document.Diagnostics, func(i, j int) bool {
		left, right := document.Diagnostics[i], document.Diagnostics[j]
		if left.SDK != right.SDK {
			return left.SDK < right.SDK
		}
		if left.Hook != right.Hook {
			return left.Hook < right.Hook
		}
		if left.Diagnostic.Location.StartLine != right.Diagnostic.Location.StartLine {
			return left.Diagnostic.Location.StartLine < right.Diagnostic.Location.StartLine
		}
		return left.Diagnostic.Location.StartColumn < right.Diagnostic.Location.StartColumn
	})
	document.Summary = summarize(document)
	return document
}

func summarize(document Document) Summary {
	summary := Summary{SDKs: len(document.SDKs), Diagnostics: len(document.Diagnostics)}
	for _, item := range document.SDKs {
		if item.State == sdk.StateResolved {
			summary.ResolvedSDKs++
		} else {
			summary.UnresolvedSDKs++
		}
		summary.Files += len(item.Files)
		summary.Hooks += len(item.Hooks)
		for _, hook := range item.Hooks {
			summary.Operations += countOperations(hook.Operations)
			summary.Capabilities += len(hook.Capabilities)
		}
	}
	return summary
}

func countOperations(operations []analysis.Operation) int {
	count := len(operations)
	for _, operation := range operations {
		count += countOperations(operation.Children)
	}
	return count
}

func cloneAndSortOperations(operations []analysis.Operation) []analysis.Operation {
	clone := append([]analysis.Operation{}, operations...)
	for index := range clone {
		clone[index].Children = cloneAndSortOperations(clone[index].Children)
	}
	sort.SliceStable(clone, func(i, j int) bool {
		left, right := clone[i].Location, clone[j].Location
		if left.StartLine != right.StartLine {
			return left.StartLine < right.StartLine
		}
		if left.StartColumn != right.StartColumn {
			return left.StartColumn < right.StartColumn
		}
		return clone[i].Kind < clone[j].Kind
	})
	return clone
}

func sortCapabilities(capabilities []analysis.Capability) {
	sort.SliceStable(capabilities, func(i, j int) bool {
		left, right := capabilities[i], capabilities[j]
		if left.Location.StartLine != right.Location.StartLine {
			return left.Location.StartLine < right.Location.StartLine
		}
		if left.Location.StartColumn != right.Location.StartColumn {
			return left.Location.StartColumn < right.Location.StartColumn
		}
		return left.Kind < right.Kind
	})
}

func cloneNodeTypes(nodeTypes map[string]int) map[string]int {
	clone := make(map[string]int, len(nodeTypes))
	for key, value := range nodeTypes {
		clone[key] = value
	}
	return clone
}

func reportFiles(files []sdk.File) []File {
	reported := make([]File, 0, len(files))
	for _, file := range files {
		item := File{
			Path: file.Path, Type: file.Type, Mode: file.Mode, Size: file.Size,
			Digest: file.Digest, LinkTarget: file.LinkTarget,
		}
		if file.Type == sdk.FileRegular {
			content, encoding := encodeContent(file.Content)
			item.Content = &content
			item.ContentEncoding = encoding
		}
		reported = append(reported, item)
	}
	return reported
}

func encodeContent(content []byte) (string, string) {
	if utf8.Valid(content) {
		return string(content), "utf-8"
	}
	return base64.StdEncoding.EncodeToString(content), "base64"
}
