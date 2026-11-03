package report

import (
	"crypto/sha3"
	"encoding/hex"
	"io/fs"
	"sort"
	"unicode"
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
	SDKs            SDKSummary            `json:"sdks"`
	Files           FileSummary           `json:"files"`
	Hooks           HookSummary           `json:"hooks"`
	Operations      OperationSummary      `json:"operations"`
	Capabilities    CapabilitySummary     `json:"capabilities"`
	UnknownCommands UnknownCommandSummary `json:"unknownCommands"`
	Diagnostics     DiagnosticSummary     `json:"diagnostics"`
}

type SDKSummary struct {
	Count      int            `json:"count"`
	SDKNames   SDKNameSummary `json:"sdkNames"`
	Resolved   int            `json:"resolved"`
	Unresolved int            `json:"unresolved"`
}

type SDKNameSummary struct {
	Resolved   []string `json:"resolved"`
	Unresolved []string `json:"unresolved"`
}

type FileSummary struct {
	Count int              `json:"count"`
	BySDK []SDKFileSummary `json:"bySdk"`
}

type HookSummary struct {
	Count int              `json:"count"`
	BySDK []SDKHookSummary `json:"bySdk"`
}

type OperationSummary struct {
	Count int                   `json:"count"`
	BySDK []SDKOperationSummary `json:"bySdk"`
}

type CapabilitySummary struct {
	Count int                    `json:"count"`
	BySDK []SDKCapabilitySummary `json:"bySdk"`
}

type UnknownCommandSummary struct {
	Count int                        `json:"count"`
	BySDK []SDKUnknownCommandSummary `json:"bySdk"`
}

type SDKUnknownCommandSummary struct {
	SDKName string                      `json:"sdkName"`
	Count   int                         `json:"count"`
	Files   []FileUnknownCommandSummary `json:"files"`
}

type FileUnknownCommandSummary struct {
	FilePath     string        `json:"filePath"`
	Count        int           `json:"count"`
	CommandNames []CountedName `json:"commandNames"`
}

type CountedName struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type SDKFileSummary struct {
	SDKName   string   `json:"sdkName"`
	Count     int      `json:"count"`
	FilePaths []string `json:"filePaths"`
}

type SDKHookSummary struct {
	SDKName   string   `json:"sdkName"`
	Count     int      `json:"count"`
	HookNames []string `json:"hookNames"`
}

type SDKOperationSummary struct {
	SDKName        string        `json:"sdkName"`
	Count          int           `json:"count"`
	OperationKinds []CountedName `json:"operationKinds"`
}

type SDKCapabilitySummary struct {
	SDKName         string        `json:"sdkName"`
	Count           int           `json:"count"`
	CapabilityNames []CountedName `json:"capabilityNames"`
}

type DiagnosticSummary struct {
	Count           int           `json:"count"`
	DiagnosticCodes []CountedName `json:"diagnosticCodes"`
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
	Diagnostics  []sdk.Diagnostic    `json:"diagnostics,omitempty"`
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
	SDK        string          `json:"sdk"`
	Hook       sdk.HookName    `json:"hook,omitempty"`
	Code       string          `json:"code"`
	Severity   string          `json:"severity"`
	Phase      string          `json:"phase,omitempty"`
	Message    string          `json:"message"`
	Location   *shell.Location `json:"location,omitempty"`
	Incomplete bool            `json:"incomplete,omitempty"`
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
			Diagnostics:  append([]sdk.Diagnostic{}, item.Diagnostics...),
		}
		for _, diagnostic := range item.Diagnostics {
			document.Diagnostics = append(document.Diagnostics, DocumentDiagnostic{
				SDK: item.Name, Code: diagnostic.Code, Severity: string(diagnostic.Severity),
				Phase: diagnostic.Phase, Message: diagnostic.Message,
			})
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
					location := diagnostic.Location
					document.Diagnostics = append(document.Diagnostics, DocumentDiagnostic{
						SDK: item.Name, Hook: hook.Name, Code: diagnostic.Code,
						Severity: string(diagnostic.Severity), Message: diagnostic.Message,
						Location: &location, Incomplete: diagnostic.Incomplete,
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
		if left.Phase != right.Phase {
			return left.Phase < right.Phase
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		leftLine, rightLine := 0, 0
		if left.Location != nil {
			leftLine = left.Location.StartLine
		}
		if right.Location != nil {
			rightLine = right.Location.StartLine
		}
		return leftLine < rightLine
	})
	document.Summary = summarize(document)
	return document
}

func summarize(document Document) Summary {
	summary := Summary{
		SDKs: SDKSummary{
			Count:    len(document.SDKs),
			SDKNames: SDKNameSummary{Resolved: []string{}, Unresolved: []string{}},
		},
		Files:           FileSummary{BySDK: []SDKFileSummary{}},
		Hooks:           HookSummary{BySDK: []SDKHookSummary{}},
		Operations:      OperationSummary{BySDK: []SDKOperationSummary{}},
		Capabilities:    CapabilitySummary{BySDK: []SDKCapabilitySummary{}},
		UnknownCommands: UnknownCommandSummary{BySDK: []SDKUnknownCommandSummary{}},
		Diagnostics:     DiagnosticSummary{Count: len(document.Diagnostics), DiagnosticCodes: []CountedName{}},
	}
	resolvedSDKNames := make(map[string]struct{})
	unresolvedSDKNames := make(map[string]struct{})
	diagnosticCodes := make(map[string]int)
	for _, diagnostic := range document.Diagnostics {
		diagnosticCodes[diagnostic.Code]++
	}
	for _, item := range document.SDKs {
		if item.State == sdk.StateResolved {
			summary.SDKs.Resolved++
			resolvedSDKNames[item.Name] = struct{}{}
		} else {
			summary.SDKs.Unresolved++
			unresolvedSDKNames[item.Name] = struct{}{}
		}
		fileSummary := SDKFileSummary{SDKName: item.Name, Count: len(item.Files), FilePaths: []string{}}
		for _, file := range item.Files {
			fileSummary.FilePaths = append(fileSummary.FilePaths, file.Path)
		}
		hookSummary := SDKHookSummary{SDKName: item.Name, Count: len(item.Hooks), HookNames: []string{}}
		operationSummary := SDKOperationSummary{SDKName: item.Name, OperationKinds: []CountedName{}}
		capabilitySummary := SDKCapabilitySummary{SDKName: item.Name, CapabilityNames: []CountedName{}}
		unknownCommandSummary := SDKUnknownCommandSummary{SDKName: item.Name, Files: []FileUnknownCommandSummary{}}
		hookNames := make(map[string]struct{})
		operationKinds := make(map[string]int)
		capabilityNames := make(map[string]int)
		for _, hook := range item.Hooks {
			hookNames[string(hook.Name)] = struct{}{}
			operationSummary.Count += countOperations(hook.Operations)
			collectOperationKinds(hook.Operations, operationKinds)
			capabilitySummary.Count += len(hook.Capabilities)
			for _, capability := range hook.Capabilities {
				capabilityNames[capability.Kind]++
			}
			unknownNames := make(map[string]int)
			unknownCount := collectUnknownCommands(hook.Operations, unknownNames)
			if unknownCount > 0 {
				unknownCommandSummary.Count += unknownCount
				unknownCommandSummary.Files = append(unknownCommandSummary.Files, FileUnknownCommandSummary{
					FilePath: hook.Path, Count: unknownCount, CommandNames: sortedCounts(unknownNames),
				})
			}
		}
		hookSummary.HookNames = sortedSet(hookNames)
		operationSummary.OperationKinds = sortedCounts(operationKinds)
		capabilitySummary.CapabilityNames = sortedCounts(capabilityNames)
		summary.Files.Count += fileSummary.Count
		summary.Hooks.Count += hookSummary.Count
		summary.Operations.Count += operationSummary.Count
		summary.Capabilities.Count += capabilitySummary.Count
		summary.UnknownCommands.Count += unknownCommandSummary.Count
		summary.Files.BySDK = append(summary.Files.BySDK, fileSummary)
		summary.Hooks.BySDK = append(summary.Hooks.BySDK, hookSummary)
		summary.Operations.BySDK = append(summary.Operations.BySDK, operationSummary)
		summary.Capabilities.BySDK = append(summary.Capabilities.BySDK, capabilitySummary)
		summary.UnknownCommands.BySDK = append(summary.UnknownCommands.BySDK, unknownCommandSummary)
	}
	summary.SDKs.SDKNames.Resolved = sortedSet(resolvedSDKNames)
	summary.SDKs.SDKNames.Unresolved = sortedSet(unresolvedSDKNames)
	summary.Diagnostics.DiagnosticCodes = sortedCounts(diagnosticCodes)
	return summary
}

func collectUnknownCommands(operations []analysis.Operation, names map[string]int) int {
	count := 0
	for _, operation := range operations {
		if operation.Kind == analysis.OperationCommand && operation.Command.Resolution == analysis.Resolved && !analysis.IsKnownCommand(operation.Command) {
			count++
			names[operation.Command.Literal]++
		}
		count += collectUnknownCommands(operation.Children, names)
	}
	return count
}

func collectOperationKinds(operations []analysis.Operation, kinds map[string]int) {
	for _, operation := range operations {
		kinds[string(operation.Kind)]++
		collectOperationKinds(operation.Children, kinds)
	}
}

func sortedCounts(values map[string]int) []CountedName {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]CountedName, 0, len(names))
	for _, name := range names {
		items = append(items, CountedName{Name: name, Count: values[name]})
	}
	return items
}

func sortedSet(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return items
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
			content, encoding := encodeContent(file.Content, file.Digest)
			if item.Digest == "" && encoding == "sha3-384" {
				item.Digest = content
			}
			item.Content = &content
			item.ContentEncoding = encoding
		}
		reported = append(reported, item)
	}
	return reported
}

func encodeContent(content []byte, digest string) (string, string) {
	if isTextContent(content) {
		return string(content), "utf-8"
	}
	if digest == "" {
		sum := sha3.Sum384(content)
		digest = "sha3-384:" + hex.EncodeToString(sum[:])
	}
	return digest, "sha3-384"
}

func isTextContent(content []byte) bool {
	if !utf8.Valid(content) {
		return false
	}
	for _, character := range string(content) {
		if unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t' {
			return false
		}
	}
	return true
}
