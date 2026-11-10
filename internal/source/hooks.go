package source

import (
	"fmt"
	"path"
	"strings"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

const (
	maxIncludeDepth      = 8
	maxIncludedFiles     = 32
	maxIncludedBytes     = 1 << 20
	maxIncludeCandidates = 8
)

type includeState struct {
	files      map[string]sdk.File
	active     map[string]bool
	included   int
	bytes      int64
	incomplete *int
	item       *sdk.SDK
	parser     *shell.Parser
	hook       sdk.HookName
}

// HookParseError reports hooks whose source could not be parsed completely.
type HookParseError struct {
	Count int
}

func (e *HookParseError) Error() string {
	return fmt.Sprintf("%d hook(s) could not be parsed completely", e.Count)
}

// ParseHooks attaches Bash AST results to every resolved hook in an inventory.
func ParseHooks(result *Result, parser *shell.Parser) error {
	incomplete := 0
	for sdkIndex := range result.SDKs {
		item := &result.SDKs[sdkIndex]
		for hookIndex := range item.Hooks {
			hook := &item.Hooks[hookIndex]
			parsed := parser.Parse(hook.Content, path.Join(item.Name, hook.Path))
			hook.Parse = &parsed
			analyzed := analysis.Analyze(string(hook.Name), &parsed)
			state := includeState{files: sdkTextFiles(*item), active: make(map[string]bool), incomplete: &incomplete, item: item, parser: parser, hook: hook.Name}
			state.resolve(analyzed.Operations, 0)
			analysis.Rebuild(&analyzed)
			hook.Analysis = &analyzed
			if parsed.Status != shell.StatusParsed {
				incomplete++
			}
		}
	}
	if incomplete > 0 {
		return &HookParseError{Count: incomplete}
	}
	return nil
}

func sdkTextFiles(item sdk.SDK) map[string]sdk.File {
	files := make(map[string]sdk.File)
	for _, file := range item.Files {
		if file.Type == sdk.FileRegular && !file.Binary && !file.Skipped && file.Digest != "" {
			files[path.Clean(file.Path)] = file
		}
	}
	return files
}

func (state *includeState) resolve(operations []analysis.Operation, depth int) {
	for index := range operations {
		operation := &operations[index]
		if operation.Kind == analysis.OperationSource {
			state.resolveSource(operation, depth)
			if operation.Name == "resolved-sdk-include" {
				continue
			}
		}
		state.resolve(operation.Children, depth)
	}
}

func (state *includeState) resolveSource(operation *analysis.Operation, depth int) {
	includePath, status := sdkIncludePath(operation.Arguments)
	if status != "" {
		state.diagnostic(status, fmt.Sprintf("source at %s is not a statically resolvable SDK-local include", operation.Location.Path))
		return
	}
	file, ok := state.files[includePath]
	if !ok {
		state.diagnostic("include-not-in-inventory", fmt.Sprintf("source %q is not an analyzable SDK inventory file", includePath))
		return
	}
	if depth >= maxIncludeDepth || state.included >= maxIncludedFiles || state.bytes+file.Size > maxIncludedBytes {
		state.diagnostic("include-limit-exceeded", fmt.Sprintf("SDK include limit exceeded while resolving %q", includePath))
		return
	}
	cycleKey := includePath + "\x00" + file.Digest
	if state.active[cycleKey] {
		state.diagnostic("include-cycle", fmt.Sprintf("SDK include cycle detected at %q", includePath))
		return
	}
	state.active[cycleKey] = true
	defer delete(state.active, cycleKey)
	state.included++
	state.bytes += file.Size
	parsed := state.parser.Parse(file.Content, path.Join(state.item.Name, includePath))
	if parsed.Status != shell.StatusParsed {
		*state.incomplete++
		state.diagnostic("include-parse-failed", fmt.Sprintf("SDK include %q could not be parsed completely", includePath))
		return
	}
	included := analysis.Analyze(string(state.hook), &parsed)
	state.resolve(included.Operations, depth+1)
	operation.Name = "resolved-sdk-include"
	operation.Include = &analysis.IncludedSource{Path: includePath, Digest: file.Digest, From: operation.Location}
	operation.Children = append(operation.Children, included.Operations...)
}

func (state *includeState) diagnostic(code, message string) {
	state.item.Diagnostics = append(state.item.Diagnostics, sdk.Diagnostic{Code: code, Severity: sdk.SeverityWarning, Phase: "include", Message: message})
}

func sdkIncludePath(arguments []analysis.Value) (string, string) {
	if len(arguments) == 0 {
		return "", "dynamic-include"
	}
	value := arguments[0]
	var rendered strings.Builder
	sdkVariable := false
	if value.Resolution == analysis.Resolved {
		rendered.WriteString(value.Literal)
	} else {
		if len(value.Candidates) > maxIncludeCandidates {
			return "", "include-candidate-limit"
		}
		for _, part := range value.Parts {
			switch part.Kind {
			case analysis.PartLiteral, analysis.PartQuotedLiteral:
				rendered.WriteString(part.Text)
			case analysis.PartVariableReference:
				if part.Name != "SDK" {
					return "", "dynamic-include"
				}
				sdkVariable = true
			default:
				return "", "dynamic-include"
			}
		}
	}
	raw := rendered.String()
	if sdkVariable {
		raw = strings.TrimPrefix(raw, "/")
	} else if strings.HasPrefix(raw, "/") {
		return "", "external-include"
	}
	cleaned := path.Clean(strings.TrimPrefix(raw, "./"))
	if cleaned == "." || cleaned == "" || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", "external-include"
	}
	return cleaned, ""
}
