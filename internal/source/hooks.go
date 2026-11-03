package source

import (
	"fmt"
	"path"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/shell"
)

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
