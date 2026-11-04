package finding

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/findingconfig"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

type match struct {
	hook       *sdk.Hook
	evidence   []Evidence
	confidence string
	key        string
}

func DatabaseInfo() Database {
	config := findingconfig.MustDefault()
	return Database{SchemaVersion: config.SchemaVersion, ContentVersion: config.ContentVersion, Source: findingconfig.SourceEmbeddedDefault}
}

// AnalyzeSDK evaluates the embedded rules without executing SDK content.
func AnalyzeSDK(item sdk.SDK) []Finding {
	config := findingconfig.MustDefault()
	var findings []Finding
	seen := make(map[string]bool)
	for _, rule := range config.Rules {
		for _, matched := range evaluate(item, rule) {
			hookName := sdk.HookName("")
			var context *Context
			if matched.hook != nil {
				hookName = matched.hook.Name
				if matched.hook.Analysis != nil {
					value := contextFrom(matched.hook.Analysis.Context)
					context = &value
				}
			}
			key := rule.ID + "\x00" + item.Name + "\x00" + string(hookName) + "\x00" + matched.key
			if seen[key] || len(matched.evidence) == 0 {
				continue
			}
			seen[key] = true
			confidence := rule.Confidence
			if matched.confidence != "" {
				confidence = lowerConfidence(confidence, matched.confidence)
			}
			findings = append(findings, Finding{
				ID: rule.ID, Kind: Kind(rule.Kind), Family: rule.Family, Title: rule.Title,
				Severity: rule.Severity, Strength: rule.Strength, Confidence: confidence, Weight: rule.Weight,
				Scope: Scope{SDK: item.Name, Hook: hookName}, Context: context, Evidence: matched.evidence,
				Message: rule.Message, Remediation: rule.Remediation,
				ProtectsAgainst: append([]string{}, rule.ProtectsAgainst...), Limitations: append([]string{}, rule.Limitations...),
			})
		}
	}
	sortFindings(findings)
	return findings
}

func evaluate(item sdk.SDK, rule findingconfig.Rule) []match {
	switch rule.Matcher.Type {
	case "capability":
		return matchCapabilities(item, rule)
	case "path-write":
		return matchPathWrites(item, rule)
	case "unknown-command":
		return matchUnknownCommands(item, rule)
	case "parse-status":
		return matchParseStatuses(item, rule)
	case "sdk-unresolved":
		if item.State != sdk.StateResolved && !hasResourceLimitDiagnostic(item) {
			return []match{{evidence: []Evidence{{Type: "metadata", ID: "sdk-state", Value: string(item.State), Resolution: analysis.Unknown}}, key: string(item.State)}}
		}
	case "sdk-diagnostic":
		var matches []match
		for _, diagnostic := range item.Diagnostics {
			if contains(rule.Matcher.DiagnosticCodes, diagnostic.Code) || containsAnySubstring(diagnostic.Message, rule.Matcher.DiagnosticMessageContains) {
				matches = append(matches, match{evidence: []Evidence{{Type: "diagnostic", ID: diagnostic.Code, Value: diagnostic.Message}}, key: diagnostic.Code})
			}
		}
		return matches
	case "all-hooks-parsed":
		if item.State == sdk.StateResolved && len(item.Hooks) > 0 && allHooksParsed(item) {
			return []match{{evidence: []Evidence{{Type: "metadata", ID: "parsed-hooks", Value: fmt.Sprintf("%d", len(item.Hooks)), Resolution: analysis.Resolved}}, key: "sdk"}}
		}
	case "all-commands-known":
		if completeAnalysis(item) && !hasUnknownCommand(item) {
			return []match{{evidence: []Evidence{{Type: "metadata", ID: "known-commands", Value: fmt.Sprintf("%d", commandCount(item)), Resolution: analysis.Resolved}}, key: "sdk"}}
		}
	case "absence-capability":
		return matchAbsence(item, rule)
	case "archive-digest":
		if item.Source == sdk.SourceStore && item.State == sdk.StateResolved && item.Digest != "" {
			return []match{{evidence: []Evidence{{Type: "metadata", ID: "archive-digest", Value: item.Digest, Resolution: analysis.Resolved}}, key: "sdk"}}
		}
	case "complete-file-inventory":
		if item.State == sdk.StateResolved && !hasDiagnostic(item, "resource-limit") {
			return []match{{evidence: []Evidence{{Type: "metadata", ID: "inventoried-files", Value: fmt.Sprintf("%d", len(item.Files)), Resolution: analysis.Resolved}}, key: "sdk"}}
		}
	case "read-only-health-check":
		return matchReadOnlyHealth(item, rule)
	case "relation-flow":
		return matchRelationFlows(item, rule)
	}
	return nil
}

func matchCapabilities(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		for _, capability := range hook.Analysis.Capabilities {
			if !contains(rule.Matcher.Capabilities, capability.Kind) {
				continue
			}
			location := capability.Location
			matches = append(matches, match{hook: hook, key: capability.OperationID, confidence: confidenceFor(capability.Resolution), evidence: []Evidence{{
				Type: "capability", ID: capability.Kind, OperationID: capability.OperationID,
				Value: capability.Target.Literal, Resolution: capability.Resolution, Location: &location,
			}}})
		}
	}
	return matches
}

func matchPathWrites(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			for _, output := range operation.Outputs {
				class := string(analysis.ClassifyPath(output.Value))
				if !contains(rule.Matcher.PathClasses, class) {
					continue
				}
				if class == string(analysis.PathDevice) && isBenignDeviceSink(output.Value) {
					continue
				}
				location := operation.Location
				matches = append(matches, match{hook: hook, key: operation.ID + ":" + class, confidence: confidenceFor(output.Value.Resolution), evidence: []Evidence{{
					Type: "operation", ID: string(operation.Kind), OperationID: operation.ID, Value: output.Value.Literal,
					Resolution: output.Value.Resolution, Location: &location,
				}}})
			}
		}
	}
	return matches
}

func matchUnknownCommands(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			if operation.Kind != analysis.OperationCommand || operation.Command.Resolution != analysis.Resolved || analysis.IsKnownCommand(operation.Command) {
				continue
			}
			location := operation.Location
			matches = append(matches, match{hook: hook, key: operation.ID, evidence: []Evidence{{Type: "operation", ID: "unknown-command", OperationID: operation.ID, Value: operation.Command.Literal, Resolution: analysis.Resolved, Location: &location}}})
		}
	}
	return matches
}

func matchParseStatuses(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if hook.Parse == nil || !contains(rule.Matcher.ParseStatuses, string(hook.Parse.Status)) {
			continue
		}
		location := shell.Location{Path: hook.Path}
		if len(hook.Parse.Diagnostics) > 0 {
			location = hook.Parse.Diagnostics[0].Location
		}
		matches = append(matches, match{hook: hook, key: string(hook.Parse.Status), evidence: []Evidence{{Type: "diagnostic", ID: string(hook.Parse.Status), Value: hook.Path, Resolution: analysis.Unknown, Location: &location}}})
	}
	return matches
}

func matchAbsence(item sdk.SDK, rule findingconfig.Rule) []match {
	if len(rule.Matcher.Capabilities) > 0 {
		if !completeAnalysis(item) || hasUnknownCommand(item) || hasAnyCapability(item, rule.Matcher.Capabilities) {
			return nil
		}
		return []match{{evidence: []Evidence{{Type: "metadata", ID: "analyzed-hooks", Value: fmt.Sprintf("%d", len(item.Hooks)), Resolution: analysis.Resolved}}, key: "sdk"}}
	}
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if hook.Analysis == nil || !hookMatches(hook, rule) {
			continue
		}
		matches = append(matches, match{hook: hook, key: string(hook.Name), evidence: []Evidence{{Type: "context", ID: "run-as-root", Value: fmt.Sprintf("%t", hook.Analysis.Context.RunAsRoot), Resolution: analysis.Resolved}}})
	}
	return matches
}

func isBenignDeviceSink(value analysis.Value) bool {
	if value.Resolution != analysis.Resolved {
		return false
	}
	cleaned := filepath.Clean(value.Literal)
	return cleaned == "/dev/null" || cleaned == "/dev/stdout" || cleaned == "/dev/stderr" || strings.HasPrefix(cleaned, "/dev/fd/")
}

func matchReadOnlyHealth(item sdk.SDK, rule findingconfig.Rule) []match {
	unsafe := []string{"project-write", "state-write", "persistence", "system-modification", "destructive-operation", "privilege-modification"}
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil || hook.Parse == nil || hook.Parse.Status != shell.StatusParsed || hookHasUnknownCommand(*hook) {
			continue
		}
		if hasCapability(hook.Analysis.Capabilities, unsafe) {
			continue
		}
		matches = append(matches, match{hook: hook, key: string(hook.Name), evidence: []Evidence{{Type: "context", ID: "read-only-health-check", Value: hook.Path, Resolution: analysis.Resolved}}})
	}
	return matches
}

func matchRelationFlows(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if hook.Analysis == nil || !hookMatches(hook, rule) {
			continue
		}
		operations := operationMap(hook.Analysis.Operations)
		capabilities := capabilitiesByOperation(hook.Analysis.Capabilities)
		for sourceID, names := range capabilities {
			if !contains(names, rule.Matcher.SourceCapability) {
				continue
			}
			for _, sinkID := range reachableSinks(sourceID, hook.Analysis.Relations, rule.Matcher.RelationKinds) {
				sink, ok := operations[sinkID]
				if !ok || !contains(rule.Matcher.SinkCommands, filepath.Base(sink.Command.Literal)) {
					continue
				}
				source := operations[sourceID]
				fromLocation, toLocation := source.Location, sink.Location
				resolution := combinedResolution(source.Resolution, sink.Resolution)
				matches = append(matches, match{hook: hook, key: sinkID, confidence: confidenceFor(resolution), evidence: []Evidence{
					{Type: "capability", ID: rule.Matcher.SourceCapability, OperationID: sourceID, Resolution: source.Resolution, Location: &fromLocation},
					{Type: "data-flow", ID: "operation-graph", FromOperationID: sourceID, ToOperationID: sinkID, Value: "remote-content", Resolution: resolution, Location: &toLocation},
				}})
			}
		}
	}
	return matches
}

func reachableSinks(sourceID string, relations []analysis.Relation, flowKinds []string) []string {
	seen := map[string]bool{sourceID: true}
	queue := []string{sourceID}
	var reachable []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, relation := range relations {
			next := ""
			switch {
			case relation.Kind == analysis.RelationContains && relation.ToOperationID == current:
				// A child command contributes its result to the containing substitution or assignment.
				next = relation.FromOperationID
			case contains(flowKinds, string(relation.Kind)) && relation.FromOperationID == current:
				next = relation.ToOperationID
			}
			if next == "" || seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
			reachable = append(reachable, next)
		}
	}
	sort.Strings(reachable)
	return reachable
}

func combinedResolution(left, right analysis.Resolution) analysis.Resolution {
	if left == analysis.Unknown || right == analysis.Unknown {
		return analysis.Unknown
	}
	if left == analysis.PartiallyResolved || right == analysis.PartiallyResolved {
		return analysis.PartiallyResolved
	}
	return analysis.Resolved
}

func hookMatches(hook *sdk.Hook, rule findingconfig.Rule) bool {
	if len(rule.Matcher.HookNames) > 0 && !contains(rule.Matcher.HookNames, string(hook.Name)) {
		return false
	}
	if rule.Matcher.RunAsRoot != nil {
		return hook.Analysis != nil && hook.Analysis.Context.RunAsRoot == *rule.Matcher.RunAsRoot
	}
	return true
}

func allHooksParsed(item sdk.SDK) bool {
	for _, hook := range item.Hooks {
		if hook.Parse == nil || hook.Parse.Status != shell.StatusParsed || hook.Parse.Recovered {
			return false
		}
	}
	return true
}

func completeAnalysis(item sdk.SDK) bool {
	return item.State == sdk.StateResolved && len(item.Hooks) > 0 && allHooksParsed(item) && !hasDiagnostic(item, "resource-limit")
}

func hasDiagnostic(item sdk.SDK, code string) bool {
	for _, diagnostic := range item.Diagnostics {
		if diagnostic.Code == code || strings.Contains(diagnostic.Code, code) {
			return true
		}
	}
	return false
}

func hasResourceLimitDiagnostic(item sdk.SDK) bool {
	for _, diagnostic := range item.Diagnostics {
		if diagnostic.Code == "resource-limit" || containsAnySubstring(diagnostic.Message, []string{"resource-limit", "limit exceeded", "SDK archive exceeds"}) {
			return true
		}
	}
	return false
}

func containsAnySubstring(value string, fragments []string) bool {
	for _, fragment := range fragments {
		if fragment != "" && strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func hasUnknownCommand(item sdk.SDK) bool {
	for _, hook := range item.Hooks {
		if hookHasUnknownCommand(hook) {
			return true
		}
	}
	return false
}

func hookHasUnknownCommand(hook sdk.Hook) bool {
	if hook.Analysis == nil {
		return true
	}
	for _, operation := range flatten(hook.Analysis.Operations) {
		if operation.Kind == analysis.OperationCommand && operation.Command.Resolution == analysis.Resolved && !analysis.IsKnownCommand(operation.Command) {
			return true
		}
		if operation.Kind == analysis.OperationCommand && operation.Command.Resolution != analysis.Resolved {
			return true
		}
	}
	return false
}

func commandCount(item sdk.SDK) int {
	count := 0
	for _, hook := range item.Hooks {
		if hook.Analysis == nil {
			continue
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			if operation.Kind == analysis.OperationCommand {
				count++
			}
		}
	}
	return count
}

func hasAnyCapability(item sdk.SDK, names []string) bool {
	for _, hook := range item.Hooks {
		if hook.Analysis != nil && hasCapability(hook.Analysis.Capabilities, names) {
			return true
		}
	}
	return false
}

func hasCapability(capabilities []analysis.Capability, names []string) bool {
	for _, capability := range capabilities {
		if contains(names, capability.Kind) {
			return true
		}
	}
	return false
}

func flatten(operations []analysis.Operation) []analysis.Operation {
	var flattened []analysis.Operation
	for _, operation := range operations {
		flattened = append(flattened, operation)
		flattened = append(flattened, flatten(operation.Children)...)
	}
	return flattened
}

func operationMap(operations []analysis.Operation) map[string]analysis.Operation {
	result := make(map[string]analysis.Operation)
	for _, operation := range flatten(operations) {
		result[operation.ID] = operation
	}
	return result
}

func capabilitiesByOperation(capabilities []analysis.Capability) map[string][]string {
	result := make(map[string][]string)
	for _, capability := range capabilities {
		result[capability.OperationID] = append(result[capability.OperationID], capability.Kind)
	}
	return result
}

func contextFrom(context analysis.HookContext) Context {
	return Context{RunAsRoot: context.RunAsRoot, ProjectMounted: context.ProjectMounted, InterfacesActive: context.InterfacesActive, StateMounted: context.StateMounted}
}

func confidenceFor(resolution analysis.Resolution) string {
	switch resolution {
	case analysis.Resolved:
		return "high"
	case analysis.PartiallyResolved:
		return "medium"
	default:
		return "low"
	}
}

func lowerConfidence(left, right string) string {
	rank := map[string]int{"low": 0, "medium": 1, "high": 2}
	if rank[right] < rank[left] {
		return right
	}
	return left
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Scope.SDK != right.Scope.SDK {
			return left.Scope.SDK < right.Scope.SDK
		}
		if left.Scope.Hook != right.Scope.Hook {
			return left.Scope.Hook < right.Scope.Hook
		}
		leftLine, rightLine := 0, 0
		if len(left.Evidence) > 0 && left.Evidence[0].Location != nil {
			leftLine = left.Evidence[0].Location.StartLine
		}
		if len(right.Evidence) > 0 && right.Evidence[0].Location != nil {
			rightLine = right.Evidence[0].Location.StartLine
		}
		if leftLine != rightLine {
			return leftLine < rightLine
		}
		return left.ID < right.ID
	})
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
