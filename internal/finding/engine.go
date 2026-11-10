package finding

import (
	"fmt"
	"path/filepath"
	"regexp"
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
				matched.evidence = append(matched.evidence, includeEvidence(matched.hook, matched.evidence)...)
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
	findings = suppressSubsumedFindings(findings)
	sortFindings(findings)
	return findings
}

func includeEvidence(hook *sdk.Hook, evidence []Evidence) []Evidence {
	if hook == nil || hook.Analysis == nil {
		return nil
	}
	parents := make(map[string]string)
	includes := make(map[string]analysis.Relation)
	for _, relation := range hook.Analysis.Relations {
		switch relation.Kind {
		case analysis.RelationContains:
			parents[relation.ToOperationID] = relation.FromOperationID
		case analysis.RelationInclude:
			includes[relation.ToOperationID] = relation
		}
	}
	operations := operationMap(hook.Analysis.Operations)
	seen := make(map[string]bool)
	var additions []Evidence
	for _, item := range evidence {
		current := item.OperationID
		for current != "" {
			if relation, ok := includes[current]; ok {
				key := relation.FromOperationID + "\x00" + relation.Artifact.Literal
				if !seen[key] {
					seen[key] = true
					location := operations[relation.FromOperationID].Location
					additions = append(additions, Evidence{Type: "include", ID: "sdk-local-include", OperationID: relation.FromOperationID,
						FromOperationID: relation.FromOperationID, ToOperationID: relation.ToOperationID,
						Value: relation.Artifact.Literal, NormalizedValue: relation.Digest, Resolution: relation.Resolution, Location: &location})
				}
				break
			}
			current = parents[current]
		}
	}
	return additions
}

func suppressSubsumedFindings(findings []Finding) []Finding {
	secretFlows := make(map[string]bool)
	controlOperations := make(map[string]bool)
	executablePermissionOperations := make(map[string]bool)
	for _, item := range findings {
		if item.ID == "risk.project-secret-exfiltration" {
			secretFlows[findingFlowKey(item)] = true
		}
		if item.ID == "risk.project-control-file-modification" {
			for _, evidence := range item.Evidence {
				controlOperations[item.Scope.SDK+"\x00"+string(item.Scope.Hook)+"\x00"+evidence.OperationID] = true
			}
		}
		if item.ID == "risk.project-executable-created" {
			for _, evidence := range item.Evidence {
				if evidence.ID == "project-executable-permission" {
					executablePermissionOperations[item.Scope.SDK+"\x00"+string(item.Scope.Hook)+"\x00"+evidence.OperationID] = true
				}
			}
		}
	}
	filtered := findings[:0]
	for _, item := range findings {
		if item.ID == "risk.project-data-exfiltration" && secretFlows[findingFlowKey(item)] {
			continue
		}
		if item.ID == "risk.project-file-modification" && findingUsesOperation(item, controlOperations) {
			continue
		}
		if item.ID == "risk.project-permission-modification" && findingUsesOperation(item, executablePermissionOperations) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func findingUsesOperation(item Finding, operations map[string]bool) bool {
	for _, evidence := range item.Evidence {
		key := item.Scope.SDK + "\x00" + string(item.Scope.Hook) + "\x00" + evidence.OperationID
		if operations[key] {
			return true
		}
	}
	return false
}

func findingFlowKey(item Finding) string {
	key := item.Scope.SDK + "\x00" + string(item.Scope.Hook)
	for _, evidence := range item.Evidence {
		value := evidence.NormalizedValue
		if value == "" {
			value = evidence.Value
		}
		key += "\x00" + evidence.OperationID + "\x00" + evidence.FromOperationID + "\x00" + evidence.ToOperationID + "\x00" + value
	}
	return key
}

func evaluate(item sdk.SDK, rule findingconfig.Rule) []match {
	switch rule.Matcher.Type {
	case "capability":
		return matchCapabilities(item, rule)
	case "path-write":
		return matchPathWrites(item, rule)
	case "persistence-write":
		return matchPersistenceWrites(item, rule, false)
	case "profile-environment-write":
		return matchPersistenceWrites(item, rule, true)
	case "repository-persistence":
		return matchRepositoryPersistence(item, rule)
	case "project-in-place-modification":
		return matchProjectInPlaceModification(item, rule)
	case "toolchain-search-order-hijack":
		return matchToolchainSearchOrderHijack(item, rule)
	case "project-control-modification":
		return matchProjectControlModification(item, rule)
	case "project-deletion":
		return matchProjectDeletion(item, rule)
	case "project-executable-created":
		return matchProjectExecutableCreated(item, rule)
	case "project-permission-modification":
		return matchProjectPermissionModification(item, rule)
	case "project-vcs-state-rewrite":
		return matchProjectVCSStateRewrite(item, rule)
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

func matchProjectInPlaceModification(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		operations := operationMap(hook.Analysis.Operations)
		for _, capability := range hook.Analysis.Capabilities {
			if capability.Kind != "project-read" {
				continue
			}
			operation, ok := operations[capability.OperationID]
			if !ok || !isInPlaceEditor(operation) {
				continue
			}
			location := capability.Location
			matches = append(matches, match{hook: hook, key: capability.OperationID + ":" + capabilityTarget(capability), confidence: confidenceFor(capability.Resolution), evidence: []Evidence{{
				Type: "capability", ID: "project-in-place-modification", OperationID: capability.OperationID,
				Value: capability.Target.Literal, NormalizedValue: capabilityTarget(capability),
				Resolution: capability.Resolution, Location: &location,
			}}})
		}
	}
	return matches
}

func isInPlaceEditor(operation analysis.Operation) bool {
	if operation.Kind != analysis.OperationCommand || operation.Command.Resolution != analysis.Resolved {
		return false
	}
	command := filepath.Base(operation.Command.Literal)
	for _, argument := range argumentLiterals(operation.Arguments) {
		switch command {
		case "sed":
			if argument == "-i" || strings.HasPrefix(argument, "-i") && len(argument) > 2 {
				return true
			}
		case "perl":
			if strings.HasPrefix(argument, "-") && strings.Contains(strings.TrimPrefix(argument, "-"), "i") {
				return true
			}
		}
	}
	return false
}

func matchProjectControlModification(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		for _, capability := range hook.Analysis.Capabilities {
			class := analysis.ClassifyPath(capability.NormalizedTarget)
			if class == analysis.PathProjectSensitive && isProjectVCSControlPath(capabilityTarget(capability)) {
				class = analysis.PathProjectVCSControl
			}
			if capability.Kind != "project-write" || !contains(rule.Matcher.PathClasses, string(class)) {
				continue
			}
			location := capability.Location
			matches = append(matches, match{hook: hook, key: capability.OperationID + ":" + capabilityTarget(capability), confidence: confidenceFor(capability.Resolution), evidence: []Evidence{{
				Type: "capability", ID: "project-control-file-modification", OperationID: capability.OperationID,
				Value: capability.Target.Literal, NormalizedValue: capabilityTarget(capability),
				Resolution: capability.Resolution, Location: &location,
			}}})
		}
	}
	return matches
}

func isProjectVCSControlPath(value string) bool {
	cleaned := filepath.ToSlash(filepath.Clean(value))
	return cleaned == "/project/.git/config" || cleaned == "/project/.gitmodules" || strings.HasPrefix(cleaned, "/project/.git/hooks/")
}

func matchProjectDeletion(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			if operation.Kind != analysis.OperationCommand || operation.Command.Resolution != analysis.Resolved {
				continue
			}
			command := filepath.Base(operation.Command.Literal)
			if command != "rm" && command != "unlink" && command != "rmdir" {
				continue
			}
			for _, target := range commandPathOperands(operation.Arguments) {
				normalized := normalizeProjectOperand(target, hook.Name)
				class := analysis.ClassifyPath(normalized)
				if !contains(rule.Matcher.PathClasses, string(class)) {
					continue
				}
				location := operation.Location
				matches = append(matches, match{hook: hook, key: operation.ID + ":" + normalized.Literal, confidence: confidenceFor(normalized.Resolution), evidence: []Evidence{{
					Type: "operation", ID: "project-file-delete", OperationID: operation.ID,
					Value: target.Literal, NormalizedValue: normalized.Literal, Resolution: normalized.Resolution,
					Location: &location,
				}}})
			}
		}
	}
	return matches
}

func matchProjectExecutableCreated(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		writes := make(map[string]analysis.Capability)
		for _, capability := range hook.Analysis.Capabilities {
			if capability.Kind == "project-write" && capability.Resolution == analysis.Resolved {
				writes[filepath.Clean(capabilityTarget(capability))] = capability
			}
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			target, addsExecutable := chmodProjectTarget(operation, hook.Name)
			if !addsExecutable || target.Literal == "" {
				continue
			}
			writer, ok := writes[filepath.Clean(target.Literal)]
			if !ok {
				continue
			}
			writerLocation, chmodLocation := writer.Location, operation.Location
			matches = append(matches, match{hook: hook, key: writer.OperationID + ":" + operation.ID, confidence: "high", evidence: []Evidence{
				{Type: "capability", ID: "project-executable-write", OperationID: writer.OperationID, Value: writer.Target.Literal, NormalizedValue: capabilityTarget(writer), Resolution: writer.Resolution, Location: &writerLocation},
				{Type: "operation", ID: "project-executable-permission", OperationID: operation.ID, Value: target.Literal, NormalizedValue: target.Literal, Resolution: target.Resolution, Location: &chmodLocation},
			}})
		}
	}
	return matches
}

func matchProjectPermissionModification(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			target, _ := chmodProjectTarget(operation, hook.Name)
			if target.Literal == "" {
				continue
			}
			location := operation.Location
			matches = append(matches, match{hook: hook, key: operation.ID + ":" + target.Literal, confidence: confidenceFor(target.Resolution), evidence: []Evidence{{
				Type: "operation", ID: "project-permission-modification", OperationID: operation.ID,
				Value: target.Literal, NormalizedValue: target.Literal, Resolution: target.Resolution, Location: &location,
			}}})
		}
	}
	return matches
}

func matchProjectVCSStateRewrite(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			kind, root, ok := gitProjectMutation(operation, hook.Name)
			if !ok {
				continue
			}
			location := operation.Location
			matches = append(matches, match{hook: hook, key: operation.ID + ":" + kind, confidence: "high", evidence: []Evidence{{
				Type: "operation", ID: "project-vcs-state-rewrite", OperationID: operation.ID,
				Value: strings.Join(argumentLiterals(operation.Arguments), " "), NormalizedValue: root,
				Resolution: analysis.Resolved, Location: &location,
			}}})
		}
	}
	return matches
}

func commandPathOperands(arguments []analysis.Value) []analysis.Value {
	var operands []analysis.Value
	optionsEnded := false
	for _, argument := range arguments {
		if argument.Resolution != analysis.Resolved {
			continue
		}
		if !optionsEnded && argument.Literal == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && strings.HasPrefix(argument.Literal, "-") && argument.Literal != "-" {
			continue
		}
		operands = append(operands, argument)
	}
	return operands
}

func normalizeProjectOperand(value analysis.Value, hook sdk.HookName) analysis.Value {
	if value.Resolution != analysis.Resolved || value.Literal == "" {
		return analysis.Value{Resolution: analysis.Unknown, Literal: value.Literal, Parts: value.Parts}
	}
	normalized := filepath.Clean(value.Literal)
	if !filepath.IsAbs(normalized) && hook == sdk.HookSetupProject {
		normalized = filepath.Join("/project", normalized)
	}
	value.Literal = normalized
	return value
}

func chmodProjectTarget(operation analysis.Operation, hook sdk.HookName) (analysis.Value, bool) {
	if operation.Kind != analysis.OperationCommand || operation.Command.Resolution != analysis.Resolved || filepath.Base(operation.Command.Literal) != "chmod" {
		return analysis.Value{}, false
	}
	arguments := argumentLiterals(operation.Arguments)
	addsExecutable := false
	for _, argument := range arguments {
		if strings.Contains(argument, "+x") || strings.Contains(argument, "+X") {
			addsExecutable = true
		}
	}
	operands := commandPathOperands(operation.Arguments)
	if len(operands) < 2 {
		return analysis.Value{}, addsExecutable
	}
	target := normalizeProjectOperand(operands[len(operands)-1], hook)
	if target.Literal != "/project" && !strings.HasPrefix(target.Literal, "/project/") {
		return analysis.Value{}, addsExecutable
	}
	return target, addsExecutable
}

func gitProjectMutation(operation analysis.Operation, hook sdk.HookName) (string, string, bool) {
	if operation.Kind != analysis.OperationCommand || operation.Command.Resolution != analysis.Resolved || filepath.Base(operation.Command.Literal) != "git" {
		return "", "", false
	}
	arguments := argumentLiterals(operation.Arguments)
	root := ""
	var command []string
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "-C" && index+1 < len(arguments) {
			root = arguments[index+1]
			index++
			continue
		}
		if strings.HasPrefix(argument, "--git-dir=") || strings.HasPrefix(argument, "--work-tree=") {
			continue
		}
		command = append(command, argument)
	}
	if root == "" && hook == sdk.HookSetupProject {
		root = "/project"
	}
	root = filepath.Clean(root)
	if root != "/project" && !strings.HasPrefix(root, "/project/") {
		return "", "", false
	}
	if len(command) == 0 {
		return "", "", false
	}
	switch command[0] {
	case "reset":
		if contains(command[1:], "--hard") {
			return "reset-hard", root, true
		}
	case "clean":
		for _, argument := range command[1:] {
			if argument == "--force" || strings.HasPrefix(argument, "-") && strings.Contains(strings.TrimPrefix(argument, "-"), "f") {
				return "clean-force", root, true
			}
		}
	case "checkout", "restore":
		if contains(command, "--") || len(command) > 1 {
			return command[0] + "-files", root, true
		}
	case "remote":
		if len(command) > 1 && (command[1] == "set-url" || command[1] == "add" || command[1] == "remove" || command[1] == "rename") {
			return "remote-" + command[1], root, true
		}
	case "update-index":
		for _, argument := range command[1:] {
			if strings.HasPrefix(argument, "--skip-worktree") || strings.HasPrefix(argument, "--assume-unchanged") || strings.HasPrefix(argument, "--index-info") {
				return "update-index", root, true
			}
		}
	}
	return "", "", false
}

func matchToolchainSearchOrderHijack(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		projectWrites := make(map[string]analysis.Capability)
		for _, capability := range hook.Analysis.Capabilities {
			if capability.Kind == "project-write" && capability.Resolution == analysis.Resolved {
				projectWrites[capability.OperationID] = capability
			}
		}
		for _, chmod := range flatten(hook.Analysis.Operations) {
			executable := executableProjectTarget(chmod)
			if executable == "" {
				continue
			}
			writer, ok := projectWriteForTarget(projectWrites, executable)
			if !ok {
				continue
			}
			for _, generator := range flatten(hook.Analysis.Operations) {
				prepended := prependedProjectPath(generator)
				if prepended == "" || filepath.Clean(prepended) != filepath.Dir(filepath.Clean(executable)) {
					continue
				}
				configWrite, ok := redirectedProjectWrite(generator.ID, hook.Analysis.Relations, projectWrites)
				if !ok {
					continue
				}
				writerLocation, chmodLocation, generatorLocation := writer.Location, chmod.Location, generator.Location
				matches = append(matches, match{hook: hook, key: writer.OperationID + ":" + chmod.ID + ":" + generator.ID, confidence: "high", evidence: []Evidence{
					{Type: "capability", ID: "toolchain-executable-write", OperationID: writer.OperationID, Value: writer.Target.Literal, NormalizedValue: capabilityTarget(writer), Resolution: writer.Resolution, Location: &writerLocation},
					{Type: "operation", ID: "toolchain-executable-permission", OperationID: chmod.ID, Value: executable, Resolution: chmod.Resolution, Location: &chmodLocation},
					{Type: "operation", ID: "toolchain-path-prepend", OperationID: generator.ID, ToOperationID: configWrite.OperationID, Value: prepended, Resolution: generator.Resolution, Location: &generatorLocation},
				}})
			}
		}
	}
	return matches
}

func executableProjectTarget(operation analysis.Operation) string {
	if operation.Kind != analysis.OperationCommand || filepath.Base(operation.Command.Literal) != "chmod" {
		return ""
	}
	arguments := argumentLiterals(operation.Arguments)
	executable := false
	for _, argument := range arguments {
		if strings.Contains(argument, "+x") {
			executable = true
		}
	}
	if !executable {
		return ""
	}
	for index := len(arguments) - 1; index >= 0; index-- {
		if strings.HasPrefix(arguments[index], "/project/") {
			return filepath.Clean(arguments[index])
		}
	}
	return ""
}

func projectWriteForTarget(writes map[string]analysis.Capability, target string) (analysis.Capability, bool) {
	for _, capability := range writes {
		if filepath.Clean(capabilityTarget(capability)) == filepath.Clean(target) {
			return capability, true
		}
	}
	return analysis.Capability{}, false
}

func prependedProjectPath(operation analysis.Operation) string {
	if operation.Kind != analysis.OperationCommand {
		return ""
	}
	for _, argument := range argumentLiterals(operation.Arguments) {
		value := strings.TrimSpace(argument)
		if index := strings.Index(value, "PATH="); index >= 0 {
			value = strings.Trim(value[index+len("PATH="):], "\"'")
			for _, suffix := range []string{":$PATH", ":${PATH}"} {
				if strings.HasSuffix(value, suffix) {
					candidate := strings.TrimSuffix(value, suffix)
					if strings.HasPrefix(candidate, "/project/") {
						return filepath.Clean(candidate)
					}
				}
			}
		}
	}
	return ""
}

func redirectedProjectWrite(sourceID string, relations []analysis.Relation, writes map[string]analysis.Capability) (analysis.Capability, bool) {
	for _, relation := range relations {
		if relation.Kind == analysis.RelationRedirectFlow && relation.FromOperationID == sourceID {
			capability, ok := writes[relation.ToOperationID]
			return capability, ok
		}
	}
	return analysis.Capability{}, false
}

func matchRepositoryPersistence(item sdk.SDK, rule findingconfig.Rule) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		for _, capability := range hook.Analysis.Capabilities {
			if capability.Kind != "project-write" || !isRepositoryHookFile(capabilityTarget(capability)) {
				continue
			}
			location := capability.Location
			matches = append(matches, match{hook: hook, key: capability.OperationID, confidence: confidenceFor(capability.Resolution), evidence: []Evidence{{
				Type: "capability", ID: "repository-hook-write", OperationID: capability.OperationID,
				Value: capability.Target.Literal, NormalizedValue: capabilityTarget(capability),
				Resolution: capability.Resolution, Location: &location,
			}}})
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			if !isGitHooksPathConfiguration(operation) {
				continue
			}
			location := operation.Location
			matches = append(matches, match{hook: hook, key: operation.ID, confidence: confidenceFor(operation.Resolution), evidence: []Evidence{{
				Type: "operation", ID: "repository-hook-config", OperationID: operation.ID,
				Value: strings.Join(argumentLiterals(operation.Arguments), " "), Resolution: operation.Resolution, Location: &location,
			}}})
		}
	}
	return matches
}

func capabilityTarget(capability analysis.Capability) string {
	if capability.NormalizedTarget.Literal != "" {
		return capability.NormalizedTarget.Literal
	}
	return capability.Target.Literal
}

func isRepositoryHookFile(value string) bool {
	cleaned := filepath.ToSlash(filepath.Clean(value))
	marker := "/.git/hooks/"
	index := strings.Index(cleaned, marker)
	return index >= 0 && strings.Trim(cleaned[index+len(marker):], "/") != ""
}

func isGitHooksPathConfiguration(operation analysis.Operation) bool {
	if operation.Kind != analysis.OperationCommand || operation.Command.Resolution != analysis.Resolved || filepath.Base(operation.Command.Literal) != "git" {
		return false
	}
	arguments := argumentLiterals(operation.Arguments)
	configuration := false
	hooksPathIndex := -1
	for index, argument := range arguments {
		configuration = configuration || argument == "config"
		if contains([]string{"--unset", "--unset-all", "--remove-section"}, argument) {
			return false
		}
		if strings.EqualFold(strings.TrimLeft(argument, "-"), "core.hookspath") {
			hooksPathIndex = index
		}
	}
	return configuration && hooksPathIndex >= 0 && hooksPathIndex+1 < len(arguments) && strings.TrimSpace(arguments[hooksPathIndex+1]) != ""
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
			value := capability.NormalizedTarget.Literal
			if value == "" && len(capability.NormalizedTarget.Candidates) > 0 {
				value = strings.Join(capability.NormalizedTarget.Candidates, ",")
			}
			key := capability.OperationID
			if rule.Kind == string(KindObservation) {
				key = capability.OperationID + ":" + capability.Kind + ":" + value + ":" + locationKey(location)
			}
			matches = append(matches, match{hook: hook, key: key, confidence: confidenceFor(capability.Resolution), evidence: []Evidence{{
				Type: "capability", ID: capability.Kind, OperationID: capability.OperationID,
				Value: capability.Target.Literal, NormalizedValue: value,
				NormalizedCandidates: append([]string{}, capability.NormalizedTarget.Candidates...),
				Resolution:           capability.Resolution, Location: &location,
			}}})
		}
	}
	return matches
}

func locationKey(location shell.Location) string {
	return fmt.Sprintf("%s:%d:%d", location.Path, location.StartLine, location.StartColumn)
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

func matchPersistenceWrites(item sdk.SDK, rule findingconfig.Rule, safeProfileOnly bool) []match {
	var matches []match
	for index := range item.Hooks {
		hook := &item.Hooks[index]
		if !hookMatches(hook, rule) || hook.Analysis == nil {
			continue
		}
		operations := operationMap(hook.Analysis.Operations)
		for _, capability := range hook.Analysis.Capabilities {
			if capability.Kind != "persistence" || capability.RuleID == "path.persistence.read" {
				continue
			}
			safeProfile := isSafeProfileEnvironmentWrite(hook, capability, operations, hook.Analysis.Relations)
			if safeProfile != safeProfileOnly {
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

func isSafeProfileEnvironmentWrite(hook *sdk.Hook, capability analysis.Capability, operations map[string]analysis.Operation, relations []analysis.Relation) bool {
	if hook.Name != sdk.HookSetupBase || capability.Resolution != analysis.Resolved || !isProfileEnvironmentPath(capability.Target.Literal) {
		return false
	}
	writer, ok := operations[capability.OperationID]
	if !ok {
		return false
	}
	switch writer.Kind {
	case analysis.OperationRedirectWrite:
		return hasSafeRedirectSource(writer.ID, operations, relations)
	case analysis.OperationCommand:
		if filepath.Base(writer.Command.Literal) != "tee" {
			return false
		}
		return hasSafePipelineSource(writer.ID, operations, relations)
	default:
		return false
	}
}

func isProfileEnvironmentPath(value string) bool {
	cleaned := filepath.Clean(value)
	return filepath.Dir(cleaned) == "/etc/profile.d" && strings.HasSuffix(filepath.Base(cleaned), ".sh") && filepath.Base(cleaned) != ".sh"
}

func hasSafeRedirectSource(writerID string, operations map[string]analysis.Operation, relations []analysis.Relation) bool {
	current := writerID
	staticHeredoc := ""
	for range 8 {
		predecessor := sequencePredecessor(current, relations)
		if predecessor == "" {
			return false
		}
		operation, ok := operations[predecessor]
		if !ok {
			return false
		}
		if operation.Kind == analysis.OperationRedirectRead || operation.Kind == analysis.OperationRedirectWrite {
			if operation.Name == "heredoc" {
				if len(operation.Arguments) != 1 {
					return false
				}
				content, safe := resolvedProfileTemplate(operation.Arguments[0])
				if !safe || containsExecutablePayload(content) {
					return false
				}
				staticHeredoc = content
			}
			current = predecessor
			continue
		}
		return isSafeProfileContentGenerator(operation, staticHeredoc)
	}
	return false
}

func resolvedProfileTemplate(value analysis.Value) (string, bool) {
	if value.Resolution == analysis.Resolved {
		return value.Literal, true
	}
	if len(value.Parts) == 0 {
		return "", false
	}
	var rendered strings.Builder
	for _, part := range value.Parts {
		switch part.Kind {
		case analysis.PartLiteral, analysis.PartQuotedLiteral:
			rendered.WriteString(part.Text)
		case analysis.PartVariableReference:
			if part.Name != "SDK" {
				return "", false
			}
			rendered.WriteString("${SDK}")
		default:
			return "", false
		}
	}
	return rendered.String(), true
}

func hasSafePipelineSource(writerID string, operations map[string]analysis.Operation, relations []analysis.Relation) bool {
	for _, relation := range relations {
		if relation.Kind != analysis.RelationPipeline || relation.ToOperationID != writerID {
			continue
		}
		return isSafeProfileContentGenerator(operations[relation.FromOperationID], "")
	}
	return false
}

func sequencePredecessor(operationID string, relations []analysis.Relation) string {
	for _, relation := range relations {
		if relation.Kind == analysis.RelationSequence && relation.ToOperationID == operationID {
			return relation.FromOperationID
		}
	}
	return ""
}

func isSafeProfileContentGenerator(operation analysis.Operation, staticHeredoc string) bool {
	if operation.Kind != analysis.OperationCommand || operation.Command.Resolution != analysis.Resolved {
		return false
	}
	switch filepath.Base(operation.Command.Literal) {
	case "echo":
		return resolvedArguments(operation.Arguments) && isEnvironmentProfileText(strings.Join(argumentLiterals(operation.Arguments), " "))
	case "printf":
		if !resolvedArguments(operation.Arguments) || len(operation.Arguments) == 0 {
			return false
		}
		format := operation.Arguments[0].Literal
		if isEnvironmentProfileText(format) {
			return !containsExecutablePayload(strings.Join(argumentLiterals(operation.Arguments[1:]), " "))
		}
		if !strings.Contains(format, "%") || len(operation.Arguments) == 1 {
			return false
		}
		for _, argument := range operation.Arguments[1:] {
			if !isEnvironmentProfileText(argument.Literal) {
				return false
			}
		}
		return true
	case "cat":
		return staticHeredoc != "" && isEnvironmentProfileText(staticHeredoc)
	default:
		return false
	}
}

var environmentAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func isEnvironmentProfileText(value string) bool {
	value = strings.ReplaceAll(value, `\n`, "\n")
	found := false
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		assignment := line
		if strings.HasPrefix(line, "export ") {
			assignment = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		if !environmentAssignment.MatchString(assignment) || containsExecutablePayload(assignment) || strings.ContainsAny(assignment, ";|&`") || strings.Contains(assignment, "$(") {
			return false
		}
		found = true
	}
	return found
}

func resolvedArguments(arguments []analysis.Value) bool {
	for _, argument := range arguments {
		if argument.Resolution != analysis.Resolved {
			return false
		}
	}
	return true
}

func argumentLiterals(arguments []analysis.Value) []string {
	values := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		values = append(values, argument.Literal)
	}
	return values
}

func containsExecutablePayload(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"curl ", "wget ", "bash -c", "sh -c", "| bash", "| sh", "source ", "`curl", "`wget", "$(curl", "$(wget"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
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
		if !hookMatches(hook, rule) || hook.Parse == nil || !contains(rule.Matcher.ParseStatuses, string(hook.Parse.Status)) {
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
		if hasHookSelector(rule.Matcher) {
			var matches []match
			for index := range item.Hooks {
				hook := &item.Hooks[index]
				if !hookMatches(hook, rule) || hook.Analysis == nil || hook.Parse == nil || hook.Parse.Status != shell.StatusParsed || hook.Parse.Recovered || hookHasUnknownCommand(*hook) {
					continue
				}
				if hasCapability(hook.Analysis.Capabilities, rule.Matcher.Capabilities) {
					continue
				}
				matches = append(matches, match{hook: hook, key: string(hook.Name), evidence: []Evidence{{
					Type: "context", ID: "capability-absent", Value: strings.Join(rule.Matcher.Capabilities, ","), Resolution: analysis.Resolved,
				}}})
			}
			return matches
		}
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
		capabilities := capabilityOccurrencesByOperation(hook.Analysis.Capabilities)
		for sourceID, occurrences := range capabilities {
			for _, sourceCapability := range occurrences {
				if sourceCapability.Kind != rule.Matcher.SourceCapability {
					continue
				}
				if rule.Matcher.SameOperation {
					matches = append(matches, sameOperationFlow(hook, rule, sourceCapability, capabilities[sourceID])...)
				}
				for _, reachable := range reachableSinks(sourceID, sourceCapability.Resolution, hook.Analysis.Relations, rule.Matcher.RelationKinds) {
					sink, ok := operations[reachable.id]
					if !ok || !sinkCommandMatches(sink, rule.Matcher.SinkCommands) {
						continue
					}
					sinks := matchingSinkCapabilities(capabilities[reachable.id], rule.Matcher.SinkCapability)
					if rule.Matcher.SinkCapability != "" && len(sinks) == 0 {
						continue
					}
					if rule.Matcher.SinkCapability == "" {
						sinks = []analysis.Capability{{OperationID: reachable.id, Operation: sink.Kind, Resolution: sink.Resolution, Location: sink.Location}}
					}
					for _, sinkCapability := range sinks {
						matches = append(matches, flowMatch(hook, rule, sourceCapability, sinkCapability, reachable.resolution, reachable.path))
					}
				}
			}
		}
	}
	return matches
}

type reachableOperation struct {
	id         string
	resolution analysis.Resolution
	path       []analysis.Relation
}

func reachableSinks(sourceID string, sourceResolution analysis.Resolution, relations []analysis.Relation, flowKinds []string) []reachableOperation {
	best := map[string]analysis.Resolution{sourceID: sourceResolution}
	paths := map[string][]analysis.Relation{sourceID: nil}
	queue := []string{sourceID}
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
			if next == "" {
				continue
			}
			resolution := combinedResolution(best[current], relation.Resolution)
			previous, exists := best[next]
			if exists && resolutionRank(previous) >= resolutionRank(resolution) {
				continue
			}
			best[next] = resolution
			paths[next] = append(append([]analysis.Relation{}, paths[current]...), relation)
			queue = append(queue, next)
		}
	}
	reachable := make([]reachableOperation, 0, len(best)-1)
	for id, resolution := range best {
		if id != sourceID {
			reachable = append(reachable, reachableOperation{id: id, resolution: resolution, path: paths[id]})
		}
	}
	sort.Slice(reachable, func(i, j int) bool { return reachable[i].id < reachable[j].id })
	return reachable
}

func sameOperationFlow(hook *sdk.Hook, rule findingconfig.Rule, source analysis.Capability, capabilities []analysis.Capability) []match {
	var matches []match
	for _, sink := range matchingSinkCapabilities(capabilities, rule.Matcher.SinkCapability) {
		if sink.OperationID == "" || sink.OperationID != source.OperationID || sink.Kind == source.Kind {
			continue
		}
		matches = append(matches, flowMatch(hook, rule, source, sink, combinedResolution(source.Resolution, sink.Resolution), nil))
	}
	return matches
}

func flowMatch(hook *sdk.Hook, rule findingconfig.Rule, source, sink analysis.Capability, relationResolution analysis.Resolution, path []analysis.Relation) match {
	resolution := combinedResolution(combinedResolution(source.Resolution, sink.Resolution), relationResolution)
	fromLocation, toLocation := source.Location, sink.Location
	evidence := []Evidence{
		{Type: "capability", ID: source.Kind, OperationID: source.OperationID, Value: source.Target.Literal,
			NormalizedValue: source.NormalizedTarget.Literal, NormalizedCandidates: append([]string{}, source.NormalizedTarget.Candidates...),
			Resolution: source.Resolution, Location: &fromLocation},
	}
	for _, relation := range path {
		if relation.Kind != analysis.RelationArtifactFlow && relation.Kind != analysis.RelationCollectionFlow {
			continue
		}
		evidence = append(evidence, Evidence{Type: "artifact-flow", ID: string(relation.Kind), OperationID: relation.ToOperationID,
			FromOperationID: relation.FromOperationID, ToOperationID: relation.ToOperationID,
			Value: relation.Artifact.Literal, NormalizedValue: relation.Artifact.Literal, Resolution: relation.Resolution})
	}
	evidence = append(evidence, Evidence{Type: "data-flow", ID: sinkEvidenceID(rule), OperationID: sink.OperationID, FromOperationID: source.OperationID, ToOperationID: sink.OperationID,
		Value: sink.Target.Literal, NormalizedValue: sink.NormalizedTarget.Literal, NormalizedCandidates: append([]string{}, sink.NormalizedTarget.Candidates...),
		Resolution: resolution, Location: &toLocation})
	return match{hook: hook, key: source.OperationID + "->" + sink.OperationID + ":" + capabilityTargetKey(source) + ":" + capabilityTargetKey(sink), confidence: confidenceFor(resolution), evidence: evidence}
}

func capabilityTargetKey(capability analysis.Capability) string {
	if capability.NormalizedTarget.Literal != "" {
		return capability.NormalizedTarget.Literal
	}
	if len(capability.NormalizedTarget.Candidates) > 0 {
		return strings.Join(capability.NormalizedTarget.Candidates, ",")
	}
	return capability.Target.Literal
}

func sinkEvidenceID(rule findingconfig.Rule) string {
	if rule.Matcher.SinkCapability != "" {
		return rule.Matcher.SinkCapability
	}
	return "operation-graph"
}

func sinkCommandMatches(operation analysis.Operation, commands []string) bool {
	return len(commands) == 0 || contains(commands, filepath.Base(operation.Command.Literal))
}

func matchingSinkCapabilities(capabilities []analysis.Capability, kind string) []analysis.Capability {
	if kind == "" {
		return nil
	}
	var matches []analysis.Capability
	for _, capability := range capabilities {
		if capability.Kind == kind {
			matches = append(matches, capability)
		}
	}
	return matches
}

func resolutionRank(resolution analysis.Resolution) int {
	switch resolution {
	case analysis.Resolved:
		return 2
	case analysis.PartiallyResolved:
		return 1
	default:
		return 0
	}
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
	if !hasContextSelector(rule.Matcher) {
		return true
	}
	if hook.Analysis == nil {
		return false
	}
	context := hook.Analysis.Context
	return matchesBool(rule.Matcher.RunAsRoot, context.RunAsRoot) &&
		matchesBool(rule.Matcher.ProjectMounted, context.ProjectMounted) &&
		matchesBool(rule.Matcher.InterfacesActive, context.InterfacesActive) &&
		matchesBool(rule.Matcher.StateMounted, context.StateMounted) &&
		matchesBool(rule.Matcher.ContextDependent, context.ContextDependent)
}

func hasHookSelector(matcher findingconfig.Matcher) bool {
	return len(matcher.HookNames) > 0 || hasContextSelector(matcher)
}

func hasContextSelector(matcher findingconfig.Matcher) bool {
	return matcher.RunAsRoot != nil || matcher.ProjectMounted != nil || matcher.InterfacesActive != nil || matcher.StateMounted != nil || matcher.ContextDependent != nil
}

func matchesBool(expected *bool, actual bool) bool {
	return expected == nil || *expected == actual
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
		if diagnostic.Severity != sdk.SeverityError {
			continue
		}
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

func capabilityOccurrencesByOperation(capabilities []analysis.Capability) map[string][]analysis.Capability {
	result := make(map[string][]analysis.Capability)
	for _, capability := range capabilities {
		result[capability.OperationID] = append(result[capability.OperationID], capability)
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
