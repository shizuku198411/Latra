package analysis

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/capabilityconfig"
)

// PathClass identifies security-relevant filesystem areas.
type PathClass string

const (
	PathSDK                       PathClass = "sdk"
	PathProject                   PathClass = "project"
	PathUserHome                  PathClass = "user-home"
	PathRootHome                  PathClass = "root-home"
	PathState                     PathClass = "state"
	PathRuntime                   PathClass = "runtime"
	PathSystem                    PathClass = "system"
	PathPersistence               PathClass = "persistence"
	PathSensitive                 PathClass = "sensitive"
	PathProjectSensitive          PathClass = "project-sensitive"
	PathUserSensitive             PathClass = "user-sensitive"
	PathSystemSensitive           PathClass = "system-sensitive"
	PathUnknownSensitiveCandidate PathClass = "unknown-sensitive-candidate"
	PathDevice                    PathClass = "device"
	PathTemporary                 PathClass = "temporary"
	PathUnknown                   PathClass = "unknown"
)

// ClassifyPath maps a resolved or partially resolved path to a security area.
func ClassifyPath(value Value) PathClass {
	return classifyPath(value, HookContext{}, capabilityconfig.MustDefault())
}

func classifyPath(value Value, context HookContext, config *capabilityconfig.Config) PathClass {
	for _, part := range value.Parts {
		if part.Kind != PartVariableReference {
			continue
		}
		for _, class := range []PathClass{PathState, PathSDK} {
			if contains(config.PathClasses[string(class)].VariableNames, part.Name) {
				return class
			}
		}
	}
	if value.Literal == "" && len(value.Candidates) > 0 {
		fallback := PathUnknown
		for _, candidate := range value.Candidates {
			class := classifyPath(literalValue(candidate), context, config)
			if isSensitivePathClass(class) || class == PathProject {
				return class
			}
			if fallback == PathUnknown {
				fallback = class
			}
		}
		return fallback
	}
	path := value.Literal
	path = filepath.Clean(path)
	if isProjectPath(path) && matchesPath(strings.TrimPrefix(path, "/project/"), config.PathClasses[string(PathProjectSensitive)]) {
		return PathProjectSensitive
	}
	if !filepath.IsAbs(path) && matchesPath(path, config.PathClasses[string(PathProjectSensitive)]) {
		if context.Name == "setup-project" {
			return PathProjectSensitive
		}
		return PathUnknownSensitiveCandidate
	}
	if matchesPath(path, config.PathClasses[string(PathUserSensitive)]) {
		return PathUserSensitive
	}
	if matchesPath(path, config.PathClasses[string(PathSystemSensitive)]) {
		return PathSystemSensitive
	}
	if value.Resolution != Resolved && matchesKnownFragment(value, config.PathClasses[string(PathUnknownSensitiveCandidate)]) {
		return PathUnknownSensitiveCandidate
	}
	if value.Resolution != Resolved && matchesKnownFragment(value, config.PathClasses[string(PathPersistence)]) {
		return PathPersistence
	}
	if matchesExactOrPrefix(path, config.PathClasses[string(PathProject)]) {
		return PathProject
	}
	if matchesExactOrPrefix(path, config.PathClasses[string(PathRootHome)]) {
		if matchesPath(path, config.PathClasses[string(PathSensitive)]) {
			return PathSensitive
		}
		return PathRootHome
	}
	if matchesExactOrPrefix(path, config.PathClasses[string(PathUserHome)]) {
		if matchesPath(path, config.PathClasses[string(PathSensitive)]) {
			return PathSensitive
		}
		return PathUserHome
	}
	if matchesPath(path, config.PathClasses[string(PathState)]) {
		return PathState
	}
	if matchesPath(path, config.PathClasses[string(PathRuntime)]) {
		return PathRuntime
	}
	if matchesPrefix(path, config.PathClasses[string(PathSDK)].Prefixes) {
		return PathSDK
	}
	if matchesPath(path, config.PathClasses[string(PathDevice)]) {
		return PathDevice
	}
	if matchesPath(path, config.PathClasses[string(PathTemporary)]) {
		return PathTemporary
	}
	if matchesPath(path, config.PathClasses[string(PathPersistence)]) {
		return PathPersistence
	}
	if matchesPath(path, config.PathClasses[string(PathSensitive)]) {
		return PathSensitive
	}
	if matchesPath(path, config.PathClasses[string(PathSystem)]) {
		return PathSystem
	}
	if matchesContains(path, config.PathClasses[string(PathSDK)].Contains) {
		return PathSDK
	}
	return PathUnknown
}

func isSensitivePathClass(class PathClass) bool {
	switch class {
	case PathProjectSensitive, PathUserSensitive, PathSystemSensitive, PathUnknownSensitiveCandidate, PathSensitive:
		return true
	default:
		return false
	}
}

// ExtractCapabilities derives factual behaviors without assigning risk scores.
func ExtractCapabilities(operations []Operation, context HookContext) []Capability {
	return extractCapabilities(operations, context, capabilityconfig.MustDefault())
}

// IsKnownCommand reports whether a resolved command is covered by embedded
// command definitions or behavioral knowledge.
func IsKnownCommand(command Value) bool {
	if command.Resolution != Resolved {
		return false
	}
	name := filepath.Base(command.Literal)
	config := capabilityconfig.MustDefault()
	if _, ok := config.CommandDefinitions[name]; ok {
		return true
	}
	for _, rule := range config.CommandRules {
		if contains(rule.Commands, name) {
			return true
		}
	}
	for _, rule := range config.FileCommandRules {
		if contains(rule.Commands, name) {
			return true
		}
	}
	for _, rule := range config.TargetRules {
		if contains(rule.Commands, name) {
			return true
		}
	}
	for _, rule := range config.Interpreters {
		if contains(rule.Commands, name) {
			return true
		}
	}
	for _, rule := range config.UploadRules {
		if contains(rule.Commands, name) {
			return true
		}
	}
	return false
}

func extractCapabilities(operations []Operation, context HookContext, config *capabilityconfig.Config) []Capability {
	var capabilities []Capability
	for i := range operations {
		operation := &operations[i]
		capabilities = append(capabilities, capabilitiesForOperation(*operation, context, config)...)
		capabilities = append(capabilities, extractCapabilities(operation.Children, context, config)...)
	}
	return capabilities
}

func capabilitiesForOperation(operation Operation, context HookContext, config *capabilityconfig.Config) []Capability {
	var capabilities []Capability
	add := func(kind, ruleID string, target Value, resolution Resolution) {
		capabilities = append(capabilities, Capability{
			Kind: kind, RuleID: ruleID, RuleSource: capabilityconfig.SourceEmbeddedDefault,
			Operation: operation.Kind, OperationID: operation.ID,
			Target: target, Resolution: resolution, Location: operation.Location,
		})
	}
	for _, rule := range config.OperationRules {
		if !contains(rule.OperationKinds, string(operation.Kind)) {
			continue
		}
		if rule.CommandResolution == "unresolved" && operation.Command.Resolution == Resolved {
			continue
		}
		for _, capability := range rule.Capabilities {
			add(capability, rule.ID, operation.Command, operation.Resolution)
		}
	}
	for _, wrapper := range operation.Wrappers {
		for _, rule := range config.WrapperRules {
			if !contains(rule.Wrappers, wrapper) {
				continue
			}
			for _, capability := range rule.Capabilities {
				add(capability, rule.ID, literalValue(wrapper), Resolved)
			}
		}
	}
	if operation.Command.Resolution == Resolved {
		command := filepath.Base(operation.Command.Literal)
		for _, rule := range config.CommandRules {
			matched, matchResolution := matchCommand(operation.Arguments, rule.Match)
			if !contains(rule.Commands, command) || !matched {
				continue
			}
			for _, capability := range rule.Capabilities {
				add(capability, rule.ID, operation.Command, matchResolution)
			}
		}
		for _, rule := range config.FileCommandRules {
			matched, _ := matchCommand(operation.Arguments, rule.Match)
			if !contains(rule.Commands, command) || !matched {
				continue
			}
			operands := positionalArgumentsWithOptions(operation.Arguments, rule.Options)
			for _, operandRule := range rule.Operands {
				for _, operand := range selectOperands(operands, operandRule.Selector) {
					addPathAccessCapabilities(&capabilities, operation, operand, operandRule.Access, context, config)
				}
			}
			for _, optionRule := range rule.OptionOperands {
				for _, operand := range matchAllOptions(operation.Arguments, optionRule.Options) {
					if optionRule.PathMarker != "" {
						var matched bool
						operand, matched = pathAfterMarker(operand, optionRule.PathMarker)
						if !matched {
							continue
						}
					}
					addPathAccessCapabilities(&capabilities, operation, operand, optionRule.Access, context, config)
				}
			}
		}
		for _, rule := range config.TargetRules {
			if !contains(rule.Commands, command) {
				continue
			}
			for _, argument := range operation.Arguments {
				if argument.Resolution != Resolved {
					continue
				}
				for _, prefix := range rule.Prefixes {
					if !strings.HasPrefix(argument.Literal, prefix) {
						continue
					}
					target := literalValue(strings.TrimPrefix(argument.Literal, prefix))
					normalized := normalizePathValue(target, operation.workingDirectory)
					if contains(rule.PathClasses, string(classifyPath(normalized, context, config))) {
						for _, capability := range rule.Capabilities {
							before := len(capabilities)
							add(capability, rule.ID, target, normalized.Resolution)
							if len(capabilities) > before {
								capabilities[before].NormalizedTarget = normalized
							}
						}
					}
				}
			}
		}
		for _, rule := range config.UploadRules {
			if !contains(rule.Commands, command) {
				continue
			}
			if target, matched := matchAnyOption(operation.Arguments, rule.Options); matched {
				add(rule.Capability, rule.ID, target, target.Resolution)
			}
		}
		for _, rule := range config.Interpreters {
			if !contains(rule.Commands, command) {
				continue
			}
			if code, matched := matchAnyOption(operation.Arguments, rule.Options); matched {
				add(rule.Capability, rule.ID, code, code.Resolution)
			}
		}
	}
	for _, input := range operation.Inputs {
		addPathCapability(&capabilities, operation, input.Value, false, context, config)
	}
	for _, output := range operation.Outputs {
		addPathCapability(&capabilities, operation, output.Value, true, context, config)
	}
	return capabilities
}

func pathAfterMarker(value Value, marker string) (Value, bool) {
	if value.Resolution != Resolved {
		return value, false
	}
	index := strings.Index(value.Literal, marker)
	if index < 0 || index+len(marker) == len(value.Literal) {
		return Value{}, false
	}
	return literalValue(value.Literal[index+len(marker):]), true
}

func matchCommand(arguments []Value, match capabilityconfig.CommandMatch) (bool, Resolution) {
	resolution := Resolved
	if len(match.AnyOptions) > 0 {
		if _, matched := matchAnyOption(arguments, match.AnyOptions); !matched {
			return false, resolution
		}
	}
	if len(match.ExcludedOptions) > 0 {
		if _, matched := matchAnyOption(arguments, match.ExcludedOptions); matched {
			return false, resolution
		}
	}
	if len(match.AnyShortFlags) > 0 && !hasShortFlag(arguments, match.ShortFlagSet, match.AnyShortFlags) {
		return false, resolution
	}
	if len(match.ExcludedShortFlags) > 0 && hasShortFlag(arguments, match.ShortFlagSet, match.ExcludedShortFlags) {
		return false, resolution
	}
	positionals := positionalArguments(arguments, match.OptionsConsumingNext)
	subcommand := ""
	usesSubcommand := len(match.Subcommands) > 0 || len(match.ExcludedSubcommands) > 0
	if usesSubcommand && len(positionals) > 0 {
		if positionals[0].Resolution == Resolved {
			subcommand = positionals[0].Literal
		} else {
			resolution = PartiallyResolved
		}
	}
	if len(match.Subcommands) > 0 && resolution == Resolved && !contains(match.Subcommands, subcommand) {
		return false, resolution
	}
	if resolution == Resolved && contains(match.ExcludedSubcommands, subcommand) {
		return false, resolution
	}
	if len(match.SubcommandPaths) > 0 {
		matched, pathResolution := matchSubcommandPaths(positionals, match.SubcommandPaths)
		if !matched {
			return false, resolution
		}
		if pathResolution != Resolved {
			resolution = pathResolution
		}
	}
	if len(match.ExcludedSubcommandPaths) > 0 {
		matched, pathResolution := matchSubcommandPaths(positionals, match.ExcludedSubcommandPaths)
		if matched && pathResolution == Resolved {
			return false, resolution
		}
		if matched {
			resolution = pathResolution
		}
	}
	if len(match.AnyArgumentPrefixes) > 0 && !hasArgumentPrefix(arguments, match.AnyArgumentPrefixes) {
		return false, resolution
	}
	if len(match.ExcludedArgumentPrefixes) > 0 && hasArgumentPrefix(arguments, match.ExcludedArgumentPrefixes) {
		return false, resolution
	}
	if match.ArgumentCondition != nil {
		conditionArguments := positionals
		start := match.ArgumentCondition.StartPosition
		if match.ArgumentCondition.AfterSubcommand && start == 0 {
			start = 1
		}
		if start >= len(conditionArguments) {
			conditionArguments = nil
		} else {
			conditionArguments = conditionArguments[start:]
		}
		matched, conditionResolution := matchArgumentClasses(conditionArguments, match.ArgumentCondition.AnyClasses)
		if !matched {
			return false, resolution
		}
		if conditionResolution != Resolved {
			resolution = conditionResolution
		}
	}
	if match.ArgumentAt != nil {
		if match.ArgumentAt.Position >= len(positionals) {
			return false, resolution
		}
		argument := positionals[match.ArgumentAt.Position]
		if argument.Resolution != Resolved {
			resolution = PartiallyResolved
		} else if !contains(match.ArgumentAt.Values, argument.Literal) {
			return false, resolution
		}
	}
	if len(match.SourceClasses) > 0 {
		if len(positionals) < 2 {
			return false, resolution
		}
		matched, endpointResolution := matchEndpointClasses(positionals[0], match.SourceClasses)
		if !matched {
			return false, resolution
		}
		if endpointResolution != Resolved {
			resolution = endpointResolution
		}
	}
	if len(match.DestinationClasses) > 0 {
		if len(positionals) < 2 {
			return false, resolution
		}
		matched, endpointResolution := matchEndpointClasses(positionals[len(positionals)-1], match.DestinationClasses)
		if !matched {
			return false, resolution
		}
		if endpointResolution != Resolved {
			resolution = endpointResolution
		}
	}
	if match.Source != "" {
		if len(positionals) < 2 {
			return false, resolution
		}
		source := positionals[0]
		if source.Resolution != Resolved {
			resolution = PartiallyResolved
		} else if (match.Source == "remote") != isRemotePath(source.Literal) {
			return false, resolution
		}
	}
	if match.Destination != "" {
		if len(positionals) == 0 {
			return false, resolution
		}
		destination := positionals[len(positionals)-1]
		if destination.Resolution != Resolved {
			return true, PartiallyResolved
		}
		remote := isRemotePath(destination.Literal)
		if (match.Destination == "remote") != remote {
			return false, resolution
		}
	}
	if match.RemoteOperands != "" {
		remote, uncertain := false, false
		for _, operand := range positionals {
			if operand.Resolution != Resolved {
				uncertain = true
				continue
			}
			if isRemotePath(operand.Literal) {
				remote = true
			}
		}
		if match.RemoteOperands == "any" && !remote {
			if uncertain {
				resolution = PartiallyResolved
			} else {
				return false, resolution
			}
		}
		if match.RemoteOperands == "none" && remote {
			return false, resolution
		}
		if uncertain {
			resolution = PartiallyResolved
		}
	}
	return true, resolution
}

func matchEndpointClasses(argument Value, classes []string) (bool, Resolution) {
	if argument.Resolution != Resolved {
		return true, PartiallyResolved
	}
	for _, class := range classes {
		if (class == "network-address" && isNetworkAddress(argument.Literal)) ||
			(class == "executable-address" && isExecutableAddress(argument.Literal)) ||
			(class == "local-data-address" && isLocalDataAddress(argument.Literal)) {
			return true, Resolved
		}
	}
	return false, Resolved
}

func matchSubcommandPaths(arguments []Value, paths [][]string) (bool, Resolution) {
	uncertain := false
	for _, path := range paths {
		if len(arguments) < len(path) {
			continue
		}
		matched := true
		pathUncertain := false
		for index, expected := range path {
			if arguments[index].Resolution != Resolved {
				pathUncertain = true
				continue
			}
			if arguments[index].Literal != expected {
				matched = false
				break
			}
		}
		if matched && !pathUncertain {
			return true, Resolved
		}
		if matched {
			uncertain = true
		}
	}
	if uncertain {
		return true, PartiallyResolved
	}
	return false, Resolved
}

func matchArgumentClasses(arguments []Value, classes []string) (bool, Resolution) {
	if len(arguments) == 0 && contains(classes, "none") {
		return true, Resolved
	}
	uncertain := false
	for _, argument := range arguments {
		if argument.Resolution != Resolved {
			if contains(classes, "unresolved") {
				return true, PartiallyResolved
			}
			uncertain = true
			continue
		}
		for _, class := range classes {
			if (class == "non-local-artifact" && !isLocalArtifact(argument.Literal)) ||
				(class == "non-local-package-source" && !isLocalPackageSource(argument.Literal)) ||
				(class == "build-source" && isBuildSource(argument.Literal)) ||
				(class == "any-resolved" && argument.Literal != "") ||
				(class == "network-address" && isNetworkAddress(argument.Literal)) ||
				(class == "executable-address" && isExecutableAddress(argument.Literal)) ||
				(class == "local-data-address" && isLocalDataAddress(argument.Literal)) {
				return true, Resolved
			}
		}
	}
	if uncertain {
		return true, PartiallyResolved
	}
	return false, Resolved
}

func isNetworkAddress(argument string) bool {
	upper := strings.ToUpper(argument)
	for _, prefix := range []string{"TCP:", "TCP4:", "TCP6:", "UDP:", "UDP4:", "UDP6:", "OPENSSL:", "SOCKS:"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func isExecutableAddress(argument string) bool {
	upper := strings.ToUpper(argument)
	return strings.HasPrefix(upper, "EXEC:") || strings.HasPrefix(upper, "SYSTEM:")
}

func isLocalDataAddress(argument string) bool {
	upper := strings.ToUpper(argument)
	for _, prefix := range []string{"-", "STDIN", "STDOUT", "FILE:", "OPEN:", "CREATE:"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func isLocalArtifact(argument string) bool {
	return argument == "." || argument == ".." || strings.HasPrefix(argument, "/") || strings.HasPrefix(argument, "./") ||
		strings.HasPrefix(argument, "../") || strings.HasPrefix(argument, "file:") ||
		strings.Contains(argument, "/") || strings.HasSuffix(strings.ToLower(argument), ".deb")
}

func isLocalPackageSource(argument string) bool {
	lower := strings.ToLower(argument)
	if argument == "." || argument == ".." || strings.HasPrefix(argument, "/") || strings.HasPrefix(argument, "./") || strings.HasPrefix(argument, "../") || strings.HasPrefix(argument, "file:") {
		return true
	}
	for _, suffix := range []string{".gem", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".whl", ".zip"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func isBuildSource(argument string) bool {
	lower := strings.ToLower(argument)
	if isLocalPackageSource(argument) || strings.HasPrefix(lower, "git+") || strings.HasPrefix(lower, "hg+") || strings.HasPrefix(lower, "svn+") || strings.HasPrefix(lower, "bzr+") {
		return true
	}
	return strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tar.bz2") || strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".zip")
}

func isRemotePath(argument string) bool {
	if strings.HasPrefix(argument, "/") || strings.HasPrefix(argument, "./") || strings.HasPrefix(argument, "../") || strings.HasPrefix(argument, "file:") {
		return false
	}
	return strings.Contains(argument, ":")
}

func positionalArguments(arguments []Value, consumingNext []string) []Value {
	return scanPositionalArguments(arguments, func(argument string) bool { return contains(consumingNext, argument) })
}

func positionalArgumentsWithOptions(arguments []Value, options []capabilityconfig.OptionSpec) []Value {
	return scanPositionalArguments(arguments, func(argument string) bool { return optionConsumesNext(argument, options) })
}

func scanPositionalArguments(arguments []Value, consumesNext func(string) bool) []Value {
	positionals := make([]Value, 0, len(arguments))
	optionsEnded := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !optionsEnded && argument.Resolution == Resolved && argument.Literal == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && argument.Resolution == Resolved && argument.Literal != "-" && strings.HasPrefix(argument.Literal, "-") {
			if consumesNext(argument.Literal) && index+1 < len(arguments) {
				index++
			}
			continue
		}
		positionals = append(positionals, argument)
	}
	return positionals
}

func hasShortFlag(arguments []Value, flagSet, targets []string) bool {
	allowed := make(map[byte]bool, len(flagSet))
	wanted := make(map[byte]bool, len(targets))
	for _, flag := range flagSet {
		allowed[flag[1]] = true
	}
	for _, flag := range targets {
		wanted[flag[1]] = true
	}
	for _, argument := range arguments {
		if argument.Resolution != Resolved {
			continue
		}
		if argument.Literal == "--" {
			break
		}
		if len(argument.Literal) < 2 || argument.Literal[0] != '-' || strings.HasPrefix(argument.Literal, "--") {
			continue
		}
		valid, matched := true, false
		for index := 1; index < len(argument.Literal); index++ {
			if !allowed[argument.Literal[index]] {
				valid = false
				break
			}
			if wanted[argument.Literal[index]] {
				matched = true
			}
		}
		if valid && matched {
			return true
		}
	}
	return false
}

func optionConsumesNext(argument string, options []capabilityconfig.OptionSpec) bool {
	for _, option := range options {
		if argument != option.Name {
			continue
		}
		for _, style := range option.ValueStyles {
			if style == "next" {
				return true
			}
		}
	}
	return false
}

func selectOperands(operands []Value, selector string) []Value {
	switch selector {
	case "all":
		return operands
	case "first":
		if len(operands) > 0 {
			return operands[:1]
		}
	case "last":
		if len(operands) > 0 {
			return operands[len(operands)-1:]
		}
	case "all-but-first":
		if len(operands) > 1 {
			return operands[1:]
		}
	case "all-but-last":
		if len(operands) > 1 {
			return operands[:len(operands)-1]
		}
	}
	return nil
}

func addPathAccessCapabilities(capabilities *[]Capability, operation Operation, target Value, access string, context HookContext, config *capabilityconfig.Config) {
	if access == "read" || access == "read-write" {
		addPathCapability(capabilities, operation, target, false, context, config)
	}
	if access == "write" || access == "read-write" {
		addPathCapability(capabilities, operation, target, true, context, config)
	}
}

func hasArgumentPrefix(arguments []Value, prefixes []string) bool {
	for _, argument := range arguments {
		if argument.Resolution != Resolved {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(argument.Literal, prefix) {
				return true
			}
		}
	}
	return false
}

func matchAnyOption(arguments []Value, options []capabilityconfig.OptionSpec) (Value, bool) {
	matches := matchAllOptions(arguments, options)
	if len(matches) == 0 {
		return Value{}, false
	}
	return matches[0], true
}

func matchAllOptions(arguments []Value, options []capabilityconfig.OptionSpec) []Value {
	var matches []Value
	for index, argument := range arguments {
		if argument.Resolution != Resolved {
			continue
		}
		if argument.Literal == "--" {
			break
		}
		for _, option := range options {
			appendMatch := func(value Value) {
				if len(option.Values) == 0 || (value.Resolution == Resolved && contains(option.Values, value.Literal)) {
					matches = append(matches, value)
				}
			}
			for _, style := range option.ValueStyles {
				switch style {
				case "none":
					if argument.Literal == option.Name {
						appendMatch(argument)
					}
				case "next":
					if argument.Literal == option.Name && index+1 < len(arguments) {
						appendMatch(arguments[index+1])
					}
				case "attached":
					if strings.HasPrefix(argument.Literal, option.Name) && len(argument.Literal) > len(option.Name) {
						appendMatch(literalValue(argument.Literal[len(option.Name):]))
					}
				case "equals":
					prefix := option.Name + "="
					if strings.HasPrefix(argument.Literal, prefix) {
						appendMatch(literalValue(strings.TrimPrefix(argument.Literal, prefix)))
					}
				}
			}
		}
	}
	return matches
}

func addPathCapability(capabilities *[]Capability, operation Operation, target Value, write bool, context HookContext, config *capabilityconfig.Config) {
	normalized := normalizePathValue(target, operation.workingDirectory)
	class := classifyPath(normalized, context, config)
	mapping, ok := config.PathCapabilities[string(class)]
	if !ok {
		return
	}
	rule := mapping.Read
	if write {
		rule = mapping.Write
	}
	if rule == nil {
		return
	}
	for _, capability := range append([]string{rule.Capability}, rule.AdditionalCapabilities...) {
		*capabilities = append(*capabilities, Capability{
			Kind: capability, RuleID: rule.ID,
			RuleSource: capabilityconfig.SourceEmbeddedDefault, Operation: operation.Kind,
			OperationID: operation.ID, Target: target, NormalizedTarget: normalized,
			Resolution: normalized.Resolution, Location: operation.Location,
		})
	}
}

func normalizePathValue(target, workingDirectory Value) Value {
	if target.Literal != "" && filepath.IsAbs(target.Literal) {
		normalized := target
		normalized.Literal = filepath.Clean(target.Literal)
		return normalized
	}
	if target.Literal == "" && len(target.Candidates) > 0 {
		var candidates []string
		for _, candidate := range target.Candidates {
			normalized := normalizePathValue(literalValue(candidate), workingDirectory)
			if normalized.Resolution == Resolved && normalized.Literal != "" && !contains(candidates, normalized.Literal) {
				candidates = append(candidates, normalized.Literal)
			}
			for _, value := range normalized.Candidates {
				if !contains(candidates, value) {
					candidates = append(candidates, value)
				}
			}
		}
		if len(candidates) > 0 && len(candidates) <= candidateLimit {
			sort.Strings(candidates)
			return Value{Resolution: PartiallyResolved, Candidates: candidates}
		}
	}
	if target.Literal != "" {
		switch {
		case workingDirectory.Resolution == Resolved && filepath.IsAbs(workingDirectory.Literal):
			normalized := target
			normalized.Literal = filepath.Clean(filepath.Join(workingDirectory.Literal, target.Literal))
			return normalized
		case workingDirectory.Resolution == PartiallyResolved && len(workingDirectory.Candidates) > 0:
			candidates := make([]string, 0, len(workingDirectory.Candidates))
			for _, directory := range workingDirectory.Candidates {
				if filepath.IsAbs(directory) {
					candidates = append(candidates, filepath.Clean(filepath.Join(directory, target.Literal)))
				}
			}
			if len(candidates) > 0 && len(candidates) <= candidateLimit {
				sort.Strings(candidates)
				return Value{Parts: target.Parts, Resolution: PartiallyResolved, Candidates: candidates}
			}
		}
	}
	return Value{Parts: target.Parts, Resolution: Unknown, Literal: target.Literal, Candidates: target.Candidates}
}

func matchesExactOrPrefix(path string, class capabilityconfig.PathClass) bool {
	return contains(class.Exact, path) || matchesPrefix(path, class.Prefixes)
}

func matchesPath(path string, class capabilityconfig.PathClass) bool {
	if contains(class.ExcludedExact, path) || contains(class.ExcludedBasenames, filepath.Base(path)) {
		return false
	}
	if matchesExactOrPrefix(path, class) || matchesContains(path, class.Contains) || matchesPrefix(path, class.Prefixes) {
		return true
	}
	base := filepath.Base(path)
	if contains(class.Basenames, base) || matchesPrefix(base, class.BasenamePrefixes) {
		return true
	}
	for _, marker := range class.CaseInsensitiveContains {
		if strings.Contains(strings.ToLower(path), strings.ToLower(marker)) {
			return true
		}
	}
	for _, suffix := range class.Suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isProjectPath(path string) bool {
	return path == "/project" || strings.HasPrefix(path, "/project/")
}

func matchesKnownFragment(value Value, class capabilityconfig.PathClass) bool {
	var fragment strings.Builder
	for _, part := range value.Parts {
		if part.Kind == PartLiteral || part.Kind == PartQuotedLiteral || part.Kind == PartGlob {
			fragment.WriteString(part.Text)
		}
	}
	return fragment.Len() > 0 && matchesPath(fragment.String(), class)
}

func matchesPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func matchesContains(path string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}
