package analysis

import (
	"path/filepath"
	"sort"
	"strings"
)

const maxAliasResolutionDepth = 8

type pathAlias struct {
	target    string
	creatorID string
}

// ResolvePathAliases applies only aliases created statically by earlier
// operations in the same hook. It never inspects the host filesystem.
func ResolvePathAliases(operations []Operation) []Relation {
	aliases := make(map[string]pathAlias)
	var relations []Relation
	resolveAliasesInOperations(operations, aliases, &relations)
	return relations
}

func resolveAliasesInOperations(operations []Operation, aliases map[string]pathAlias, relations *[]Relation) {
	for index := range operations {
		operation := &operations[index]
		if operation.Reachability == Unreachable {
			continue
		}
		command := filepath.Base(operation.Command.Literal)
		if operation.Kind == OperationCommand && command == "ln" {
			if target, link, ok := symbolicLinkOperands(*operation); ok {
				aliases[link] = pathAlias{target: target, creatorID: operation.ID}
			}
		} else {
			removedAliases := aliasesRemovedByOperation(*operation, aliases)
			resolveOperationAliasPaths(operation, aliases, relations)
			for _, name := range removedAliases {
				delete(aliases, name)
			}
		}

		if len(operation.Children) == 0 {
			continue
		}
		childAliases := cloneAliases(aliases)
		resolveAliasesInOperations(operation.Children, childAliases, relations)
		if operation.Kind == OperationFunctionInvocation {
			for name, alias := range childAliases {
				aliases[name] = alias
			}
		}
	}
}

func symbolicLinkOperands(operation Operation) (string, string, bool) {
	if operation.Command.Resolution != Resolved {
		return "", "", false
	}
	var operands []Value
	symbolic := false
	optionsEnded := false
	for _, argument := range operation.Arguments {
		if argument.Resolution != Resolved {
			return "", "", false
		}
		if !optionsEnded && argument.Literal == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && strings.HasPrefix(argument.Literal, "-") && argument.Literal != "-" {
			flags := strings.TrimPrefix(argument.Literal, "-")
			symbolic = symbolic || argument.Literal == "--symbolic" || !strings.HasPrefix(argument.Literal, "--") && strings.Contains(flags, "s")
			continue
		}
		operands = append(operands, argument)
	}
	if !symbolic || len(operands) != 2 {
		return "", "", false
	}
	linkValue := normalizePathValue(operands[1], operation.workingDirectory)
	if linkValue.Resolution != Resolved || linkValue.Literal == "" {
		return "", "", false
	}
	link := filepath.Clean(linkValue.Literal)
	target := operands[0].Literal
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(link), target)
	}
	return filepath.Clean(target), link, true
}

func resolveOperationAliasPaths(operation *Operation, aliases map[string]pathAlias, relations *[]Relation) {
	for index := range operation.Arguments {
		resolveAliasValue(&operation.Arguments[index], operation, aliases, relations)
	}
	for index := range operation.Inputs {
		resolveAliasValue(&operation.Inputs[index].Value, operation, aliases, relations)
	}
	for index := range operation.Outputs {
		resolveAliasValue(&operation.Outputs[index].Value, operation, aliases, relations)
	}
}

func resolveAliasValue(value *Value, operation *Operation, aliases map[string]pathAlias, relations *[]Relation) {
	if value == nil || value.Resolution != Resolved || value.Literal == "" {
		return
	}
	normalized := normalizePathValue(*value, operation.workingDirectory)
	if normalized.Resolution != Resolved || !filepath.IsAbs(normalized.Literal) {
		return
	}
	original := filepath.Clean(normalized.Literal)
	resolved, creatorID, ok := resolveAliasPath(original, aliases)
	if !ok || resolved == original {
		return
	}
	value.Literal = resolved
	value.Parts = []ValuePart{{Kind: PartLiteral, Text: resolved}}
	provenanceKind := "unknown"
	if resolved == "/project" || strings.HasPrefix(resolved, "/project/") {
		provenanceKind = "project"
	}
	*relations = append(*relations, Relation{
		Kind: RelationAlias, FromOperationID: creatorID, ToOperationID: operation.ID,
		Name: original, Resolution: Resolved, Artifact: literalValue(resolved),
		Provenance: []Provenance{{Kind: provenanceKind, SourceOps: []string{creatorID}, Paths: []Value{literalValue(resolved)}, Resolution: Resolved}},
	})
}

func resolveAliasPath(value string, aliases map[string]pathAlias) (string, string, bool) {
	current := filepath.Clean(value)
	creatorID := ""
	seen := make(map[string]bool)
	for depth := 0; depth < maxAliasResolutionDepth; depth++ {
		name, alias, ok := longestAliasPrefix(current, aliases)
		if !ok {
			return current, creatorID, creatorID != ""
		}
		if seen[name] {
			return value, "", false
		}
		seen[name] = true
		if creatorID == "" {
			creatorID = alias.creatorID
		}
		suffix := strings.TrimPrefix(current, name)
		current = filepath.Clean(alias.target + suffix)
	}
	return value, "", false
}

func longestAliasPrefix(value string, aliases map[string]pathAlias) (string, pathAlias, bool) {
	var names []string
	for name := range aliases {
		if value == name || strings.HasPrefix(value, name+string(filepath.Separator)) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", pathAlias{}, false
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	name := names[0]
	return name, aliases[name], true
}

func aliasesRemovedByOperation(operation Operation, aliases map[string]pathAlias) []string {
	if operation.Kind != OperationCommand || operation.Command.Resolution != Resolved {
		return nil
	}
	command := filepath.Base(operation.Command.Literal)
	if command != "rm" && command != "unlink" && command != "rmdir" {
		return nil
	}
	var removed []string
	for _, argument := range operation.Arguments {
		if argument.Resolution != Resolved || argument.Literal == "" || strings.HasPrefix(argument.Literal, "-") {
			continue
		}
		path := normalizePathValue(argument, operation.workingDirectory)
		name := filepath.Clean(path.Literal)
		if _, ok := aliases[name]; ok {
			removed = append(removed, name)
		}
	}
	return removed
}

func cloneAliases(source map[string]pathAlias) map[string]pathAlias {
	clone := make(map[string]pathAlias, len(source))
	for name, alias := range source {
		clone[name] = alias
	}
	return clone
}
