package analysis

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const maxArtifactRelations = 256

// BuildRelations assigns deterministic per-hook operation IDs and returns the
// structural and basic data-flow graph used by later finding analysis.
func BuildRelations(operations []Operation) []Relation {
	nextID := 1
	assignOperationIDs(operations, "", &nextID)

	collector := relationCollector{seen: make(map[string]bool)}
	collector.structural(operations)
	collector.functionCalls(operations)
	collector.redirectFlows(operations)
	collector.variableFlows(operations, make(map[string]variableDefinition))
	collector.artifactFlows(operations)
	sort.SliceStable(collector.relations, func(i, j int) bool {
		left, right := collector.relations[i], collector.relations[j]
		if left.FromOperationID != right.FromOperationID {
			return left.FromOperationID < right.FromOperationID
		}
		if left.ToOperationID != right.ToOperationID {
			return left.ToOperationID < right.ToOperationID
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Name < right.Name
	})
	return collector.relations
}

func (c *relationCollector) functionCalls(operations []Operation) {
	var flat []*Operation
	flattenOperationPointers(operations, &flat)
	declarations := make(map[string]*Operation)
	for _, operation := range flat {
		if operation.Kind == OperationFunctionDeclaration && operation.Name != "" {
			declarations[operation.Name] = operation
		}
	}
	for _, operation := range flat {
		if operation.Kind != OperationFunctionInvocation || operation.Command.Resolution != Resolved {
			continue
		}
		if declaration := declarations[operation.Command.Literal]; declaration != nil {
			c.add(RelationCall, operation.ID, declaration.ID, operation.Command.Literal, operation.Resolution)
		}
		for index := range operation.Arguments {
			for _, child := range operation.Children {
				c.add(RelationArgumentFlow, operation.ID, child.ID, fmt.Sprint(index+1), combineResolution(operation.Arguments[index].Resolution, child.Resolution))
			}
		}
	}
}

func (c *relationCollector) redirectFlows(operations []Operation) {
	for index := range operations {
		operation := &operations[index]
		if operation.Kind == OperationRedirectWrite && operation.statementGroup != 0 {
			if producer := precedingOutputProducer(operations[:index], operation.statementGroup); producer != nil {
				c.add(RelationRedirectFlow, producer.ID, operation.ID, "stdout-to-file",
					combineResolution(producer.Resolution, operation.Resolution))
				if producer.Kind == OperationCommand && filepath.Base(producer.Command.Literal) == "find" {
					artifact := firstResolvedOperand(producer.Arguments)
					artifact = normalizePathValue(artifact, producer.workingDirectory)
					c.addArtifact(RelationCollectionFlow, producer.ID, operation.ID, "enumeration-to-file",
						combineResolution(producer.Resolution, operation.Resolution), artifact,
						[]Provenance{{Kind: "project", SourceOps: []string{producer.ID}, Paths: []Value{artifact}, Resolution: artifact.Resolution}})
				}
			}
		}
		c.redirectFlows(operation.Children)
	}
}

func firstResolvedOperand(arguments []Value) Value {
	for _, argument := range arguments {
		if argument.Resolution == Resolved && argument.Literal != "" && !strings.HasPrefix(argument.Literal, "-") {
			return argument
		}
	}
	return Value{Resolution: Unknown}
}

func precedingOutputProducer(operations []Operation, statementGroup int) *Operation {
	for index := len(operations) - 1; index >= 0; index-- {
		operation := &operations[index]
		if operation.statementGroup != statementGroup {
			break
		}
		switch operation.Kind {
		case OperationCommand, OperationFunctionInvocation, OperationSource, OperationEval:
			return operation
		case OperationPipeline:
			return lastLeaf(operation.Children)
		}
	}
	return nil
}

func assignOperationIDs(operations []Operation, parentID string, nextID *int) {
	for index := range operations {
		operation := &operations[index]
		operation.ID = fmt.Sprintf("op-%04d", *nextID)
		*nextID = *nextID + 1
		operation.ParentID = parentID
		operation.Sequence = index
		assignOperationIDs(operation.Children, operation.ID, nextID)
	}
}

type relationCollector struct {
	relations []Relation
	seen      map[string]bool
}

func (c *relationCollector) add(kind RelationKind, from, to, name string, resolution Resolution) {
	c.addArtifact(kind, from, to, name, resolution, Value{}, nil)
}

func (c *relationCollector) addArtifact(kind RelationKind, from, to, name string, resolution Resolution, artifact Value, provenance []Provenance) {
	if from == "" || to == "" || from == to {
		return
	}
	key := string(kind) + "\x00" + from + "\x00" + to + "\x00" + name + "\x00" + artifact.Literal
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.relations = append(c.relations, Relation{
		Kind: kind, FromOperationID: from, ToOperationID: to, Name: name, Resolution: resolution,
		Artifact: artifact, Provenance: provenance,
	})
}

type artifactAccess struct {
	operation      *Operation
	path           Value
	write          bool
	provenanceKind string
	provenance     []Provenance
}

func (c *relationCollector) artifactFlows(operations []Operation) {
	var flat []*Operation
	flattenOperationPointers(operations, &flat)
	writers := make(map[string]artifactAccess)
	origins := make(map[string][]Provenance)
	for _, relation := range c.relations {
		if relation.Kind == RelationCollectionFlow && len(relation.Provenance) > 0 {
			origins[relation.ToOperationID] = append([]Provenance{}, relation.Provenance...)
		}
	}
	edges := 0
	for _, operation := range flat {
		for _, deleted := range operationDeletedArtifacts(operation) {
			delete(writers, artifactPathKey(deleted))
		}
		for _, access := range operationArtifactAccesses(operation) {
			key := artifactPathKey(access.path)
			if key == "" {
				continue
			}
			if access.write {
				access.provenance = append([]Provenance{}, origins[operation.ID]...)
				if len(access.provenance) == 0 {
					access.provenance = []Provenance{{Kind: access.provenanceKind, SourceOps: []string{operation.ID}, Paths: []Value{access.path}, Resolution: access.path.Resolution}}
				}
				writers[key] = access
				continue
			}
			writer, ok := writers[key]
			if !ok || edges >= maxArtifactRelations {
				continue
			}
			resolution := combineResolution(writer.path.Resolution, access.path.Resolution)
			provenance := append([]Provenance{}, writer.provenance...)
			for index := range provenance {
				provenance[index].Resolution = combineResolution(provenance[index].Resolution, resolution)
			}
			c.addArtifact(RelationArtifactFlow, writer.operation.ID, operation.ID, "file-artifact", resolution, access.path, provenance)
			origins[operation.ID] = mergeProvenance(origins[operation.ID], provenance)
			edges++
		}
	}
}

func operationDeletedArtifacts(operation *Operation) []Value {
	if operation.Kind != OperationCommand || operation.Command.Resolution != Resolved {
		return nil
	}
	command := filepath.Base(operation.Command.Literal)
	if command != "rm" && command != "unlink" && command != "rmdir" {
		return nil
	}
	var deleted []Value
	for _, argument := range operation.Arguments {
		if argument.Resolution == Resolved && argument.Literal != "" && !strings.HasPrefix(argument.Literal, "-") {
			deleted = append(deleted, normalizePathValue(argument, operation.workingDirectory))
		}
	}
	return deleted
}

func flattenOperationPointers(operations []Operation, flat *[]*Operation) {
	for index := range operations {
		operation := &operations[index]
		*flat = append(*flat, operation)
		flattenOperationPointers(operation.Children, flat)
	}
}

func operationArtifactAccesses(operation *Operation) []artifactAccess {
	var accesses []artifactAccess
	add := func(value Value, write bool, provenance string) {
		value = normalizePathValue(value, operation.workingDirectory)
		if value.Resolution == Unknown || value.Literal == "" {
			return
		}
		accesses = append(accesses, artifactAccess{operation: operation, path: value, write: write, provenanceKind: provenance})
	}
	for _, input := range operation.Inputs {
		if input.Kind == "file-read" {
			add(input.Value, false, "unknown")
		}
	}
	for _, output := range operation.Outputs {
		if output.Kind == "file-write" {
			add(output.Value, true, "generated")
		}
	}
	if operation.Kind != OperationCommand || operation.Command.Resolution != Resolved {
		return accesses
	}
	command := filepath.Base(operation.Command.Literal)
	arguments := resolvedArgumentLiterals(operation.Arguments)
	switch command {
	case "tar":
		if value := optionPath(arguments, "-T", "--files-from"); value != "" {
			add(literalValue(value), false, "generated")
		}
		if tarCreatesArchive(arguments) {
			if value := tarFilePath(arguments); value != "" && value != "-" {
				add(literalValue(value), true, "generated")
			}
		}
	case "zip":
		operands := nonOptionArguments(arguments)
		if len(operands) > 0 {
			add(literalValue(operands[0]), true, "generated")
			for _, operand := range operands[1:] {
				add(literalValue(operand), false, "unknown")
			}
		}
	case "cp", "install", "mv", "rsync":
		operands := nonOptionArguments(arguments)
		if len(operands) > 1 {
			for _, operand := range operands[:len(operands)-1] {
				add(literalValue(operand), false, "unknown")
			}
			add(literalValue(operands[len(operands)-1]), true, "generated")
		}
	case "curl":
		for _, option := range []string{"-T", "--upload-file"} {
			if value := optionPath(arguments, option, option); value != "" && value != "-" {
				add(literalValue(strings.TrimPrefix(value, "@")), false, "unknown")
			}
		}
		for _, argument := range arguments {
			if strings.HasPrefix(argument, "@") && len(argument) > 1 {
				add(literalValue(strings.TrimPrefix(argument, "@")), false, "unknown")
			}
		}
	}
	return accesses
}

func tarFilePath(arguments []string) string {
	if value := optionPath(arguments, "-f", "--file"); value != "" {
		return value
	}
	for index, argument := range arguments {
		if !strings.HasPrefix(argument, "-") || strings.HasPrefix(argument, "--") {
			continue
		}
		flagIndex := strings.Index(strings.TrimPrefix(argument, "-"), "f")
		if flagIndex < 0 {
			continue
		}
		flags := strings.TrimPrefix(argument, "-")
		if flagIndex+1 < len(flags) {
			return flags[flagIndex+1:]
		}
		if index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func mergeProvenance(existing, additions []Provenance) []Provenance {
	result := append([]Provenance{}, existing...)
	seen := make(map[string]bool)
	for _, provenance := range result {
		seen[provenance.Kind+"\x00"+strings.Join(provenance.SourceOps, ",")] = true
	}
	for _, provenance := range additions {
		key := provenance.Kind + "\x00" + strings.Join(provenance.SourceOps, ",")
		if !seen[key] {
			seen[key] = true
			result = append(result, provenance)
		}
	}
	return result
}

func resolvedArgumentLiterals(values []Value) []string {
	var result []string
	for _, value := range values {
		if value.Resolution == Resolved {
			result = append(result, value.Literal)
		}
	}
	return result
}

func optionPath(arguments []string, short, long string) string {
	for index, argument := range arguments {
		if argument == short || argument == long {
			if index+1 < len(arguments) {
				return arguments[index+1]
			}
		}
		if strings.HasPrefix(argument, long+"=") {
			return strings.TrimPrefix(argument, long+"=")
		}
		if len(short) == 2 && strings.HasPrefix(argument, short) && len(argument) > 2 {
			return strings.TrimPrefix(argument, short)
		}
	}
	return ""
}

func tarCreatesArchive(arguments []string) bool {
	for _, argument := range arguments {
		if argument == "--create" || strings.HasPrefix(argument, "-") && !strings.HasPrefix(argument, "--") && strings.Contains(argument[1:], "c") {
			return true
		}
	}
	return false
}

func nonOptionArguments(arguments []string) []string {
	var result []string
	for _, argument := range arguments {
		if !strings.HasPrefix(argument, "-") {
			result = append(result, argument)
		}
	}
	return result
}

func artifactPathKey(value Value) string {
	if value.Resolution != Resolved || value.Literal == "" || value.Literal == "-" {
		return ""
	}
	return filepath.Clean(value.Literal)
}

func (c *relationCollector) structural(operations []Operation) {
	for index := range operations {
		operation := &operations[index]
		if index > 0 {
			c.add(RelationSequence, operations[index-1].ID, operation.ID, "", combineResolution(operations[index-1].Resolution, operation.Resolution))
		}
		for childIndex := range operation.Children {
			child := &operation.Children[childIndex]
			c.add(RelationContains, operation.ID, child.ID, "", child.Resolution)
			if operation.Kind == OperationSource && operation.Include != nil {
				c.addInclude(operation, child)
			}
			if child.Kind == OperationCommandSubstitution || child.Kind == OperationProcessSubstitution {
				c.add(RelationSubstitutionFlow, child.ID, operation.ID, "stdout", child.Resolution)
			}
		}
		if operation.Kind == OperationPipeline && operation.pipelineBoundary > 0 && operation.pipelineBoundary < len(operation.Children) {
			from := lastLeaf(operation.Children[:operation.pipelineBoundary])
			to := firstLeaf(operation.Children[operation.pipelineBoundary:])
			if from != nil && to != nil {
				c.add(RelationPipeline, from.ID, to.ID, "stdout-to-stdin", combineResolution(from.Resolution, to.Resolution))
			}
		}
		c.structural(operation.Children)
	}
}

func (c *relationCollector) addInclude(source, child *Operation) {
	artifact := literalValue(source.Include.Path)
	key := string(RelationInclude) + "\x00" + source.ID + "\x00" + child.ID + "\x00" + source.Include.Path
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.relations = append(c.relations, Relation{
		Kind: RelationInclude, FromOperationID: source.ID, ToOperationID: child.ID, Name: "sdk-local-source",
		Resolution: Resolved, Artifact: artifact, Digest: source.Include.Digest,
		Provenance: []Provenance{{Kind: "sdk", SourceOps: []string{source.ID}, Paths: []Value{artifact}, Resolution: Resolved}},
	})
}

func firstLeaf(operations []Operation) *Operation {
	if len(operations) == 0 {
		return nil
	}
	operation := &operations[0]
	if len(operation.Children) > 0 {
		if child := firstLeaf(operation.Children); child != nil {
			return child
		}
	}
	return operation
}

func lastLeaf(operations []Operation) *Operation {
	if len(operations) == 0 {
		return nil
	}
	operation := &operations[len(operations)-1]
	if len(operation.Children) > 0 {
		if child := lastLeaf(operation.Children); child != nil {
			return child
		}
	}
	return operation
}

type variableDefinition struct {
	operationID string
	resolution  Resolution
}

func (c *relationCollector) variableFlows(operations []Operation, definitions map[string]variableDefinition) {
	for index := range operations {
		operation := &operations[index]
		for _, name := range operationVariableReferences(*operation) {
			if definition, ok := definitions[name]; ok {
				c.add(RelationVariableFlow, definition.operationID, operation.ID, name,
					combineResolution(definition.resolution, operation.Resolution))
			}
		}

		if operation.Kind == OperationAssignment && operation.Name != "" {
			definitions[operation.Name] = variableDefinition{operationID: operation.ID, resolution: operation.Resolution}
		}

		if len(operation.Children) == 0 {
			continue
		}
		childDefinitions := cloneVariableDefinitions(definitions)
		c.variableFlows(operation.Children, childDefinitions)
	}
}

func operationVariableReferences(operation Operation) []string {
	seen := make(map[string]bool)
	var names []string
	collect := func(value Value) {
		for _, part := range value.Parts {
			if part.Kind != PartVariableReference || part.Name == "" || seen[part.Name] {
				continue
			}
			seen[part.Name] = true
			names = append(names, part.Name)
		}
	}
	collect(operation.Command)
	for _, argument := range operation.Arguments {
		collect(argument)
	}
	for _, input := range operation.Inputs {
		collect(input.Value)
	}
	for _, output := range operation.Outputs {
		collect(output.Value)
	}
	sort.Strings(names)
	return names
}

func cloneVariableDefinitions(definitions map[string]variableDefinition) map[string]variableDefinition {
	clone := make(map[string]variableDefinition, len(definitions))
	for name, definition := range definitions {
		clone[name] = definition
	}
	return clone
}

func combineResolution(left, right Resolution) Resolution {
	if left == Unknown || right == Unknown {
		return Unknown
	}
	if left == PartiallyResolved || right == PartiallyResolved {
		return PartiallyResolved
	}
	return Resolved
}
