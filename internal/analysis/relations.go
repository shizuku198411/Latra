package analysis

import (
	"fmt"
	"sort"
)

// BuildRelations assigns deterministic per-hook operation IDs and returns the
// structural and basic data-flow graph used by later finding analysis.
func BuildRelations(operations []Operation) []Relation {
	nextID := 1
	assignOperationIDs(operations, "", &nextID)

	collector := relationCollector{seen: make(map[string]bool)}
	collector.structural(operations)
	collector.variableFlows(operations, make(map[string]variableDefinition))
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
	if from == "" || to == "" || from == to {
		return
	}
	key := string(kind) + "\x00" + from + "\x00" + to + "\x00" + name
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.relations = append(c.relations, Relation{
		Kind: kind, FromOperationID: from, ToOperationID: to, Name: name, Resolution: resolution,
	})
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
