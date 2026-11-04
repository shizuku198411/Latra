package analysis_test

import (
	"reflect"
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/shell"
)

func TestAnalyzeBuildsDeterministicOperationGraph(t *testing.T) {
	t.Parallel()

	source := []byte("payload=$(printf remote)\nprintf '%s' \"$payload\" | bash\n")
	parser := shell.NewParser()
	parsed := parser.Parse(source, "fixture/hooks/setup-project")
	if parsed.Status != shell.StatusParsed {
		t.Fatalf("parse status = %q, diagnostics = %#v", parsed.Status, parsed.Diagnostics)
	}

	result := analysis.Analyze("setup-project", &parsed)
	operations := flattenOperations(result.Operations)
	if len(operations) != 6 {
		t.Fatalf("operations = %#v", operations)
	}
	wantIDs := []string{"op-0001", "op-0002", "op-0003", "op-0004", "op-0005", "op-0006"}
	for index, operation := range operations {
		want := wantIDs[index]
		if operation.ID != want {
			t.Errorf("operation[%d].ID = %q, want %q", index, operation.ID, want)
		}
	}
	if operations[1].ParentID != "op-0001" || operations[2].ParentID != "op-0002" {
		t.Errorf("substitution parents = %q, %q", operations[1].ParentID, operations[2].ParentID)
	}
	if operations[4].ParentID != "op-0004" || operations[4].Sequence != 0 || operations[5].Sequence != 1 {
		t.Errorf("pipeline children = %#v, %#v", operations[4], operations[5])
	}

	wantRelations := map[string]bool{
		"contains|op-0001|op-0002|":                true,
		"contains|op-0002|op-0003|":                true,
		"substitution-flow|op-0002|op-0001|stdout": true,
		"sequence|op-0001|op-0004|":                true,
		"contains|op-0004|op-0005|":                true,
		"contains|op-0004|op-0006|":                true,
		"sequence|op-0005|op-0006|":                true,
		"pipeline|op-0005|op-0006|stdout-to-stdin": true,
		"variable-flow|op-0001|op-0005|payload":    true,
	}
	gotRelations := make(map[string]bool)
	for _, relation := range result.Relations {
		key := string(relation.Kind) + "|" + relation.FromOperationID + "|" + relation.ToOperationID + "|" + relation.Name
		gotRelations[key] = true
	}
	for relation := range wantRelations {
		if !gotRelations[relation] {
			t.Errorf("missing relation %q; all = %#v", relation, result.Relations)
		}
	}

	secondParsed := shell.NewParser().Parse(source, "fixture/hooks/setup-project")
	second := analysis.Analyze("setup-project", &secondParsed)
	if !reflect.DeepEqual(result.Operations, second.Operations) || !reflect.DeepEqual(result.Relations, second.Relations) {
		t.Error("operation graph is not deterministic")
	}
}

func TestCapabilitiesReferenceOperationIDs(t *testing.T) {
	t.Parallel()

	parsed := shell.NewParser().Parse([]byte("curl https://example.invalid/tool\n"), "fixture/hooks/setup-project")
	result := analysis.Analyze("setup-project", &parsed)
	if len(result.Operations) != 1 || result.Operations[0].ID == "" {
		t.Fatalf("operations = %#v", result.Operations)
	}
	if len(result.Capabilities) == 0 {
		t.Fatal("expected curl capabilities")
	}
	for _, capability := range result.Capabilities {
		if capability.OperationID != result.Operations[0].ID {
			t.Errorf("capability operation ID = %q, want %q", capability.OperationID, result.Operations[0].ID)
		}
	}
}

func flattenOperations(operations []analysis.Operation) []analysis.Operation {
	var flattened []analysis.Operation
	for _, operation := range operations {
		flattened = append(flattened, operation)
		flattened = append(flattened, flattenOperations(operation.Children)...)
	}
	return flattened
}
