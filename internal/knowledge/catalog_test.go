package knowledge_test

import (
	"slices"
	"testing"

	"github.com/shizuku198411/Latra/internal/knowledge"
)

func TestDefaultCatalogContainsDirectConditionalAndPathAssociations(t *testing.T) {
	t.Parallel()

	catalog := knowledge.Default()
	if catalog.SchemaVersion != "1" || catalog.DatabaseSchema != "1" || catalog.Summary.Capabilities == 0 || catalog.Summary.Commands == 0 || catalog.Summary.Rules == 0 {
		t.Fatalf("catalog metadata = %#v", catalog)
	}
	assertAssociation(t, catalog, "curl", "network-access", "direct")
	assertAssociation(t, catalog, "curl", "external-send", "conditional")
	assertAssociation(t, catalog, "cp", "project-write", "path-dependent")
	assertAssociation(t, catalog, "sudo", "identity-change", "wrapper")
}

func TestSelectFiltersBothDirections(t *testing.T) {
	t.Parallel()

	catalog := knowledge.Default()
	capabilities, err := knowledge.Select(catalog, knowledge.Query{Entity: "capabilities", Command: "curl", Verbose: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(capabilities.Capabilities, func(item knowledge.Capability) bool { return item.Name == "network-access" }) {
		t.Errorf("curl capabilities = %#v", capabilities.Capabilities)
	}
	commands, err := knowledge.Select(catalog, knowledge.Query{Entity: "commands", Capability: "identity-change", Verbose: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(commands.Commands, func(item knowledge.Command) bool { return item.Name == "sudo" }) {
		t.Errorf("identity commands = %#v", commands.Commands)
	}
}

func assertAssociation(t *testing.T, catalog knowledge.Catalog, command, capability, associationType string) {
	t.Helper()
	for _, item := range catalog.Commands {
		if item.Name != command {
			continue
		}
		for _, association := range item.Associations {
			if association.Capability == capability && association.Type == associationType {
				return
			}
		}
	}
	t.Errorf("association command=%q capability=%q type=%q not found", command, capability, associationType)
}
