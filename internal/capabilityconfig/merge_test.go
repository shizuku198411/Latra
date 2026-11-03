package capabilityconfig

import "testing"

func TestMergeConfigRejectsDuplicateMapEntries(t *testing.T) {
	t.Parallel()

	target := &Config{CapabilityDefinitions: map[string]CapabilityDefinition{
		"network-access": {Description: "first"},
	}}
	fragment := &Config{CapabilityDefinitions: map[string]CapabilityDefinition{
		"network-access": {Description: "second"},
	}}
	if err := mergeConfig(target, fragment, "duplicate.yaml"); err == nil {
		t.Fatal("expected duplicate capability definition error")
	}
}

func TestMergeConfigRejectsDuplicateSchemaVersion(t *testing.T) {
	t.Parallel()

	if err := mergeConfig(&Config{SchemaVersion: "1"}, &Config{SchemaVersion: "1"}, "duplicate.yaml"); err == nil {
		t.Fatal("expected duplicate schema version error")
	}
}
