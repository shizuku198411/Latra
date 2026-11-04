package capabilityconfig_test

import (
	"os"
	"testing"

	"github.com/shizuku198411/Latra/internal/capabilityconfig"
)

func TestEmbeddedDefaultIsValid(t *testing.T) {
	t.Parallel()

	config, err := capabilityconfig.Default()
	if err != nil {
		t.Fatal(err)
	}
	if config.SchemaVersion != "1" {
		t.Errorf("schema version = %q", config.SchemaVersion)
	}
	if len(config.CommandRules) == 0 || len(config.OperationRules) == 0 || len(config.PathClasses) == 0 {
		t.Errorf("embedded configuration is incomplete: %#v", config)
	}
	if len(config.CapabilityDefinitions) == 0 || len(config.FileCommandRules) == 0 {
		t.Errorf("embedded capability knowledge is incomplete: %#v", config)
	}
	for _, command := range []string{"workshop", "workshopctl"} {
		definition, ok := config.CommandDefinitions[command]
		if !ok || definition.Category != "workshop-official" {
			t.Errorf("command definition %q = %#v, present = %t", command, definition, ok)
		}
	}
}

func TestEmbeddedDefaultFragmentLayout(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("default")
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{
		"README.md":                true,
		"capabilities.yaml":        true,
		"commands-core.yaml":       true,
		"commands-network.yaml":    true,
		"command-definitions.yaml": true,
		"commands-runtime.yaml":    true,
		"commands-system.yaml":     true,
		"files.yaml":               true,
		"interpreters.yaml":        true,
		"operations.yaml":          true,
		"path-capabilities.yaml":   true,
		"path-classes.yaml":        true,
		"targets.yaml":             true,
		"uploads.yaml":             true,
		"wrappers.yaml":            true,
	}
	if len(entries) != len(expected) {
		t.Fatalf("fragment count = %d, want %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		if entry.IsDir() || !expected[entry.Name()] {
			t.Errorf("unexpected default fragment %q", entry.Name())
		}
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte("schema-version: \"1\"\nunknown-field: true\n"))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestParseRejectsDuplicateRuleIDs(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte(`
schema-version: "1"
command-rules:
  - id: duplicate.rule
    commands: [one]
    capabilities: [network-access]
  - id: duplicate.rule
    commands: [two]
    capabilities: [network-download]
`))
	if err == nil {
		t.Fatal("expected duplicate rule ID error")
	}
}

func TestParseRejectsUnknownPathClassReference(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte(`
schema-version: "1"
path-capabilities:
  missing:
    read: {id: path.missing.read, capability: project-read}
`))
	if err == nil {
		t.Fatal("expected unknown path class error")
	}
}

func TestParseRejectsUndefinedCapability(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte(`
schema-version: "1"
capability-definitions:
  known:
    description: Known behavior.
command-rules:
  - id: command.invalid
    commands: [fixture]
    capabilities: [missing]
`))
	if err == nil {
		t.Fatal("expected undefined capability error")
	}
}

func TestParseRejectsInvalidOperandSelector(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte(`
schema-version: "1"
capability-definitions:
  project-read:
    description: Reads project data.
file-command-rules:
  - id: file.invalid
    commands: [fixture]
    operands:
      - selector: middle
        access: read
`))
	if err == nil {
		t.Fatal("expected invalid operand selector error")
	}
}

func TestParseRejectsInvalidOptionValueStyle(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte(`
schema-version: "1"
capability-definitions:
  external-send:
    description: Sends data externally.
upload-rules:
  - id: command.invalid-upload
    commands: [fixture]
    options:
      - name: --data
        value-styles: [suffix]
    capability: external-send
`))
	if err == nil {
		t.Fatal("expected invalid option value style error")
	}
}

func TestParseRejectsContradictoryCommandMatch(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte(`
schema-version: "1"
capability-definitions:
  network-access:
    description: Uses a network endpoint.
command-rules:
  - id: command.invalid-match
    commands: [fixture]
    match:
      subcommands: [fetch]
      excluded-subcommands: [fetch]
    capabilities: [network-access]
`))
	if err == nil {
		t.Fatal("expected contradictory command match error")
	}
}

func TestParseRejectsShortFlagOutsideDeclaredSet(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte(`
schema-version: "1"
capability-definitions:
  network-download:
    description: Downloads remote content.
command-rules:
  - id: command.invalid-short-flags
    commands: [fixture]
    match:
      short-flag-set: [-s]
      excluded-short-flags: [-I]
    capabilities: [network-download]
`))
	if err == nil {
		t.Fatal("expected undeclared short flag error")
	}
}

func TestParseRejectsUnknownArgumentClass(t *testing.T) {
	t.Parallel()

	_, err := capabilityconfig.Parse([]byte(`
schema-version: "1"
capability-definitions:
  network-access:
    description: Accesses a network endpoint.
command-rules:
  - id: command.invalid-argument-class
    commands: [fixture]
    match:
      argument-condition:
        any-classes: [unknown]
    capabilities: [network-access]
`))
	if err == nil {
		t.Fatal("expected unknown argument class error")
	}
}
