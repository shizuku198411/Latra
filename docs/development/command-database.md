# Command database development

Latra's built-in command and capability knowledge is maintained as YAML under [`internal/capabilityconfig/default/`](../../internal/capabilityconfig/default/). These files are embedded in the Latra binary at build time.

This guide explains how to choose and edit the appropriate YAML fragment. It intentionally focuses on database maintenance rather than the Go evaluator implementation.

## Choose the correct fragment

| Change | Fragment |
| --- | --- |
| Register a known command without assigning behavior | `command-definitions.yaml` |
| Add or change a capability definition | `capabilities.yaml` |
| Map a command or command form to capabilities | `commands-core.yaml`, `commands-network.yaml`, `commands-runtime.yaml`, or `commands-system.yaml` |
| Describe file operands read or written by a command | `files.yaml` |
| Describe a command wrapper and continue analyzing its inner command | `wrappers.yaml` |
| Detect inline code accepted by an interpreter option | `interpreters.yaml` |
| Detect an option that sends local data externally | `uploads.yaml` |
| Detect prefixed targets such as `dd of=...` | `targets.yaml` |
| Map shell AST operation kinds to capabilities | `operations.yaml` |
| Classify paths | `path-classes.yaml` |
| Map classified path reads and writes to capabilities | `path-capabilities.yaml` |

Prefer an existing fragment. Add a new fragment only for a stable functional area, and update the expected fragment list in `internal/capabilityconfig/loader_test.go` when doing so.

## General rules

- YAML is decoded strictly. Unknown field names fail validation.
- `schema-version` is currently `"1"` and is declared only in `capabilities.yaml`.
- Rule IDs are globally unique across every fragment.
- IDs, capability names, and categories use lowercase letters and digits separated by `.` or `-`.
- Referenced capabilities and path classes must already be defined somewhere in the merged database.
- Map entries such as command definitions, capability definitions, and path classes cannot be overridden by another fragment.
- Use block-style lists, with one value per line.
- Leave one blank line between rule or definition blocks.

A typical rule ID identifies both the evaluator family and the behavior:

```yaml
id: command.example-network
```

Common prefixes include `command.`, `file.`, `wrapper.`, `interpreter.`, `operation.`, and `path.`.

## Register a known command

Use `command-definitions.yaml` when Latra should recognize a command but its presence alone does not justify a capability.

```yaml
command-definitions:
  examplectl:
    category: sdk-tool
    description: Example SDK management command.
```

This removes `examplectl` from the unknown-command summary without reporting behavior that has not been established.

Current categories are documented in [`docs/capabilities.md`](../capabilities.md). A category is descriptive metadata, not a capability. If a genuinely new category is required, use a valid identifier and update the public category list.

Do not add a broad capability rule only to make a command known. Add a command definition first, then add narrowly supported behavioral rules separately.

## Add a command capability rule

Command rules map a command invocation to one or more capabilities.

```yaml
command-rules:
  - id: command.example-network
    commands:
      - example
    capabilities:
      - network-access
```

Without a `match` block, the rule applies to every invocation of the listed commands. Use this only when the behavior is inherent to the command.

Add a `match` block when behavior depends on a subcommand, option, argument, or endpoint:

```yaml
command-rules:
  - id: command.example-upload
    commands:
      - example
    match:
      subcommands:
        - upload
      any-options:
        - name: --source
          value-styles:
            - next
            - equals
    capabilities:
      - network-access
      - external-send
```

Multiple rules may match the same invocation. This is expected when one command produces several independently supported capabilities.

### Command match fields

| Field | Purpose |
| --- | --- |
| `subcommands` | Match one of the listed first subcommands. |
| `excluded-subcommands` | Reject the listed first subcommands. |
| `subcommand-paths` | Match a multi-token subcommand path. |
| `excluded-subcommand-paths` | Reject a multi-token subcommand path. |
| `any-options` | Require at least one matching option specification. |
| `excluded-options` | Reject a matching option specification. |
| `options-consuming-next` | Mark options whose following token is a value rather than a positional argument. |
| `short-flag-set` | Declare short flags that may be safely expanded from a cluster. |
| `any-short-flags` | Require one of the declared short flags. |
| `excluded-short-flags` | Reject one of the declared short flags. |
| `any-argument-prefixes` | Require an argument beginning with one of the prefixes. |
| `excluded-argument-prefixes` | Reject an argument beginning with one of the prefixes. |
| `argument-condition` | Match arguments by a built-in semantic class. |
| `argument-at` | Match one of several exact values at a zero-based argument position. |
| `source` / `destination` | Match `local` or `remote` transfer endpoints. |
| `remote-operands` | Match `any` or `none` remote operands. |
| `source-classes` / `destination-classes` | Match classified network, executable, or local-data endpoints. |

Fields present in the same `match` block narrow the same rule. Prefer several small rules over one rule that combines unrelated behavior.

### Option specifications

Options are written with a name and one or more accepted value styles:

```yaml
any-options:
  - name: -o
    value-styles:
      - next
      - attached
  - name: --output
    value-styles:
      - next
      - equals
```

Supported value styles are:

| Value style | Example |
| --- | --- |
| `none` | `--verbose` |
| `next` | `--output result.txt` |
| `attached` | `-oresult.txt` |
| `equals` | `--output=result.txt` |

Long options cannot use `attached`. Use `values` to restrict an option to specific values:

```yaml
- name: --mode
  value-styles:
    - next
    - equals
  values:
    - install
    - update
```

### Short flag clusters

Declare the complete set of value-less short flags before matching flags inside a cluster:

```yaml
match:
  short-flag-set:
    - -a
    - -f
    - -v
  any-short-flags:
    - -f
```

Every entry in `any-short-flags` and `excluded-short-flags` must also appear in `short-flag-set`.

### Argument conditions

Use `argument-condition` when literal string matching is insufficient:

```yaml
match:
  subcommands:
    - install
  argument-condition:
    after-subcommand: true
    any-classes:
      - non-local-package-source
```

Supported argument classes are:

- `non-local-artifact`
- `non-local-package-source`
- `build-source`
- `any-resolved`
- `unresolved`
- `network-address`
- `executable-address`
- `local-data-address`
- `none`

`start-position` can skip leading arguments. `after-subcommand: true` begins classification after the matched subcommand.

## Describe file operands

Use `files.yaml` when command operands represent paths. File rules derive path-based capabilities through `path-classes.yaml` and `path-capabilities.yaml`.

```yaml
file-command-rules:
  - id: file.example-copy
    commands:
      - example-copy
    operands:
      - selector: all-but-last
        access: read
      - selector: last
        access: write
```

Supported operand selectors are `all`, `first`, `last`, `all-but-first`, and `all-but-last`. Supported access modes are `read`, `write`, and `read-write`.

List options that consume values so those values are not interpreted as positional paths:

```yaml
options:
  - name: --mode
    value-styles:
      - next
      - equals
```

Use `option-operands` when an option value is itself a path:

```yaml
option-operands:
  - options:
      - name: --target
        value-styles:
          - next
          - equals
    access: write
```

File rules require at least one `operands` or `option-operands` entry. They may also use a normal command `match` block.

## Use specialized rule types

### Wrappers

Use `wrappers.yaml` for commands that alter execution context while wrapping another command:

```yaml
wrapper-rules:
  - id: wrapper.example-identity
    wrappers:
      - example-user
    capabilities:
      - identity-change
```

Do not model a wrapper as a general command rule when Latra should continue analyzing its inner command.

### Interpreters

Use `interpreters.yaml` for options that execute inline source code:

```yaml
interpreters:
  - id: interpreter.example-code
    commands:
      - example-interpreter
    options:
      - name: -e
        value-styles:
          - next
          - attached
    capability: dynamic-execution
```

### Upload options

Use `uploads.yaml` when a specific option sends local content externally:

```yaml
upload-rules:
  - id: command.example-upload-file
    commands:
      - example
    options:
      - name: --upload-file
        value-styles:
          - next
          - equals
    capability: external-send
```

### Prefixed targets

Use `targets.yaml` for arguments whose prefix identifies a target path:

```yaml
target-rules:
  - id: command.example-device-write
    commands:
      - example-write
    prefixes:
      - target=
    path-classes:
      - device
    capabilities:
      - destructive-operation
```

Every referenced path class must exist in `path-classes.yaml`.

### Operation rules

Use `operations.yaml` only when behavior follows from a normalized shell operation rather than a particular executable:

```yaml
operation-rules:
  - id: operation.example
    operation-kinds:
      - source
    capabilities:
      - code-execution
```

`command-resolution` is optional and currently supports only `unresolved`.

## Add a capability or path class

Add a capability definition to `capabilities.yaml` before referencing it:

```yaml
capability-definitions:
  example-behavior:
    description: Performs an observable example behavior.
```

Also update [`docs/capabilities.md`](../capabilities.md) when the public capability set changes.

Path classes accept these match fields:

- `variable-names`
- `exact`
- `prefixes`
- `contains`
- `case-insensitive-contains`
- `suffixes`

Define the class in `path-classes.yaml`:

```yaml
path-classes:
  example:
    prefixes:
      - /var/lib/example/
```

Map path access to capabilities in `path-capabilities.yaml`:

```yaml
path-capabilities:
  example:
    read:
      id: path.example.read
      capability: example-behavior
    write:
      id: path.example.write
      capability: example-behavior
```

A path capability requires at least one of `read` or `write`.

## Validate a change

Run all commands inside the Workshop development environment:

```bash
workshop run dev -- format
workshop run dev -- check
```

Inspect the embedded database through the CLI:

```bash
workshop run dev -- latra db commands example
workshop run dev -- latra db capabilities --command example --verbose
```

Then scan a focused fixture or Workshop project that exercises both matching and non-matching command forms:

```bash
workshop run dev -- latra scan ./testdata/project-sdks/valid-project --verbose
```

When adding behavior, include regression tests for:

- the intended positive match;
- a nearby command form that must not match;
- unknown-command handling when a new known command is introduced;
- each supported option spelling or value style that the rule declares.

Before submitting the change, confirm that rule IDs are unique, capability and path-class references exist, and the CLI database output describes the new entry as intended.
