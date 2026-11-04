# Understanding scan output

This guide explains the default human-readable output from:

```bash
latra scan .
```

The default output is a compact summary intended for terminal use. It does not require `--verbose` or `--format json`.

## Example

The following Workshop project uses one project SDK and one Store SDK.

```text
Input
  Kind: project
  Root: /project/example

Workshops
  development
    Definition: .workshop/development.yaml
    Base: ubuntu@24.04

Summary
  SDKs: 2 (2 resolved, 0 unresolved)
    Resolved: project-base, rust
    Unresolved: -
  Files: 26
    project-base (5): hooks/check-health, hooks/setup-base, hooks/setup-project, sdk.yaml, ... and more files (1)
    rust (21): meta/sdk.yaml, sdk/hooks/check-health, sdk/hooks/setup-base, ... and more files (18)
  Hooks: 5
    project-base (3): check-health, setup-base, setup-project
    rust (2): check-health, setup-base
  Operations: 61
    project-base (47): assignment (10), command-invocation (23), control-flow (9), redirect-write (5)
    rust (14): command-invocation (9), control-flow (1), redirect-read (1), redirect-write (2), source (1)
  Capabilities: 22
    project-base (12): code-execution (1), device-access (5), identity-change (2), network-access (3), system-modification (1)
    rust (10): code-execution (1), destructive-operation (1), dynamic-execution (1), identity-change (2), network-access (2), persistence (1), system-modification (2)
  Unknown Commands: 7
    project-base (7)
      hooks/check-health (5): cd (1), clang (1), llvm-objcopy (1), llvm-objdump (1), qemu-system-riscv64 (1)
      hooks/setup-base (1): cd (1)
      hooks/setup-project (1): make (1)
    rust (0)
  Diagnostics: 0: -
```

## Input

```text
Input
  Kind: project
  Root: /project/example
```

`Kind` identifies what Latra scanned:

- `project` means a Workshop project containing definitions under `.workshop/`.
- `project-sdk` means an individual project SDK directory was scanned directly.

`Root` is the normalized path used as the scan input.

## Workshops

```text
Workshops
  development
    Definition: .workshop/development.yaml
    Base: ubuntu@24.04
```

This section lists each Workshop definition discovered in the project:

- `development` is the Workshop name.
- `Definition` is the project-relative YAML definition.
- `Base` is the Ubuntu base used to resolve compatible Store SDKs.

A project may contain multiple Workshop definitions. Latra combines their SDK declarations while retaining the definition and base information.

## SDKs

```text
SDKs: 2 (2 resolved, 0 unresolved)
  Resolved: project-base, rust
  Unresolved: -
```

This section reports the SDK resolution state:

- `Resolved` SDKs were available for inventory and hook analysis.
- `Unresolved` SDKs could not be fully analyzed. Check `Diagnostics` for the reason.

Use the displayed SDK names as the `<sdk>` argument to `latra hook` and `latra cat`.

For example:

```bash
latra hook project-base setup-base
latra cat rust meta/sdk.yaml
```

When these commands are run from the project root, Latra uses the SDK channel declared in the current project's `.workshop/*.yaml` definitions.

## Files

```text
Files: 26
  project-base (5): hooks/check-health, hooks/setup-base, hooks/setup-project, sdk.yaml, ... and more files (1)
  rust (21): meta/sdk.yaml, sdk/hooks/check-health, sdk/hooks/setup-base, ... and more files (18)
```

`Files` is the total number of inventoried filesystem entries across all SDKs. The count includes regular files, directories, and symbolic links.

Each SDK line contains:

1. the SDK name;
2. the total number of entries for that SDK;
3. its metadata file and standard Workshop hook files;
4. the number of additional entries hidden from the compact output.

The paths shown here can be passed directly to `latra cat` together with the SDK name:

```bash
latra cat project-base sdk.yaml
latra cat rust meta/sdk.yaml
```

Text files are printed as-is. For binary files, Latra prints the detected file type, MIME type, size, and SHA3-384 digest instead of raw binary data.

The compact report intentionally hides non-hook files behind `... and more files`. Use the verbose report to discover every inventoried path, then pass the selected path to `latra cat`:

```bash
latra scan . --verbose
latra cat rust share/example-file
```

## Hooks

```text
Hooks: 5
  project-base (3): check-health, setup-base, setup-project
  rust (2): check-health, setup-base
```

This section lists the standard Workshop hooks found in each SDK. The number in parentheses is the number of detected hooks for that SDK.

Use the SDK name and hook name directly with `latra hook`:

```bash
latra hook project-base check-health
latra hook rust setup-base
```

The command prints the original hook source without executing it.

## Operations

```text
Operations: 61
  project-base (47): assignment (10), command-invocation (23), control-flow (9), redirect-write (5)
```

Operations are normalized shell behaviors derived from the hook AST. The first count is the total number of operation occurrences. Per-SDK and per-kind counts also include repeated occurrences.

Common operation kinds include:

| Operation | Meaning |
| --- | --- |
| `assignment` | Assigns a shell variable. |
| `command-invocation` | Invokes a command or shell builtin. |
| `command-substitution` | Runs a command whose output is substituted into another expression. |
| `control-flow` | Uses a conditional, loop, or other shell control structure. |
| `pipeline` | Connects commands through a pipeline. |
| `redirect-read` | Reads data through shell redirection. |
| `redirect-write` | Writes data through shell redirection. |
| `source` | Loads another shell file into the current shell context. |

Use `latra hook` when an operation count needs to be understood in its original source context.

In a verbose report, each operation has a hook-local ID such as `op-0001`. The hook's `relations` connect those IDs to show containment, execution order, pipelines, substitutions, and conservatively inferred variable flow. Capabilities refer back to their source operation with `operationId`. This graph is primarily intended for machine-readable JSON consumers and contextual finding analysis.

## Capabilities

```text
Capabilities: 22
  project-base (12): code-execution (1), device-access (5), identity-change (2), network-access (3), system-modification (1)
```

Capabilities describe observable or conservatively inferred behavior. Counts represent detected occurrences, not unique capability names.

A capability is not a severity, risk score, policy decision, or claim that an SDK is malicious. See [Categories and capabilities](capabilities.md) for the current definitions.

To inspect the embedded knowledge associated with a capability, use:

```bash
latra db capabilities network-access
```

## Unknown Commands

```text
Unknown Commands: 7
  project-base (7)
    hooks/check-health (5): cd (1), clang (1), llvm-objcopy (1), llvm-objdump (1), qemu-system-riscv64 (1)
    hooks/setup-base (1): cd (1)
    hooks/setup-project (1): make (1)
  rust (0)
```

An unknown command was found in a hook but is not covered by Latra's embedded command database. Unknown does not mean malicious, and it does not mean safe. It means Latra has no command-specific knowledge for that command yet.

The report groups unknown commands by SDK and hook path. To investigate the first group above:

1. take the SDK name `project-base`;
2. take the final component of `hooks/check-health`, which is `check-health`;
3. print the hook source:

```bash
latra hook project-base check-health
```

The names and counts after the hook path show which commands to look for and how many command occurrences Latra detected in that hook.

Use the command database to check whether a command is already registered:

```bash
latra db commands clang
```

If the command is unknown, this query returns an error instead of a database entry.

## Diagnostics

```text
Diagnostics: 0: -
```

Diagnostics report problems encountered while resolving, downloading, extracting, parsing, or analyzing SDKs.

`0: -` means no diagnostics were produced. When diagnostics exist, the summary lists their codes and occurrence counts, and a `Diagnostics` section after the summary provides the affected SDK or hook, severity, phase, and message.

An unresolved SDK or a parsing diagnostic means the report may be incomplete. Review diagnostics before treating the inventory as complete.

## Investigation workflow

For a typical investigation:

1. Run `latra scan .` from the Workshop project root.
2. Check whether every expected SDK is listed under `Resolved`.
3. Review `Diagnostics` and resolve incomplete scans first.
4. Use `Files` paths with `latra cat <sdk> <file>`.
5. Use `Hooks` names with `latra hook <sdk> <hook>`.
6. Follow hook paths under `Unknown Commands` and inspect those hooks first.
7. Use Operations and Capabilities to identify behavior that needs closer source review.
