# Capability model and definitions

Latra classifies known commands by category and reports observable or conservatively inferred SDK behavior as capabilities. The embedded capability database is the semantic boundary between shell analysis and finding evaluation.

A capability describes detected behavior. It is not a risk score, severity, policy decision, or claim of malicious intent. Finding rules consume capabilities together with paths, operation relations, and Workshop lifecycle context.

## Source of truth

Capability definitions and the rules that emit them are YAML fragments under [`internal/capabilityconfig/default/`](../../../internal/capabilityconfig/default/). The loader strictly decodes, merges, validates, and embeds these fragments into the Latra binary. Runtime scans do not read mutable capability files from the host.

The database schema version is declared once in `capabilities.yaml`. Duplicate definitions, duplicate rule IDs, unknown YAML fields, undefined capabilities, and undefined path classes fail validation.

## Semantic layers

| Layer | Purpose | Scored |
| --- | --- | --- |
| Command category | Describes what a registered command generally is. | No |
| Capability | Records behavior supported by command, operation, file, or path evidence. | No |
| Path class | Classifies the security-relevant meaning of a resolved path. | No |
| Finding | Interprets evidence and context as risk, assurance, or observation. | Yes, except observations |

## Command categories

| Category | Description |
| --- | --- |
| `shell-builtin` | Commands implemented by the shell, such as output, condition, and shell-state operations. |
| `system-utility` | General operating-system and distribution utilities. |
| `sdk-tool` | Commands supplied by or closely associated with an SDK toolchain. |
| `workshop-official` | Official Canonical Workshop commands. |

Use `latra db commands` to list the currently registered commands and `latra db commands <command>` to inspect an individual command.

Categories are attached only to command definitions. They do not emit
capabilities and do not affect findings or scores.

## Capabilities

| Capability | Description |
| --- | --- |
| `network-access` | Uses a network protocol to communicate with an endpoint, including loopback, containers, virtual machines, and the host. Unix-domain sockets are excluded. |
| `network-download` | Retrieves or consumes response content, files, repositories, or packages from a remote endpoint. |
| `external-send` | Sends local or generated data to a remote endpoint. |
| `code-execution` | Executes a shell, interpreter, function, or dynamically supplied program. |
| `dynamic-execution` | Evaluates code whose complete behavior cannot be determined statically. |
| `privilege-modification` | Changes permissions, ownership, or file capabilities. |
| `destructive-operation` | Deletes or overwrites data, filesystems, devices, or broad path sets. |
| `project-read` | Reads data from the mounted Workshop project. |
| `project-write` | Writes data to the mounted Workshop project. |
| `credential-read` | Reads a path likely to contain credentials or other sensitive data. |
| `sensitive-file-read` | Reads a file classified as potentially containing secrets or other sensitive data. |
| `project-sensitive-file-read` | Reads a sensitive file from the mounted Workshop project. |
| `state-read` | Reads persisted Workshop SDK state. |
| `state-write` | Writes persisted Workshop SDK state. |
| `device-access` | Reads from or writes to a device or kernel interface path. |
| `persistence` | Changes or writes a location used to retain behavior across sessions or boots. |
| `system-modification` | Changes system packages, services, or protected system paths. |
| `environment-modification` | Installs, removes, or changes packages or tools in a language or user environment. |
| `identity-change` | Executes a command with a different user or group identity. |
| `execution-context-change` | Executes a command with a changed root, session, scheduling, or process context. |
| `namespace-access` | Creates or enters Linux namespaces or another process execution context. |

Use `latra db capabilities` to list the embedded capability database and `latra db capabilities <capability>` to inspect an individual capability.

## Capability emission

Capabilities may be emitted from several evidence sources. The source rule ID,
operation ID, target, resolution, and source location are retained in the
analysis model.

| Source | Typical use |
| --- | --- |
| Command rule | Behavior inherent to a command or a narrowly matched command form. |
| Wrapper rule | Identity or execution-context behavior while preserving analysis of the wrapped command. |
| Interpreter rule | Inline or dynamically supplied source code. |
| Upload rule | A command option that sends local data externally. |
| File rule | Read or write access derived from positional or option operands. |
| Target rule | A prefixed argument that identifies a path or device target. |
| Operation rule | Behavior derived from a normalized shell operation instead of a command name. |
| Path capability | Security meaning derived from the classified target of a file access. |

Multiple rules may emit capabilities for the same operation. This is expected
when each capability represents an independently supported fact. Findings are
responsible for interpreting combinations and suppressing semantically
subsumed results.

## Path classes

Path classes describe the security meaning of resolved or partially resolved
file targets. They are defined in `path-classes.yaml`; only classes mapped in
`path-capabilities.yaml` emit read or write capabilities.

| Path class | Meaning |
| --- | --- |
| `project-sensitive` | Secret-like files under the mounted project, including environment, cloud, SSH, and package credentials. |
| `user-sensitive` | Credential locations under root or Workshop user homes. |
| `system-sensitive` | Protected system credential and authorization files. |
| `unknown-sensitive-candidate` | Partially known paths with a secret-like suffix or basename. |
| `sensitive` | General credential-, token-, secret-, SSH-, AWS-, or key-like paths. |
| `persistence` | Startup, service, cron, profile, shell rc, or Git hook locations. |
| `state` | Persisted Workshop SDK state. |
| `sdk` | SDK-owned files and paths derived from the `SDK` variable. |
| `project` | Files under `/project`. |
| `project-vcs-control` | Project Git configuration, submodule metadata, and repository hooks. |
| `project-ci-control` | Project continuous-integration workflow and pipeline definitions. |
| `project-build-control` | Project build and package lifecycle configuration. |
| `project-dependency-control` | Project dependency manifests and lock files. |
| `project-execution-control` | Project scripts and development task configuration that can run commands later. |
| `project-source` | Project source trees whose deletion affects repository integrity. |
| `project-generated` | Well-known Project build-output directories such as `build`, `dist`, `out`, and `target`. |
| `root-home` | Files under `/root`. |
| `user-home` | Files under `/home/workshop`. |
| `runtime` | Runtime state under `/run`. |
| `device` | Kernel and device interfaces under `/proc`, `/sys`, or `/dev`. |
| `temporary` | Temporary storage under `/tmp` or `/var/tmp`. |
| `system` | System paths under `/etc`, `/usr`, or `/opt`. |

Classification uses normalized paths and hook context. More specific sensitive
project and credential classes are evaluated before broad project, home, and
system classes. Exclusions such as `.env.example` are applied before positive
matches. Variable-backed paths such as `SDK` and `SDK_STATE_DIR` retain their
semantic class even when their final runtime value is unavailable.

Some mappings emit additional capabilities. For example, reading a
`project-sensitive` target emits `project-sensitive-file-read`,
`sensitive-file-read`, and `project-read`. These are factual views of the same
access and allow finding rules to select the narrowest suitable evidence.

## Change contract

When adding or changing a capability:

1. Define it in `capabilities.yaml` with a factual, intent-neutral description.
2. Add the narrowest command, operation, file, target, or path rule that can
   support it.
3. Add positive and nearby negative regression cases for every supported form.
4. Inspect it with `latra db capabilities <capability>` and, when command-based,
   `latra db capabilities --command <command> --verbose`.
5. Update this document when the public capability or path-class vocabulary
   changes.
6. Run `workshop run -- format` and `workshop run -- check`.

Do not add a capability solely to make a command known. Register the command
without behavior and add capability rules only when the behavior is supported
by its invocation form or resulting operation.
