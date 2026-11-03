# Capability inventory

Latra reports capabilities as observable or conservatively inferred behavior. A capability is not a risk score, severity, policy decision, or claim of malicious intent. Every reported capability includes the rule ID and source, normalized operation, source location, target value, and resolution level that support the inference.

The built-in knowledge is split by responsibility under `internal/capabilityconfig/default/` and embedded in the Latra binary at build time. `capabilities.yaml` owns the schema version and capability definitions; rule fragments are grouped by evaluation model and command area. The fragments are strictly decoded, merged without silent map overrides, and then validated together for rule ID uniqueness, capability references, matcher values, operand selectors, access modes, and path-class references.

## Meanings

| Capability | Meaning |
| --- | --- |
| `network-access` | Uses a network protocol to communicate with an endpoint, including loopback, containers, virtual machines, and the host. Unix-domain sockets are not currently included. |
| `network-download` | Retrieves or consumes response content, files, repositories, or packages from a remote endpoint. Header-only and probe-only requests are excluded where the command exposes that distinction. |
| `external-send` | Sends local or generated data to a remote endpoint. A connection alone is not treated as a send. |
| `code-execution` | Executes a shell, interpreter, function, or dynamically supplied program. |
| `dynamic-execution` | Evaluates code whose complete behavior cannot be determined statically. |
| `privilege-modification` | Changes permissions, ownership, or file capabilities. |
| `destructive-operation` | Deletes or overwrites data, filesystems, devices, or broad path sets. |
| `project-read` / `project-write` | Reads from or writes to the mounted Workshop project. |
| `credential-read` | Reads a path likely to contain credentials or other sensitive data. |
| `state-read` / `state-write` | Reads from or writes to persisted Workshop SDK state. |
| `device-access` | Reads from or writes to a device or kernel interface path. |
| `persistence` | Changes or writes a location used to retain behavior across sessions or boots. |
| `system-modification` | Changes system packages, services, or protected system paths. |
| `environment-modification` | Installs, removes, or changes packages or tools in a language or user environment. |
| `identity-change` | Selects or changes the user or group identity used to execute a command. |
| `execution-context-change` | Changes the root, session, scheduling, or process context used to execute a command. |
| `namespace-access` | Creates or enters Linux namespaces or another process execution context. |

## Matching model

Command rules can distinguish subcommands, included or excluded options, argument prefixes, and transfer direction. Option matching supports a separate next argument, an attached short-option value, and a long-option `=` value.

File command rules describe positional operand roles rather than treating every argument identically. For example, `cp source destination` reads `source` and writes `destination`; a `grep` pattern is not treated as a file; and declared option values are removed from positional path operands. Redirects continue to supply explicit read and write data-flow edges.

When a required subcommand is dynamic, Latra retains each potentially matching capability with `PartiallyResolved` resolution instead of silently treating the operation as safe. A single dynamic subcommand can therefore match multiple mutually exclusive rules. Rules that require a specific option are only emitted when that option is observable.

The standard `--` option terminator is honored. Tokens after it remain positional operands even when they begin with `-`. Short-option clusters are expanded only when a rule declares the complete set of value-less flags that can safely occur in that cluster.

For APT installation, local artifacts include absolute and relative paths, `file:` URIs, path-like values, and `.deb` filenames. Network access is retained when at least one target is not a local artifact, including mixed local and remote target lists.

For SCP-style paths, an unqualified value containing `:` is treated as remote because SCP interprets it that way. Prefix a local colon-containing path with `./`, `../`, or `/` to keep it local.

Encoding, compression, archive, and cryptographic tools are not classified as obfuscation merely because they are present. Latra currently omits that capability until the operation and data flow provide evidence of concealment or restoration of executable content.

## Scope and limitations

The matcher is intentionally bounded and declarative; it is not a complete parser for every supported command. Static shell values can remain partially resolved or unknown, and cross-process or interprocedural data flow may not be recoverable. Consumers should use capability resolution and provenance when applying policy, and should not interpret absence as proof that a behavior cannot occur.

Workshop hooks can already run as root. Latra therefore does not treat the presence of `sudo` as proof of privilege escalation. Execution-user selection is recorded separately from `privilege-modification`, which is reserved for permissions, ownership, and file capabilities.

Latra now records `sudo`, `runuser`, and `pkexec` as `identity-change` while continuing to analyze their normalized inner command. This remains an execution-identity fact rather than a claim that privilege was gained. `su` command strings cannot yet be reparsed as nested shell AST, so they are retained as dynamic execution.

See [Command coverage](command-coverage.md) for the built-in command families and their matching boundaries.
