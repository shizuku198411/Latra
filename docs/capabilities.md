# Categories and capabilities

Latra classifies known commands by category and reports observable or conservatively inferred SDK behavior as capabilities.

A capability describes detected behavior. It is not a risk score, severity, policy decision, or claim of malicious intent.

## Command categories

| Category | Description |
| --- | --- |
| `shell-builtin` | Commands implemented by the shell, such as output, condition, and shell-state operations. |
| `system-utility` | General operating-system and distribution utilities. |
| `sdk-tool` | Commands supplied by or closely associated with an SDK toolchain. |
| `workshop-official` | Official Canonical Workshop commands. |

Use `latra db commands` to list the currently registered commands and `latra db commands <command>` to inspect an individual command.

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
