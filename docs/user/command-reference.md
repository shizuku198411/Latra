# Command reference

Latra statically inventories and analyzes Canonical Workshop SDKs without executing their hooks.

```text
latra <command> [arguments] [options]
```

## Commands

| Command | Purpose |
| --- | --- |
| `scan` | Inventory and analyze the SDKs used by a Workshop project. |
| `db` | Inspect Latra's embedded command and capability database. |
| `file` | Print an SDK file or describe a binary SDK file. |
| `hook` | Print a standard Workshop hook from an SDK. |
| `cache` | Remove SDK Store artifacts from Latra's local cache. |
| `version` | Print Latra build information. |
| `help` | Print command-line help. |

## `latra scan`

Scan a Workshop project or an individual project SDK.

```text
latra scan <PROJECT_OR_PROJECT_SDK> [options]
```

### Arguments

| Argument | Description |
| --- | --- |
| `PROJECT_OR_PROJECT_SDK` | A Workshop project containing `.workshop/*.yaml`, or a project SDK directory containing SDK metadata. |

### Options

| Option | Description |
| --- | --- |
| `--format text|json` | Select the report format. The default is `text`. |
| `--output PATH`, `-o PATH` | Write the report to a file. Use `-` for stdout, which is the default. |
| `--verbose` | Include complete SDK, file, hook, parse, operation, and capability details. |
| `--quiet` | Suppress non-error status output, including the scan spinner. |
| `--no-color` | Disable terminal colors where supported. |

The `--format` and `--output` options also accept `--format=<value>` and `--output=<value>`.

### Compact and verbose reports

Without `--verbose`, both text and JSON reports contain:

- input information;
- Workshop definitions;
- the summary;
- diagnostics.

The compact text summary displays only SDK metadata and standard hook paths in its Files section. Other entries are represented by `... and more files (<count>)`.

With `--verbose`, the report includes the complete SDK inventory and analysis details. Text file contents are included directly. Binary file contents are represented by metadata and a digest.

### Examples

Scan the current Workshop project and print a compact text report:

```bash
latra scan .
```

Print a compact JSON summary:

```bash
latra scan . --format json
```

Write the complete JSON report to a file:

```bash
latra scan . --format json --verbose --output latra-report.json
```

Scan an individual project SDK directly:

```bash
latra scan .workshop/project-base
```

### Status output

When stderr is an interactive terminal, Latra displays an animated scan status:

```text
scanning SDK(s) ... |
```

The line changes to `completed!` when scanning succeeds and `failed!` when it fails. The status is written to stderr and never becomes part of a text or JSON report. It is disabled by `--quiet` and is not emitted when stderr is redirected.

See [Understanding scan output](report-output.md) for the meaning of each summary section.

## `latra db`

Inspect the command and capability knowledge embedded in the Latra binary.

### Database overview

```text
latra db [options]
```

The overview reports the database source, schema version, and the number of capabilities, commands, and rules.

```bash
latra db
```

### Capabilities

```text
latra db capabilities [CAPABILITY] [--command COMMAND] [options]
```

| Form | Description |
| --- | --- |
| `latra db capabilities` | List every capability. |
| `latra db capabilities <capability>` | Show one capability and its command/rule associations. |
| `latra db capabilities --command <command>` | List capabilities associated with a command. |

Examples:

```bash
latra db capabilities
latra db capabilities network-access
latra db capabilities --command curl --verbose
```

### Commands

```text
latra db commands [COMMAND] [--capability CAPABILITY] [options]
```

| Form | Description |
| --- | --- |
| `latra db commands` | List every known command. |
| `latra db commands <command>` | Show one command, its category, description, and rule associations. |
| `latra db commands --capability <capability>` | List commands associated with a capability. |

Examples:

```bash
latra db commands
latra db commands curl
latra db commands --capability network-access --verbose
```

### Database options

| Option | Description |
| --- | --- |
| `--format text|json` | Select the output format. The default is `text`. |
| `--output PATH`, `-o PATH` | Write output to a file. Use `-` for stdout. |
| `--verbose` | Include rule associations in list and filtered-list results. |
| `--command COMMAND` | Filter `db capabilities` by command. |
| `--capability CAPABILITY` | Filter `db commands` by capability. |

A named capability or command query includes its associations without requiring `--verbose`. Unknown names return an error.

The database reflects the configuration embedded when the binary was built. See [Capability model and definitions](../development/database/capabilities.md) for the definitions and [Command database development](../development/database/command-database.md) for maintenance instructions.

## `latra file`

Print a file from a project SDK or a Store SDK already materialized in Latra's cache.

```text
latra file <SDK> <FILE> [options]
```

### Arguments

| Argument | Description |
| --- | --- |
| `SDK` | The normalized SDK name shown by `latra scan`. |
| `FILE` | The SDK-relative file path shown in the inventory. |

The file path must remain inside the selected SDK and must identify a regular file.

### Content selection options

| Option | Description |
| --- | --- |
| `--project PATH` | Resolve the SDK from the Workshop definitions under `PATH`. The default is the current directory. |
| `--channel CHANNEL` | Explicitly select a cached Store channel instead of using a Workshop declaration. |
| `--revision REVISION` | Select a positive cached revision within the resolved or explicit channel. |
| `--` | Stop option parsing. Following values are treated as positional arguments. |

Options may use either `--option value` or `--option=value` syntax.

### SDK selection

When `--channel` is not supplied, Latra:

1. reads `.workshop/*.yaml` from the current directory or `--project` path;
2. finds the requested SDK declaration;
3. uses the declared Store channel, or the `stable` default when omitted;
4. selects the newest matching cached revision unless `--revision` is supplied;
5. reads `.workshop/<name>` directly when the declaration is `project-<name>`.

Latra returns an error when the SDK is not declared, declarations conflict, the declared channel is not cached, or a requested revision does not exist. It does not silently select another channel.

An explicit `--channel` overrides Workshop channel resolution and selects directly from the cache. `--revision` cannot be used with a project SDK.

`file` does not download a missing Store SDK. Run `latra scan` first to resolve and cache the SDK used by the project.

### Output

Text files are written to stdout unchanged. Binary files produce a description similar to:

```text
Binary file
Type: ELF 64-bit LSB
MIME: application/octet-stream
Size: 123456 bytes
SHA3-384: <digest>
```

Files larger than 128 MiB are not displayed by `file`.

### Examples

Print the metadata file for an SDK declared by the current project:

```bash
latra file go meta/sdk.yaml
```

Read from another Workshop project:

```bash
latra file go meta/sdk.yaml --project ../another-project
```

Explicitly inspect a cached channel and revision:

```bash
latra file go sdk/hooks/setup-base --channel 1.26/stable --revision 42
```

## `latra hook`

Print a standard Workshop hook without executing it.

```text
latra hook <SDK> <HOOK> [options]
```

### Arguments

| Argument | Description |
| --- | --- |
| `SDK` | The normalized SDK name shown by `latra scan`. |
| `HOOK` | A standard Workshop hook name. |

Supported hook names are:

- `setup-base`
- `setup-project`
- `check-health`
- `save-state`
- `restore-state`

The command supports the same `--project`, `--channel`, `--revision`, and `--` options and the same SDK selection rules as `latra file`.

Latra accepts both SDK hook layouts internally:

- `hooks/<hook>`
- `sdk/hooks/<hook>`

The caller supplies only the hook name, not its path. An SDK containing the same hook in both layouts is rejected as ambiguous.

### Examples

Print a Store SDK hook using the channel declared by the current project:

```bash
latra hook go setup-base
```

Print a project SDK hook from another project:

```bash
latra hook project-base check-health --project ../another-project
```

Inspect a specific cached Store revision:

```bash
latra hook rust setup-base --channel latest/stable --revision 54
```

## `latra cache`

Inspect or remove SDK Store artifacts cached by Latra.

```text
latra cache list
latra cache clean [--project PATH]
latra cache clean --all
```

List every complete SDK Store cache entry, independently of the current
project:

```bash
latra cache list
```

The output contains the SDK name, effective Store channel, and revision. A
cache entry is listed only when both its extracted revision directory and
corresponding `.sdk` archive are present.

Without `--all`, Latra reads the Workshop definitions in the current directory
and removes every cached channel and revision for the Store SDKs declared by
that project. Project SDKs, system SDKs, try SDKs, and Store SDKs unrelated to
the project are not removed.

Use `--project` to select another Workshop project:

```bash
latra cache clean --project ../another-project
```

Use `--all` to remove every entry beneath Latra's cache root:

```bash
latra cache clean --all
```

`--all` cannot be combined with `--project`. The cache root directory itself is
preserved and will be reused by later scans. Missing matching entries are not
treated as an error.

## `latra version`

Print the version, commit, and build date recorded in the binary.

```text
latra version
latra -v
latra --version
```

Development builds without injected release metadata resemble:

```text
latra dev (commit: unknown, built: unknown)
```

## `latra help`

Print the built-in command summary.

```text
latra help
latra -h
latra --help
```

Running `latra` without arguments also prints help and exits successfully.

## Output streams

| Stream | Content |
| --- | --- |
| stdout | Reports, database output, file contents, hook contents, version, and help. |
| stderr | Interactive scan status, diagnostics, usage errors, and runtime errors. |

Use `--output` when a scan or database report should be written directly to a file. The `file` and `hook` commands always write successful content to stdout.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The command completed successfully. |
| `1` | Scanning, resolution, analysis, file access, output, or database lookup failed. |
| `2` | Command syntax or option usage was invalid. |

A scan can produce a report and still return `1` when hook parsing was incomplete. Always check the exit code when using Latra in automation.

## Environment

| Variable | Description |
| --- | --- |
| `SDK_STORE_URL` | Override the SDK Store API base URL used by `latra scan`. Intended for testing or alternate compatible services. |
