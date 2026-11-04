# Quick start

Run Latra from the root of a Workshop project.

See the [Command reference](command-reference.md) for complete syntax and options.

## Scan the project

```bash
# command: latra scan <project dir>

latra scan .
```

The default text report summarizes the detected SDKs, files, hooks, operations, capabilities, unknown commands, and diagnostics.

See [Understanding scan output](report-output.md) for a field-by-field explanation and investigation workflow.

## Inspect a hook or file

Use an SDK name and hook reported by the scan:

```bash
# command: latra hook <sdk> <hook>

latra hook go setup-base
```

Display any detected SDK file by its reported path:

```bash
# command: latra cat <sdk> <file>

latra cat go meta/sdk.yaml
```

Replace `go`, `setup-base`, and `meta/sdk.yaml` with values from your project report. Latra resolves the SDK from the current project's `.workshop/*.yaml` definitions, including its declared channel.

## Write a JSON report

Print the summary as JSON:

```bash
latra scan . --format json
```

Write the complete inventory and analysis details to a file:

```bash
latra scan . --format json --verbose --output latra-report.json
```
