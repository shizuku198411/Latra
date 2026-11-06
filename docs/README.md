# Documentation

Latra documentation is organized by audience and purpose.

## User documentation

- [Quick Start](user/quickstart.md) — scan a Workshop project, inspect SDK
  files and hooks, and create a JSON report.
- [Command reference](user/command-reference.md) — complete CLI syntax,
  options, exit codes, and environment variables.
- [Understanding scan output](user/report-output.md) — interpret inventory,
  observations, findings, diagnostics, and assessment results.

## Development documentation

- [Development environment](development/development.md) — build and test
  Latra in its Workshop environment.
- [Analysis database overview](development/database/README.md) — relationships
  among command knowledge, capabilities, paths, and findings.
- [Capability model and definitions](development/database/capabilities.md) —
  semantic capability and path-class reference.
- [Command database development](development/database/command-database.md) —
  maintain embedded command and capability mappings.
- [Finding database development](development/database/finding-database.md) —
  add and verify finding rules and matchers.
- [JSON report schema](development/json-schema.md) — report model and schema
  maintenance guidance.

## Design documentation

- [Analysis and assessment](design/analysis-and-assessment.md) — AST analysis,
  capabilities, findings, scoring, and assessment design.
