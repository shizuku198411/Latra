# JSON report schema

The machine-readable JSON Schema for Latra scan reports is [`report.schema.json`](report.schema.json). It uses JSON Schema Draft 2020-12 and describes report `schemaVersion` `"1"`.

## Report variants

The schema accepts both JSON report forms produced by `latra scan`:

| Command | Variant | Top-level fields |
| --- | --- | --- |
| `latra scan . --format json` | Compact | `schemaVersion`, `scanner`, `input`, `workshops`, `summary`, `diagnostics` |
| `latra scan . --format json --verbose` | Full | All compact fields plus `sdks` |

The root schema uses `oneOf` to distinguish these variants. The compact form intentionally omits SDK details rather than returning an empty `sdks` array.

## Stability boundary

`schemaVersion` is the compatibility boundary for report consumers. Version `1` is fixed for the v0.1.0 report structure.

Within one schema version:

- field names and meanings should remain compatible;
- enum values should not be removed or redefined;
- required fields should not become optional without a deliberate compatibility decision;
- new incompatible structures require a schema version change;
- deterministic array ordering is an output guarantee but is not expressed as a JSON Schema constraint.

The scanner's release version is reported separately in `scanner.version`. It does not replace `schemaVersion`.

## Main structure

```text
report
├── schemaVersion
├── scanner
├── input
├── workshops[]
├── summary
│   ├── sdks
│   ├── files
│   ├── hooks
│   ├── operations
│   ├── capabilities
│   ├── unknownCommands
│   └── diagnostics
├── sdks[]                 # full report only
│   ├── metadata
│   ├── declarations[]
│   ├── files[]
│   ├── hooks[]
│   │   ├── parse
│   │   ├── context
│   │   ├── operations[]
│   │   └── capabilities[]
│   └── diagnostics[]
└── diagnostics[]
```

## Summary counts

Summary `count` fields contain occurrence totals, not unique-name totals.

- `files.count` counts all inventoried SDK filesystem entries.
- `hooks.count` counts detected standard hooks.
- `operations.count` recursively counts top-level and child operations.
- `capabilities.count` counts capability occurrences.
- `unknownCommands.count` counts resolved command invocations not covered by the embedded command database.
- `diagnostics.count` counts document diagnostics.

Per-SDK arrays contain the corresponding totals and sorted names. `CountedName.count` records occurrences for one name.

## File content

Every regular file in a full report contains `content` and `contentEncoding`.

| `contentEncoding` | `content` value |
| --- | --- |
| `utf-8` | Original text content. |
| `sha3-384` | SHA3-384 digest instead of binary bytes. |

Directories and symbolic links do not contain file content. A symbolic link uses `linkTarget`.

## Locations and resolution

Source locations contain a path plus start and end line and column values. Source positions are one-based when available, and the end position is exclusive. Zero values may occur when a precise source position is unavailable.

Values, operations, and capabilities use these resolution values:

- `Resolved`
- `PartiallyResolved`
- `Unknown`

SDK resolution uses a separate `state` enum defined in the schema.

## Diagnostics

The top-level `diagnostics` array is the normalized project-wide diagnostic stream. Full reports may also include SDK-level diagnostics under `sdks[].diagnostics` and parser diagnostics under `sdks[].hooks[].parse.diagnostics`.

Consumers should use the top-level array for project-wide completeness checks and the nested fields when SDK or parser-specific context is required.

## Generate reports

Generate a compact fixture:

```bash
workshop run dev -- latra scan ./testdata/project-sdks/valid-project \
  --format json \
  --output /tmp/latra-compact.json
```

Generate a full fixture:

```bash
workshop run dev -- latra scan ./testdata/project-sdks/valid-project \
  --format json \
  --verbose \
  --output /tmp/latra-full.json
```

## Validate with a JSON Schema tool

Any Draft 2020-12 compatible validator can use `report.schema.json`. For example, with `check-jsonschema` installed:

```bash
check-jsonschema \
  --schemafile docs/development/report.schema.json \
  /tmp/latra-compact.json \
  /tmp/latra-full.json
```

## Updating the schema

When changing report structs or JSON tags:

1. update `report.schema.json` in the same change;
2. update this document when field meaning or compatibility guidance changes;
3. generate both compact and full reports;
4. validate both reports against the schema;
5. update report tests for required, omitted, and enum fields;
6. change `schemaVersion` only when the compatibility boundary changes.

The implementation source of truth is `internal/report/schema.go` together with the JSON models referenced by it. The checked-in JSON Schema is the public contract for external consumers.
