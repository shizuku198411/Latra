# JSON report schema

The machine-readable JSON Schema for Latra scan reports is [`report.schema.json`](report.schema.json). It uses JSON Schema Draft 2020-12 and describes report `schemaVersion` `"4"`.

## Report variants

The schema accepts both JSON report forms produced by `latra scan`:

| Command | Variant | Top-level fields |
| --- | --- | --- |
| `latra scan . --format json` | Compact | `schemaVersion`, `scanner`, `input`, `workshops`, `summary`, `diagnostics` |
| `latra scan . --format json --verbose` | Full | All compact fields plus `sdks` |

The root schema uses `oneOf` to distinguish these variants. The compact form intentionally omits SDK details rather than returning an empty `sdks` array.

## Stability boundary

`schemaVersion` is the compatibility boundary for report consumers. Version `1` is fixed for the original v0.1.0 report structure. Version `2` adds the operation graph used by contextual finding analysis. Version `3` distinguishes analyzed, binary-only, and resource-limited file content and exposes skipped-content totals. Version `4` adds unscored observations and normalized project-access evidence.

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
├── findingDatabase
├── input
├── workshops[]
├── summary
│   ├── sdks
│   ├── files
│   ├── hooks
│   ├── operations
│   ├── capabilities
│   ├── unknownCommands
│   ├── findings
│   ├── observations
│   └── diagnostics
├── assessment
│   ├── classification
│   ├── reviewPriority
│   ├── risk
│   ├── assurance
│   ├── coverage
│   └── bySdk[]
├── sdks[]                 # full report only
│   ├── metadata
│   ├── declarations[]
│   ├── files[]
│   ├── hooks[]
│   │   ├── parse
│   │   ├── context
│   │   ├── operations[]
│   │   ├── relations[]
│   │   └── capabilities[]
│   ├── findings[]
│   └── diagnostics[]
└── diagnostics[]
```

## Summary counts

Summary `count` fields contain occurrence totals, not unique-name totals.

- `files.count` counts all inventoried SDK filesystem entries.
- `files.contentSkipped` counts entries whose content was intentionally not retained because of a resource limit. Each per-SDK `skippedFiles` entry preserves its path, size, digest, and reason.
- `hooks.count` counts detected standard hooks.
- `operations.count` recursively counts top-level and child operations.
- `capabilities.count` counts capability occurrences.
- `unknownCommands.count` counts resolved command invocations not covered by the embedded command database.
- `diagnostics.count` counts document diagnostics.
- `findings.count` contains only scored risk and assurance findings.
- `observations.count` counts unscored project-access observations. Per-SDK project access contains read/write occurrence totals and unique normalized-path totals.

Per-SDK arrays contain the corresponding totals and sorted names. `CountedName.count` records occurrences for one name.

## File content

Every file in a full report contains `contentStatus`.

| `contentStatus` | Meaning |
| --- | --- |
| `analyzed` | Text content was retained and is available for analysis. |
| `binary-only` | Binary content is represented by metadata and a digest. |
| `skipped` | Content was not retained because of a resource limit. `skipReason` explains why. |
| `not-applicable` | The entry is not a regular file. |

Every regular file also contains `content` and `contentEncoding`. For skipped files, `content` is the digest rather than the original bytes.

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

## Operation graph

Schema version 2 assigns a deterministic `id` to every operation in a hook. Child operations use `parentId`, and `sequence` is their zero-based position among siblings. IDs are local to one hook and must not be joined across hooks.

The hook-level `relations` array connects operation IDs:

| Relation | Meaning |
| --- | --- |
| `contains` | A compound operation directly contains a child operation. |
| `sequence` | Two sibling operations execute in source order. |
| `pipeline` | Standard output from one operation is connected to standard input of another. |
| `substitution-flow` | Output from a command or process substitution is consumed by its owning operation. |
| `variable-flow` | A variable assignment may supply a later reference in the same lexical scope. |
| `redirect-flow` | Standard output from a producing command is written by an output redirect in the same shell statement. |

Each capability includes `operationId`, linking the inferred behavior to its source operation. Relations and capabilities also carry `resolution`; consumers must preserve uncertainty rather than treating `PartiallyResolved` or `Unknown` as conclusive flow. `artifact-flow` and `collection-flow` relations additionally record the normalized artifact and its provenance so reports can explain a Project input transformed through temporary files before reaching a sink.

Statically resolved SDK-local includes are represented by `include` relations carrying the inventory path and digest. Operations from the included file retain their own source locations, while Finding evidence also records the calling `source` location. Function calls use bounded expansion and expose `call` and `argument-flow` relations; unresolved or resource-limited includes remain dynamic and emit diagnostics.

SDK entries may also contain `lifecycleRelations`. A `state-flow` connects a `save-state` write to a matching `restore-state` read using the statically known path below `$SDK_STATE_DIR`. Its resolution remains partial and its limitation explicitly states that channel reachability does not prove byte identity across SDK revisions.

Project reports may contain top-level `compositionRelations`. A `project-artifact-execution` relation records an exact Project path written by an earlier SDK and executed by a later SDK in the same Workshop definition and hook window. `Declaration.order` is the semantic execution order; SDK array ordering remains a deterministic display concern only. Cross-SDK evidence identifies the SDK for each endpoint.

The graph is a conservative static representation. It does not claim complete shell control-flow or runtime data-flow resolution.

## Findings

`findingDatabase` identifies the embedded rule set independently from the scanner and report schema versions. A full report stores findings and observations under each SDK. Compact and full reports include risk and assurance counts under `summary.findings`, while observations are aggregated independently under `summary.observations`.

Rules can produce three kinds:

- `risk` records behavior that may require review and carries `severity`;
- `assurance` records an observed control or limitation and carries `strength`;
- `observation` records a security-relevant fact without classifying it as good or bad. Observations have weight `0` and carry neither severity nor strength.

Assurance findings do not remove or reduce risk findings. Neither kind is a claim that an SDK is malicious or safe. `confidence` describes evidence certainty, while `weight` is rule metadata reserved for later score calibration.

Every finding contains at least one evidence item. Operation and flow evidence uses the hook-local operation IDs described above, allowing consumers to join a finding back to `operations`, `relations`, and source locations.

Project-access observation evidence preserves both `value`, the raw shell path, and `normalizedValue`, the path resolved against the hook's tracked working directory. Partially resolved paths also retain every bounded candidate in `normalizedCandidates`. The `resolution` field indicates whether the normalized result is conclusive.

## Assessment

`assessment` is separate from the occurrence-oriented `summary`. It contains the project-wide final evaluation and an entry for every SDK under `bySdk`.

- `reviewPriority` is the headline score. Higher values require earlier review.
- `risk` and `assurance` are independently aggregated; assurance never subtracts from risk.
- `coverage` records how much of the relevant static input was successfully analyzed.
- `classification` combines the three axes into a descriptive outcome rather than a malware or safety verdict.
- `keyRisks` groups risk findings by rule and retains every SDK, hook, location, and relevant value contributing to the assessment.

Finding weights are multiplied by confidence (`low` 0.50, `medium` 0.75, `high` 1.00), aggregated with diminishing returns, and capped per family. Critical and high risk findings impose severity floors. The headline score is:

```text
reviewPriority = max(riskScore, 100 - coverageScore)
```

The JSON form retains family contributions, complete key-risk scopes, and hook, command, and file coverage counters so consumers can explain the displayed score. File coverage includes `contentSkipped`; skipped non-essential content does not by itself make hook and command coverage insufficient. Assessment text and JSON both retain all key risks and locations.

## Diagnostics

The top-level `diagnostics` array is the normalized project-wide diagnostic stream. Full reports may also include SDK-level diagnostics under `sdks[].diagnostics` and parser diagnostics under `sdks[].hooks[].parse.diagnostics`.

Consumers should use the top-level array for project-wide completeness checks and the nested fields when SDK or parser-specific context is required.

## Generate reports

Generate a compact fixture:

```bash
workshop run -- latra scan ./testdata/project-sdks/valid-project \
  --format json \
  --output /tmp/latra-compact.json
```

Generate a full fixture:

```bash
workshop run -- latra scan ./testdata/project-sdks/valid-project \
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
