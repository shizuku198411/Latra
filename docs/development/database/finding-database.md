# Finding database

Latra's built-in finding rules are YAML files under [`internal/findingconfig/default/`](../../../internal/findingconfig/default/). The files are embedded into the binary at build time. Runtime scanning does not read mutable rule files from the host.

The current finding database uses schema version `4`. `schema.yaml` owns the
schema and content versions; every other fragment contributes only rules.

## Choose the correct fragment

| Rule responsibility | Fragment |
| --- | --- |
| Parser, resolution, inventory, or resource-limit coverage | `risk-analysis.yaml` |
| Direct capability and persistence behavior | `risk-behavior.yaml` |
| Sensitive-data and project-data flows | `risk-data-exposure.yaml` |
| Hook lifecycle misuse | `risk-lifecycle.yaml` |
| Remote content execution and project delivery | `risk-remote-execution.yaml` |
| Analysis completeness and absence-based assurance | `assurance-analysis.yaml` |
| Least privilege and path-scoped assurance | `assurance-scope.yaml` |
| Unscored project boundary access | `observation-project-boundary.yaml` |

Add a new fragment only for a stable rule family that does not fit an existing
responsibility. Default fragments are loaded in sorted filename order, while
finding output is deterministically sorted independently of that load order.

## Responsibilities

The finding database defines stable rule metadata and declarative matcher parameters:

- finding ID and kind (`risk`, `assurance`, or `observation`);
- family, title, message, and remediation;
- severity or strength, confidence, and weight;
- matcher type and its capability, context, path, diagnostic, or flow constraints;
- assurance relationships and limitations.

The engine in `internal/finding/` evaluates these definitions against inventory, operation, relation, capability, and hook-context data. Rules must not infer malicious intent from a command name alone.

## Rule shape

```yaml
finding-rules:
  - id: risk.remote-content-execution
    kind: risk
    family: remote-execution
    title: Remote content is executed by a shell
    severity: critical
    confidence: high
    weight: 85
    match:
      type: relation-flow
      relation-kinds:
        - pipeline
        - substitution-flow
        - variable-flow
      source-capability: network-download
      sink-commands:
        - sh
        - bash
    message: Content received from a remote endpoint flows directly to a shell.
    remediation: Download and verify the artifact before executing it.
```

Risk rules require `severity`; assurance rules require `strength`. Observation rules are unscored, require weight `0`, and carry neither severity nor strength. All rules require evidence at runtime. A matcher that cannot produce evidence must not emit a finding.

### Rule fields

| Field | Contract |
| --- | --- |
| `id` | Globally unique stable identifier using lowercase dot or hyphen segments. |
| `kind` | `risk`, `assurance`, or `observation`. |
| `family` | Assessment aggregation family. |
| `severity` | Required for risk: `info`, `low`, `medium`, `high`, or `critical`. |
| `strength` | Required for assurance: `info`, `low`, `medium`, or `high`. |
| `confidence` | `low`, `medium`, or `high`; may be lowered by runtime resolution. |
| `weight` | Integer from `0` to `100`; observations must use `0`. |
| `match` | Declarative matcher type and its constraints. |
| `message` | User-facing explanation of the observed behavior. |
| `remediation` | Optional review or mitigation guidance. |
| `protects-against` | Optional identifiers describing assurance coverage. |
| `limitations` | Optional boundaries that prevent overinterpreting the finding. |

## Matcher types

| Type | Intended evidence |
| --- | --- |
| `capability` | One matching capability occurrence, optionally constrained by hook and root context. |
| `path-write` | An operation output classified into one of the configured path classes. |
| `persistence-write` | A persistence capability except a statically controlled `setup-base` write under `/etc/profile.d/*.sh`. |
| `profile-environment-write` | A fully resolved, statically controlled `setup-base` environment-profile write. |
| `repository-persistence` | A project hook file write or a `core.hooksPath` configuration change during project setup. |
| `project-in-place-modification` | An in-place editor operation targeting a file under the mounted project. |
| `toolchain-search-order-hijack` | A correlated executable write, execute-permission change, and project PATH prepend. |
| `unknown-command` | A resolved command not covered by the command database. |
| `parse-status` | A hook parser status such as `Failed` or `Recovered`. |
| `sdk-unresolved` | A non-resolved SDK state. |
| `sdk-diagnostic` | A stable SDK diagnostic code or a narrowly configured diagnostic-message fragment when an outer layer wraps the underlying code. |
| `relation-flow` | A source capability reaching a sink through operation-graph relations. |
| `all-hooks-parsed` | SDK-wide complete parsing without recovery. |
| `all-commands-known` | SDK-wide known-command coverage. |
| `absence-capability` | Absence of a capability, emitted only when analysis coverage is sufficient. |
| `archive-digest` | A Store SDK with a recorded archive digest. |
| `complete-file-inventory` | A resolved SDK without a resource-limit diagnostic. |
| `read-only-health-check` | A parsed, known-command health check without detected mutation capabilities. |

## Hook context constraints

Hook-level matchers can narrow a rule with any combination of the following fields:

```yaml
match:
  type: capability
  capabilities:
    - project-write
  hook-names:
    - check-health
  run-as-root: true
  project-mounted: true
  interfaces-active: true
  state-mounted: false
  context-dependent: false
```

All configured fields use AND semantics. Omitted fields do not constrain the match. If a rule requires execution context but hook analysis did not produce that context, the rule does not match; Latra does not infer a positive match from the hook name alone.

Context fields are supported by hook-level matchers such as `capability`, `path-write`, `unknown-command`, `parse-status`, `relation-flow`, `read-only-health-check`, and hook-scoped `absence-capability`. SDK-level matchers reject hook context fields during configuration validation.

## Relation-flow matchers

A relation-flow matcher requires `source-capability` and at least one sink constraint. `sink-commands` matches normalized command names. `sink-capability` matches an observed sink behavior and is preferred when several commands implement the same behavior.

```yaml
match:
  type: relation-flow
  relation-kinds:
    - pipeline
    - substitution-flow
    - variable-flow
    - redirect-flow
  source-capability: project-sensitive-file-read
  sink-capability: external-send
  same-operation: true
  project-mounted: true
  interfaces-active: true
```

`relation-kinds` follows explicit operation-graph edges. Supported data-flow edges are `pipeline`, `substitution-flow`, `variable-flow`, and `redirect-flow`. `same-operation: true` additionally matches commands such as `curl -F file=@.env`, where the file input and external send are capabilities of one operation. When command and capability sink constraints are both present, both must match.

Flow evidence records the source capability and the sink, including both operation IDs, values, resolutions, and source locations. Relation resolution can lower finding confidence when substitution or variable propagation is not fully resolved.

## Profile environment calibration

The paired `persistence-write` and `profile-environment-write` matchers are mutually exclusive. A write is assigned to the low-severity profile rule only when all of the following are established:

- the hook is `setup-base` with its expected Workshop context;
- the target is fully resolved and its normalized path is `/etc/profile.d/<name>.sh`;
- content comes from resolved `echo` or `printf` arguments, or a static heredoc, and contains only declarative `NAME=...` or `export NAME=...` environment assignments, comments, and blank lines;
- heredoc templates may reference the Workshop-provided `SDK` variable; other unresolved variables and expansions are rejected;
- the content does not contain a recognized download or shell-execution payload;
- a `tee` write receives the same kind of static generator through a pipeline.

Remote download output, unresolved non-Workshop variables or paths, command substitution, arbitrary script statements, non-static file input, another lifecycle hook, and other persistence locations remain under the generic medium-severity persistence rule. Reading or sourcing a persistence-class path is not treated as a persistence write. This is an allowlisted calibration, not a general trust decision for profile writes.

## Repository hook persistence

The `repository-persistence` matcher is constrained to `setup-project` while
the project is mounted. It emits evidence for either a project write to a file
under `.git/hooks/` or a `git config` command that assigns a value to
`core.hooksPath`. Directory creation, reads of `core.hooksPath`, removal of the
setting, unrelated `.git` files, and unrelated Git configuration keys do not
match.

## Project modification and toolchain correlation

`project-in-place-modification` reports an in-place editor only when its input
has already been classified as a project read. Ordinary reads, generated-file
writes, and the same command outside `setup-project` do not match.

`toolchain-search-order-hijack` requires three correlated facts in one
`setup-project` hook: a project file is written, the same file receives execute
permission, and a project configuration file is generated with that file's
directory prepended to `PATH`. A different PATH directory, a non-project
executable, or any one behavior in isolation does not match.

## Adding a rule

1. Select the closest category file under `internal/findingconfig/default/`.
2. Add a globally unique ID. Published IDs must not be repurposed.
3. Use the narrowest matcher and preserve context constraints.
4. Add a positive fixture, a near-miss fixture, and an uncertainty or context variant.
5. Verify that every emitted finding links to source, operation, flow, diagnostic, or SDK metadata evidence.
6. Run `workshop run -- format` and `workshop run -- check`.
7. Review the normal SDK corpus for frequency and false positives.

Adding a rule, changing matcher behavior, or changing a weight requires updating `content-version` in `schema.yaml`. Changing the YAML structure or compatibility contract requires a finding database `schema-version` change. Report structure changes are versioned separately by the report `schemaVersion`.
