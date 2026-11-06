# Analysis databases

Latra separates factual shell behavior from security interpretation. Two
embedded, strictly validated YAML databases support that boundary.

```text
Shell AST and normalized operations
              │
              ▼
Command and capability database
  commands · operands · paths · capabilities
              │
              ▼
Finding database
  observations · risks · assurance · evidence
              │
              ▼
Assessment
  risk · assurance · coverage · review priority
```

## Documents

- [Capability model and definitions](capabilities.md) defines categories,
  capabilities, path semantics, and the boundary between facts and findings.
- [Command database development](command-database.md) documents every YAML
  fragment and how command forms, operands, operations, and paths emit
  capabilities.
- [Finding database development](finding-database.md) documents rule metadata,
  matcher types, lifecycle constraints, evidence, and versioning.

## Ownership boundaries

| Question | Change |
| --- | --- |
| Is this command known? | Add or update a command definition. |
| Does this command form have observable behavior? | Add a command, file, wrapper, interpreter, upload, target, or operation rule. |
| Does this path have security meaning? | Add or update a path class and its read/write capability mapping. |
| Is a new factual behavior needed? | Define a capability, then add narrow emission rules. |
| Should evidence affect review priority? | Add or update a finding rule and matcher. |

Command and capability rules must remain factual. Finding rules may interpret
those facts, but must retain evidence and lifecycle context. Neither database
should infer malicious intent from a command name alone.

## Build-time embedding

The default fragments are embedded with Go's `embed` package. Database changes
therefore require rebuilding Latra. Runtime user-defined databases are not part
of the current implementation.

Run validation inside the Workshop development environment:

```bash
workshop run -- format
workshop run -- check
```
