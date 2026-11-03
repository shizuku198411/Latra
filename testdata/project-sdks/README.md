# Workshop v0.9.9 project SDK fixtures

These fixtures cover the in-project SDK input patterns accepted by Workshop v0.9.9. This project refers to in-project SDKs as `project SDKs`. The fixtures are intended for reuse by Latra and its regression tests.

## Sources

- Workshop v0.9.9: the `v0.9.9` tag of the clone under `workshop/`
- Official documentation:
  - https://ubuntu.com/workshop/docs/explanation/sdks/concepts/
  - https://ubuntu.com/workshop/docs/reference/definition-files/sdk-definition/
  - https://ubuntu.com/workshop/docs/reference/sdks/
- Implementation:
  - `workshop/internal/sdk/local.go`: local SDK layout normalization
  - `workshop/internal/sdk/sdk.go`: `sdk.yaml` fields and strict validation
  - `workshop/internal/sdk/validate.go`: SDK name, base, architecture, and hook name constraints
  - `workshop/internal/overlord/workshopstate/manifest.go`: project SDK resolution and revision creation
  - `workshop/internal/workshop/workshop_file.go`: the `project-` prefix and Workshop-level plug/slot additions
- Upstream tests:
  - `workshop/tests/main/project-sdks/`
  - `workshop/tests/docs-how-to/write-runtime-hooks/`

## Fixture structure

`valid-project/` is a valid fixture that can be read as a single Workshop project.

| SDK | Metadata | Hooks | Primary coverage |
|---|---|---|---|
| `standard` | `sdk.yaml` | `hooks/` | Official authoring layout, minimal metadata, and all five hooks |
| `mixed-normalized-hooks` | `sdk.yaml` | `sdk/hooks/` | Mixed layout with only the hooks normalized |
| `mixed-normalized-metadata` | `meta/sdk.yaml` | `hooks/` | Mixed layout with only the metadata normalized; also used by v0.9.9 upstream tests |
| `fully-normalized` | `meta/sdk.yaml` | `sdk/hooks/` | Fully normalized Store-artifact layout, every metadata field, bundled files, and interfaces |

Workshop v0.9.9 normalizes metadata and hooks independently in `fixLayout`. The four combinations above therefore form the accepted layout matrix. The official documentation primarily presents `standard` as the authoring layout for an in-project SDK.

`invalid-projects/` separates boundary conditions that must not be mistaken for supported inputs. Each directory is an independent Workshop project and must not be scanned together with the valid fixture.

| Case | Expected result | Reason in v0.9.9 |
|---|---|---|
| `dual-metadata` | Error | `sdk.yaml` and `meta/sdk.yaml` cannot coexist |
| `dual-hooks` | Error | `hooks/` and `sdk/hooks/` cannot coexist |
| `inline-hooks` | Error | Inline hooks are supported only by the `sketch` SDK |
| `unknown-field` | Error | Runtime metadata uses strict YAML validation |
| `missing-metadata` | Error | `meta/sdk.yaml` must exist after normalization |

## Coverage

- `project-<NAME>` references from `.workshop/*.yaml`
- `sdk.yaml` and `meta/sdk.yaml`
- `hooks/` and `sdk/hooks/`
- `setup-base`, `setup-project`, `check-health`, `save-state`, and `restore-state`
- `$SDK`, `$SDK_STATE_DIR`, `$HOME`, and `/project`
- Minimal project SDK metadata, for which only `name` is required
- Every runtime metadata field recognized by v0.9.9
- Regular files bundled in an SDK directory
- Plugs and slots declared in SDK metadata
- Plugs, slots, and plug bindings added by the Workshop definition
- A Store SDK declaration alongside project SDKs (`rust` is expected to be `NotResolved` until the resolver is implemented)
- Invalid cases including strict-YAML violations, forbidden inline hooks, and duplicate metadata or hook layouts

## Safety note

The hooks are static-analysis fixtures and must not be executed directly on the host. Even the valid hooks assume the lifecycle, filesystem, and privileges provided inside a Workshop container.

