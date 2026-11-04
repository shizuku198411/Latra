# Embedded capability configuration

These YAML fragments are embedded into the Latra binary, strictly decoded, merged, and validated as one configuration.

- `capabilities.yaml` owns `schema-version` and `capability-definitions`.
- `command-definitions.yaml` contains categorized known commands that do not imply a Capability by themselves.
- `commands-*.yaml` contains command rules grouped by functional area.
- `wrappers.yaml` contains normalized command-wrapper behavior.
- `files.yaml`, `targets.yaml`, `interpreters.yaml`, `uploads.yaml`, and `operations.yaml` correspond to their evaluator models.
- `path-classes.yaml` classifies paths; `path-capabilities.yaml` maps those classes to reported behavior.

Rule IDs remain globally unique across every fragment. Capability references and path-class references may cross files because validation runs after the complete merge. Map keys such as capability definitions and path classes cannot be overridden by a later fragment.

Add new knowledge to the narrowest existing fragment. Create another fragment only when it represents a stable functional area; the loader automatically embeds every `default/*.yaml` file.
