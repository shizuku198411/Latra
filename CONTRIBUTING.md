# Contributing to Latra

Thank you for helping improve Latra. Contributions may include design feedback, test fixtures, parser improvements, documentation, bug fixes, and new analysis capabilities.

## Before contributing

- Search existing issues before opening a new one.
- Use the appropriate issue template for bugs and feature proposals.
- Keep security reports private and follow [SECURITY.md](SECURITY.md).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

For substantial changes, open an issue first so the scope and design can be discussed before implementation begins.

## Pull requests

Keep each pull request focused on one logical change. A pull request should:

- explain the problem and the chosen approach;
- include or update tests for behavioral changes;
- update user-facing documentation when applicable;
- avoid unrelated formatting or refactoring;
- preserve deterministic output and compatibility unless the change is explicitly documented.

All commits must be your own work or otherwise legally contributed under the project's MIT License. By submitting a contribution, you agree that it may be distributed under that license.

## Development

Latra development uses the committed Workshop environment and its Go 1.27 SDK. Do not use a host Go installation for project development. See [docs/development.md](docs/development.md) for setup and environment details.

The standard development commands are:

```shell
workshop run dev -- build
workshop run dev -- test
workshop run dev -- vet
workshop run dev -- check
workshop run dev -- format
```

Run `workshop run dev -- latra version` to execute Latra from the current source tree.

## Test fixtures

Treat all SDK fixtures as untrusted input. Hooks in `testdata/` are for static analysis and must not be executed directly on the host. Keep fixtures minimal, deterministic, free of real credentials, and clear about the behavior they are intended to exercise.

