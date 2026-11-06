# Development environment

Latra development takes place inside a [Canonical Workshop](https://ubuntu.com/workshop) environment. Contributors should not use a Go installation from the host system to build, test, format, or run the project.

The committed Workshop definition provides Ubuntu 26.04 and pins the Go SDK to the `1.27/stable` channel. At the time this environment was verified, the channel provided Go 1.27.3. The channel may receive patch releases without changing the project definition.

## Prerequisites

Install and configure Workshop and LXD by following the [Workshop getting-started documentation](https://ubuntu.com/workshop/docs/tutorial/part-1-get-started/). No host Go installation is required.

## Create the environment

From the repository root, launch the development workshop:

```console
$ workshop launch dev
```

If `dev` already exists and `.workshop/dev.yaml` has changed, refresh it:

```console
$ workshop refresh dev
```

Confirm that it is ready and inspect the Go toolchain:

```console
$ workshop list
WORKSHOP  STATUS  NOTES
dev       Ready   -

$ workshop exec dev -- go version
go version go1.27.3 linux/arm64
```

Do not depend on the exact patch version shown above. The `1.27/stable` channel is the reproducibility boundary for development.

## Development actions

The Workshop definition exposes the supported project commands as named actions:

```console
$ workshop actions dev
$ workshop run dev -- format
$ workshop run dev -- format-check
$ workshop run dev -- vet
$ workshop run dev -- test
$ workshop run dev -- check
$ workshop run dev -- e2e
$ workshop run dev -- build
```

Use `check` before opening a pull request. It checks formatting, runs `go vet`, and executes the complete test suite.

Use `e2e` to build the Latra binary and run the SDK Store workflow against the loopback-only Python mock Store under `testdata/e2e/`. The action does not contact the production SDK Store.

The `build` action writes the development binary to `build/latra`. Run the current source without relying on a host toolchain through the `latra` action:

```console
$ workshop run dev -- latra version
latra dev (commit: unknown, built: unknown)
```

Arguments after the action name are passed to Latra. For example, once the scan command is implemented:

```console
$ workshop run dev -- latra scan ./testdata/project-sdks/valid-project
```

For an interactive shell inside the same environment, run:

```console
$ workshop shell dev
```

The repository is mounted at `/project` and changes made there are reflected on the host checkout.

## Command database changes

See [Command database development](database/command-database.md) when adding known commands, capability mappings, match rules, or path classifications under `internal/capabilityconfig/default/`.

See [JSON report schema](json-schema.md) when changing report fields, JSON tags, enums, compact output, or verbose output.

## Dependency changes

Run Go module commands inside the workshop:

```console
$ workshop exec dev -- go get example.com/module@version
$ workshop exec dev -- go mod tidy
$ workshop run dev -- check
```

Commit both `go.mod` and `go.sum`. Update `THIRD_PARTY_NOTICES.md` when a direct dependency or its license changes.

## Troubleshooting

If an action fails because the workshop is stopped, start it and retry:

```console
$ workshop start dev
$ workshop run dev -- check
```

If the definition or SDK revision changed, use `workshop refresh dev`. Inspect failures with `workshop changes`, `workshop tasks`, and `workshop info dev`.
