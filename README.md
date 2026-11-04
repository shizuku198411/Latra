<p>
  <img src="./assets/latra_logo.png" alt="Latra logo" width="250">
</p>

# Latra

Latra is an open-source static analysis tool for [Canonical Workshop](https://ubuntu.com/workshop) SDKs. It is designed to reveal SDK contents and behavior that are otherwise difficult to inspect before a Workshop environment is created.

Workshop SDKs can include shell hooks that run during environment setup, health checks, and refresh operations. Because SDKs may come from third-party publishers, Latra treats every SDK as untrusted input and analyzes it without executing its hooks.

Latra aims to provide:

- an inventory of SDK metadata, bundled files, and lifecycle hooks;
- Bash syntax analysis based on an abstract syntax tree rather than text matching;
- normalized commands, file and network interactions, data flows, and capabilities;
- deterministic, versioned JSON output for local tooling and CI integration;
- support for in-project SDKs followed by SDK Store resolution and analysis.

Risk findings, policy enforcement, and explainable risk scoring are planned as later capabilities built on top of the inventory model.

## Project status

Latra is under active development and is not yet recommended for production enforcement. The current scope focuses on deterministic SDK inventory generation and investigation workflows.

Latra is an independent project and is not affiliated with or endorsed by Canonical Ltd.

## Quick Start

### Build and install

Build Latra inside the Workshop environment and install the resulting binary
on the host:

```bash
./scripts/install.sh
```

The installation script launches the `dev` Workshop when needed and runs
`workshop run -- build` before installing the binary. A Workshop launched by
the script is removed after the build; an already-running Workshop is preserved.

Remove the default installation with:

```bash
./scripts/uninstall.sh
```

Run Latra from the root of a Workshop project.

### Scan the project

```bash
# command: latra scan <project dir>

latra scan .
```

The default text report summarizes the detected SDKs, files, hooks, operations, capabilities, unknown commands, and diagnostics.

<details>
<summary>Example output</summary>

```text
Input
  Kind: project
  Root: /project

Workshops
  dev
    Definition: .workshop/dev.yaml
    Base: ubuntu@26.04

Summary
  SDKs: 1 (1 resolved, 0 unresolved)
    Resolved: go
    Unresolved: -
  Files: 17381
    go (17381): meta/sdk.yaml, sdk/hooks/check-health, sdk/hooks/restore-state, sdk/hooks/save-state, sdk/hooks/setup-base, ... and more files (17376)
  Hooks: 4
    go (4): check-health, restore-state, save-state, setup-base
  Operations: 27
    go (27): assignment (3), command-invocation (14), command-substitution (1), control-flow (4), pipeline (2), redirect-read (2), redirect-write (1)
  Capabilities: 9
    go (9): identity-change (6), persistence (1), state-read (1), state-write (1)
  Unknown Commands: 0
    go (0)
  Diagnostics: 0: -
```

</details>

### Inspect a hook or file

Use an SDK name and hook reported by the scan:

```bash
# command: latra hook <sdk> <hook>

latra hook go setup-base
```

<details>
<summary>Example output</summary>

```text
cat <<EOF >/etc/profile.d/go.sh
export PATH="/home/workshop/go/bin:$SDK/bin:\$PATH"
EOF

cache=/home/workshop/go/pkg/mod
sudo -iu workshop -- go env -w GOMODCACHE="$cache"

if [[ "$(dpkg --print-architecture)" == riscv64 ]]; then
gopls_version=$(cat "$SDK/share/gopls-version")
sudo -iu workshop -- env GOTOOLCHAIN=auto go install "golang.org/x/tools/gopls@${gopls_version}"
fi

sudo -iu workshop -- go env -w GOTOOLCHAIN=local
```

</details><br>

Display any detected SDK file by its reported path:

```bash
# command: latra cat <sdk> <file>

latra cat go meta/sdk.yaml
```

<details>
<summary>Example output</summary>

```text
name: go
title: Go SDK
version: 1.27.3
summary: The Go programming language
description: |
  This SDK provides the official Go toolchain for efficient Go development.
  Module downloads are persisted on the host to speed up builds across workshop
  updates, and Go environment settings are preserved between workshop updates.

  ## Key components

  - `go`: The Go programming language toolchain, including the
    compiler, standard library, and all official tools (`gofmt`, `goimports`,
    etc.). The version is determined by the SDK release, not the base image.
  - `gopls`: The official Go language server for editor integrations,
    built for the SDK's target architecture, tracking the latest gopls that
    supports the SDK's Go release. On RISC-V, the pinned version is installed
    when the workshop launches instead.
  - Module cache: Configured to persist at `~/go/pkg/mod` with a bind mount
    to the host, so downloaded dependencies survive workshop updates.
  - Environment preservation: Custom Go environment variables (set via
    `go env -w`) are automatically saved and restored across workshop updates.

  The SDK installs the complete official Go distribution from go.dev and a pinned
  `gopls` version from `golang.org/x/tools/gopls`. Build tools such as `gcc` are
  **not** included. If your project requires CGo or needs to compile C
  dependencies, install the necessary toolchain separately.

  ## Setup actions

  On launch, the SDK:

  - Adds Go binaries to `PATH` system-wide via `/etc/profile.d/go.sh`.
  - Configures `GOMODCACHE` to point to the persistent mount at
    `~/go/pkg/mod`.
  - Makes the SDK's pinned `gopls` build available on `PATH`.
  - Restores any previously changed Go environment variables.
architecture: arm64
website: https://github.com/canonical/go-sdk
license: BSD-3-Clause
plugs:
  mod-cache:
    interface: mount
    workshop-target: /home/workshop/go/pkg/mod
sdkcraft-started-at: '2026-10-20T21:30:48.728712+00:00'
```

</details><br>

Replace `go`, `setup-base`, and `meta/sdk.yaml` with values from your project report. Latra resolves the SDK from the current project's `.workshop/*.yaml` definitions, including its declared channel.

### Write a JSON report

Print the summary as JSON:

```bash
latra scan . --format json
```

Write the complete inventory and analysis details to a file:

```bash
latra scan . --format json --verbose --output latra-report.json
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating.

## Security

Do not report security vulnerabilities through public issues. See [SECURITY.md](SECURITY.md) for the reporting process.

## License

Latra is licensed under the [MIT License](LICENSE).

