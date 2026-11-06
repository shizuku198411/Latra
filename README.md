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
- evidence-backed risk and assurance findings with explainable SDK assessments;
- deterministic, versioned JSON output for local tooling and CI integration;
- support for in-project SDKs followed by SDK Store resolution and analysis.

Latra reports review priority, risk, assurance, and static-analysis coverage independently. These assessments support review decisions; they do not declare an SDK safe or malicious.

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
  Root: /project/internaldocs/sample-project

Workshops
  kernel-dev
    Definition: .workshop/kernel-dev.yaml
    Base: ubuntu@24.04

Summary
  SDKs: 2 (2 resolved, 0 unresolved)
    Resolved: project-toolchain, rust
    Unresolved: -
  Files: 26
    project-toolchain (5): hooks/check-health, hooks/setup-base, hooks/setup-project, sdk.yaml, ... and more files (1)
    rust (21): meta/sdk.yaml, sdk/hooks/check-health, sdk/hooks/setup-base, ... and more files (18)
  Hooks: 5
    project-toolchain (3): check-health, setup-base, setup-project
    rust (2): check-health, setup-base
  Operations: 61
    project-toolchain (47): assignment (10), command-invocation (23), control-flow (9), redirect-write (5)
    rust (14): command-invocation (9), control-flow (1), redirect-read (1), redirect-write (2), source (1)
  Capabilities: 25
    project-toolchain (14): code-execution (1), device-access (5), identity-change (2), network-access (3), network-download (1), project-write (1), system-modification (1)
    rust (11): code-execution (1), destructive-operation (1), dynamic-execution (1), identity-change (2), network-access (2), persistence (2), system-modification (2)
  Unknown Commands: 5
    project-toolchain (5)
      hooks/check-health (4): clang (1), llvm-objcopy (1), llvm-objdump (1), qemu-system-riscv64 (1)
      hooks/setup-project (1): make (1)
    rust (0)
  Findings: 14 (6 risk, 8 assurance)
    High-priority risks:
      project-toolchain (high): risk.remote-content-to-project (1), risk.unknown-command-root (4)
  Diagnostics: 0: -

Observations
  Project Access: 1 (0 reads, 1 writes)
  By SDK:
    project-toolchain: 1 (0 reads, 1 writes)
```

</details>

### Review the assessment

Each scan ends with an assessment that separates detected risk, positive
assurance, and analysis coverage:

```text
Assessment
  Classification: powerful-but-controlled
  Review Priority: 79/100 (high)          [████████████████░░░░]
  Risk:            79/100 (high)          [████████████████░░░░]
  Assurance:       80/100 (strong)        [████████████████░░░░]
  Coverage:        94/100 (sufficient)    [███████████████████░]
  By SDK:
    project-toolchain: powerful-but-controlled
      Review Priority: 76/100 (high)          [███████████████░░░░░]
      Risk:            76/100 (high)          [███████████████░░░░░]
      Assurance:       66/100 (strong)        [█████████████░░░░░░░]
      Coverage:        91/100 (sufficient)    [██████████████████░░]
      Key Risks:
        risk.unknown-command-root: Unknown command runs in a root hook [medium, score=68, occurrences=4]
          sdk=project-toolchain file=hooks/check-health:8:1 hook=check-health value="qemu-system-riscv64"
          sdk=project-toolchain file=hooks/check-health:9:1 hook=check-health value="clang"
          sdk=project-toolchain file=hooks/check-health:10:1 hook=check-health value="llvm-objdump"
          sdk=project-toolchain file=hooks/check-health:11:1 hook=check-health value="llvm-objcopy"
        risk.remote-content-to-project: Remote content is written into the Workshop project [medium, score=25, occurrences=1]
          sdk=project-toolchain file=hooks/setup-project:13:3 hook=setup-project value="git"
          sdk=project-toolchain file=hooks/setup-project:13:3 hook=setup-project value="opensbi"
    rust: expected-and-controlled
      Review Priority: 10/100 (low)           [██░░░░░░░░░░░░░░░░░░]
      Risk:            10/100 (low)           [██░░░░░░░░░░░░░░░░░░]
      Assurance:       68/100 (strong)        [██████████████░░░░░░]
      Coverage:        100/100 (sufficient)   [████████████████████]
      Key Risks:
        risk.profile-environment-write: Shell environment profile is written during base setup [low, score=10, occurrences=1]
          sdk=rust file=sdk/hooks/setup-base:4:11 hook=setup-base value="/etc/profile.d/rust.sh"
```

This result indicates that Latra analyzed the available hook and command
evidence with sufficient coverage. The project SDK requires focused review
because it runs unknown commands as root and writes remotely obtained content
into the project. The Rust SDK is assessed separately as
`expected-and-controlled`, with one low-risk static environment configuration
write. These classifications describe the observed behavior and controls; they
do not guarantee that either SDK is safe.

The per-SDK `Key Risks` identifies what needs review and where it was detected. Its `sdk`,
`file`, and `hook` values can be passed directly to the inspection commands in
the next section.

### Inspect a hook or file

Use an SDK name and hook reported by the scan:

```bash
# command: latra hook <sdk> <hook>

latra hook rust setup-base
```

<details>
<summary>Example output</summary>

```text
apt-get update
apt-get install build-essential

cat <<EOF >> /etc/profile.d/rust.sh
PATH="$SDK/bin:\$PATH"
EOF

# Ensure hook is idempotent.
rm -f /home/workshop/.rustup/settings.toml

sudo -u workshop --login rustup default stable

# shellcheck source=/dev/null
. /etc/profile.d/rust.sh
rustup completions bash > /etc/bash_completion.d/rustup.sh
```

</details><br>

Display any detected SDK file by its reported path:

```bash
# command: latra file <sdk> <file>

latra file rust meta/sdk.yaml
```

<details>
<summary>Example output</summary>

```text
name: rust
version: 1.99.1
summary: The Rust toolchain installer
description: |
  This SDK provides rustup and the Rust toolchain for Rust development.
  Toolchains and Cargo configuration are persisted on the host across
  workshop updates. Automatically detects project toolchain requirements
  via rust-toolchain.toml.
base: ubuntu@24.04
architecture: arm64
website: https://github.com/canonical/rust-sdk
license: Apache-2.0 OR MIT
plugs:
  cargo-registry:
    interface: mount
    workshop-target: /home/workshop/.cargo/registry
sdkcraft-started-at: '2026-10-16T19:27:34.158961+00:00'
```

</details><br>

Replace `rust`, `setup-base`, and `meta/sdk.yaml` with values from your project report. Latra resolves the SDK from the current project's `.workshop/*.yaml` definitions, including its declared channel.

### Write a JSON report

Print the summary as JSON:

```bash
latra scan . --format json
```

Write the complete inventory and analysis details to a file:

```bash
latra scan . --format json --verbose --output latra-report.json
```

### Uninstall

```bash
./scripts/uninstall.sh
```

## User documentation

- [Documentation overview](docs/README.md) — documentation organized by
  audience and purpose.
- [Quick Start](docs/user/quickstart.md) — scan a project, inspect SDK content,
  and write a JSON report.
- [Command reference](docs/user/command-reference.md) — CLI commands, arguments,
  options, exit codes, and environment variables.
- [Understanding scan output](docs/user/report-output.md) — how to read each report
  section and use its SDK, hook, and file values for further investigation.

## Developer documentation

- [Analysis databases](docs/development/database/README.md) — command
  knowledge, capabilities, path semantics, and finding rules.
- [Development environment](docs/development/development.md) — build, test,
  and run Latra in Workshop.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating.

## Security

Do not report security vulnerabilities through public issues. See [SECURITY.md](SECURITY.md) for the reporting process.

## License

Latra is licensed under the [MIT License](LICENSE).

