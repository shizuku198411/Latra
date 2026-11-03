<p>
  <img src="./assets/latra_logo.png" alt="Pluvora Logo" width="250">
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

Latra is in the pre-implementation design and fixture-building stage. It is not yet available for production use. Quick Start and installation instructions will be added with the first usable release.

Latra is an independent project and is not affiliated with or endorsed by Canonical Ltd.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating.

## Security

Do not report security vulnerabilities through public issues. See [SECURITY.md](SECURITY.md) for the reporting process.

## License

Latra is licensed under the [MIT License](LICENSE).

