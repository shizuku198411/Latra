# Security Policy

## Supported versions

Latra has not published a stable release yet. Until versioned releases are available, security fixes are applied only to the latest code on the default branch. After the first release, this section will identify the supported release lines.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in public issues, discussions, or pull requests.

Use the repository's private vulnerability reporting feature under the **Security** tab to submit a report. If private reporting is unavailable, contact a maintainer privately and ask for an appropriate reporting channel without including sensitive details in a public message.

Include the following when possible:

- the affected version or commit;
- a description of the vulnerability and its impact;
- steps or a minimal fixture that reproduces the issue;
- any known mitigations or workarounds.

Maintainers will acknowledge the report, investigate it, and coordinate disclosure and remediation with the reporter. Response times may vary while the project is in its early development stage.

## Security scope

Security-sensitive areas include unsafe SDK archive or directory handling, path traversal, symlink escape, resource exhaustion, accidental hook execution, parser crashes, output injection, cache poisoning, and exposure of secrets found in analyzed content.

Static analysis cannot prove that an SDK is safe. A clean Latra result must not be treated as a guarantee that the SDK is benign.

