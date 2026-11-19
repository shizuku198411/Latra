# Suppression rules

**We recommend adding suppression rules from Explorer.** Review the highlighted command first. If the behavior is expected for your project, Explorer fills in the SDK, hook, risk ID, and applicable line so you only need to supply the reason. The finding stays visible as suppressed, and the assessment reflects the remaining risks.

## Add a rule in Explorer

1. Run `latra explorer` from the Workshop project root and open the SDK hook containing the finding.
2. Use `j` or `k` to select the risk label, then press `r` to review the command and proposed rule. Explorer can propose a line-specific rule when the finding is attributable to a single command in the hook.
3. Press `a`, enter why the behavior is expected, and press Enter. Explorer saves the rule to `.latra/suppression_rule.yaml` and rescans automatically.

To remove an exception, select its **Suppressed** label, press `r` to check its scope, then press `d`. This deletes the entire rule, including every line it covers.

## Write a rule by hand

Create `.latra/suppression_rule.yaml` in the Workshop project root. Use `version: 1` and a `rules` list. For example, suppose the SDK assessment identifies a service installation at line 29 and its activation at line 33. After reviewing both commands, you could record that decision as follows:

```yaml
version: 1
rules:
  - id: expected-development-service
    risk: risk.persistence-write
    sdk: dev-tools
    hook: setup-project
    line: [29, 33]
    reason: "This SDK installs and enables the user service required by the development environment."
```

| Field | What to enter |
| --- | --- |
| `id` | A unique name for your suppression rule. Latra uses it to identify which rule matched. |
| `risk` | The exact risk ID from the risk label or Key Risks, such as `risk.persistence-write`. |
| `sdk` | The SDK name shown in the assessment. |
| `hook` | The hook name shown for the finding, such as `setup-project`. |
| `line` | Optional list of positive, one-based **command start lines**. Use `[29]` for one command or `[29, 33]` for multiple lines. |
| `reason` | A non-empty explanation of why your project accepts this behavior. |

**Choose the scope deliberately.** With `line: [29]`, a command spanning lines 29–30 is matched by its start at 29. Other commands starting on that same line can also match the specified risk. Check these numbers after editing the hook. To accept the risk throughout the SDK hook, omit the `line` field entirely. That scope includes future matches in the same hook. An empty list (`line: []`) is invalid.

## Verify a manual edit

Run `latra scan --verbose` from the project root, or reopen Explorer. The verbose report shows each rule's status, reason, and match count. If a rule is unmatched, check the risk ID, SDK, hook, and command start lines. When multiple rules cover one finding, the first matching rule in file order applies.

If the YAML or a rule is invalid, Latra reports a warning and completes the scan with all suppression rules from that file ignored. Fix the reported error and scan again.
