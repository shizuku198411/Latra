# Finding fixtures

Each directory is an independently valid Workshop project SDK fixture for one embedded Latra finding rule. The directory and SDK name are the finding ID with dots replaced by hyphens.

The regression test loads every SDK, parses its hooks, applies any external resolution state required by the rule, and verifies that the corresponding finding is emitted. It also compares the fixture table with the complete embedded finding database, so a new finding rule requires a new fixture.

Hooks are static-analysis inputs and must not be executed on a host system. Several fixtures intentionally contain destructive-looking, malformed, or data-exfiltration shell code.

Store-only and resolver-only findings still use a valid SDK directory. Their Store source, digest, unresolved state, or resource-limit diagnostic is supplied by the test because those properties do not originate from project SDK files.
