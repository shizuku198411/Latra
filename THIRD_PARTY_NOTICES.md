# Third-party notices

Latra directly depends on the following open-source modules:

| Module | Version | License | Purpose |
|---|---:|---|---|
| `github.com/klauspost/compress` | v1.20.3 | BSD-3-Clause | Zstandard SDK archive decompression |
| `go.yaml.in/yaml/v3` | v3.0.6 | MIT and Apache-2.0 | YAML parsing |
| `mvdan.cc/sh/v3` | v3.14.1 | BSD-3-Clause | Bash syntax parsing |

The module graph and exact checksums are recorded in `go.mod` and `go.sum`. Transitive dependencies and notices must be reviewed whenever dependencies change and before each release.

