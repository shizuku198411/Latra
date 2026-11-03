# Command coverage

Latra's embedded rules cover the following command families. Rules use subcommands, options, operand roles, endpoint direction, path classes, or wrapper normalization where the command name alone would be ambiguous.

| Area | Commands |
| --- | --- |
| Remote transfer and sockets | `curl`, `wget`, `git`, `ssh`, `scp`, `nc`, `rsync`, `sftp`, `socat`, `ftp`, `lftp`, `telnet` |
| Interpreters and indirect execution | `bash`, `sh`, Python, Perl, Ruby, Node.js, AWK, PHP, Lua, `xargs`, `find` |
| Package and environment management | APT, Snap, pip, npm, npx, Yarn, pnpm, Cargo, RubyGems, Go, dpkg |
| Identity and execution context | `sudo`, `su`, `runuser`, `pkexec`, `env`, `timeout`, `nice`, `nohup`, `setsid`, `chroot`, `unshare`, `nsenter`, `setpriv` |
| Services and persistence | `systemctl`, `service`, `crontab`, `systemd-run`, `at`, `batch`, `atrm`, `update-rc.d` |
| Mount and storage | `mount`, `umount`, `rm`, `dd`, `mkfs`, `shred`, `truncate`, `wipefs`, `blkdiscard`, `fdisk`, `sfdisk`, `parted` |
| Access and accounts | `chmod`, `chown`, `setcap`, `chattr`, `setfacl`, user/group management, `passwd` |

## Important boundaries

- rsync distinguishes local copies, remote sources, and remote destinations. Delete modes and `--rsync-path` are reported separately.
- sftp connection behavior is reported, and batch files are inventoried as file reads. Transfer directions inside interactive or batch content are not inferred until that content is parsed.
- socat recognizes TCP, UDP, OpenSSL, and SOCKS address forms, local data addresses, and `EXEC:` or `SYSTEM:` process addresses. Unix-domain sockets remain outside `network-access`.
- Package managers distinguish explicit local sources from registry, module, or remote package targets. Lockfile-based installs with no explicit target are treated as network retrieval where applicable.
- pip build execution is reported for observable local projects, VCS sources, and source archives. A package name alone does not prove whether an index will return a wheel or source distribution.
- npm-family lifecycle execution is omitted when `--ignore-scripts` is present.
- Read-only forms such as service status, package listing, `passwd --status`, partition listing, wipefs inspection, and blkdiscard dry runs are excluded from modification rules.
- Wrapper commands retain the inner command as the normalized Operation. Wrapper-specific behavior is emitted as a separate capability with its own rule provenance.

These rules inventory observable behavior; they do not guarantee that a command succeeds or that a conditional behavior is exercised at runtime.

## Inspecting the embedded database

Use the `db` command to inspect the effective embedded knowledge without scanning a project:

```console
latra db
latra db capabilities
latra db capabilities network-access
latra db commands
latra db commands curl
latra db commands --capability network-access
latra db capabilities --command curl
```

The command supports `--format text|json`, `--output PATH|-`, and `--verbose`. List output is compact by default; a named detail query or `--verbose` includes association types and rule IDs. Associations distinguish direct, conditional, path-dependent, wrapper, and Operation-derived behavior.

### Choosing a database command

Choose the command based on what you already know and what you want to discover. A positional name requests details about that entity; a filter performs a reverse lookup from the other entity type.

| Command | Primary question | Output | When to use it |
| --- | --- | --- | --- |
| `latra db` | What is embedded in this Latra binary? | Database source, schema version, and total numbers of capabilities, commands, and rules. | Confirm the database bundled into a release or quickly inspect its size. |
| `latra db capabilities` | Which capabilities can Latra report? | All capability names and descriptions. | Explore Latra's behavior vocabulary before writing policy or interpreting a scan. |
| `latra db capabilities <capability>` | How is this capability produced? | One capability with associated commands, association types, and rule IDs. | Review the complete implementation and provenance of a known capability such as `network-access`. |
| `latra db capabilities --command <command>` | Which capabilities are associated with this command? | A capability-oriented reverse lookup containing every capability associated with the command. | Start from a command found in a hook and obtain a concise list of behaviors it may produce. |
| `latra db commands` | Which commands have embedded knowledge? | All known command names. | Check coverage or determine whether a command will appear in the unknown-command summary. |
| `latra db commands <command>` | Exactly how does Latra classify this command? | One command with its capabilities, association types, and rule IDs. | Investigate the detailed treatment of a known command, including direct, conditional, path-dependent, and wrapper associations. |
| `latra db commands --capability <capability>` | Which commands can produce this capability? | A command-oriented reverse lookup containing every associated command. | Audit the command coverage for a capability or identify commands relevant to a policy. |

The two similar command-oriented queries serve different levels of detail:

```console
latra db capabilities --command curl
```

This starts with `curl` but returns the related capability entries, which is useful when the question is “what behaviors can this command represent?”

```console
latra db commands curl
```

This returns the single `curl` command entry and its rule-level associations, which is useful when the question is “exactly which rules and association types apply to this command?”

Use `--verbose` on a list or reverse lookup when rule associations are needed. Named detail queries include those associations by default.

### Output options

| Option | Purpose |
| --- | --- |
| `--format text\|json` | Select human-readable text or stable JSON output. |
| `--output PATH`, `-o PATH` | Atomically write the result to a file instead of standard output. |
| `--verbose` | Include association types and rule IDs in list and reverse-lookup output. |

## Unknown command summary

The report summary groups resolved `command-invocation` operations that do not appear in any embedded command, file, target, interpreter, or upload rule. Counts are reported by SDK and hook file, with deduplicated command names for each file.

“Unknown” means that Latra has no behavioral knowledge for the command. It does not mean that the executable is missing from the container, invalid, or dangerous. Common shell utilities and project-specific tools can therefore appear in this inventory until explicit knowledge is added. Commands whose names cannot be resolved statically are handled as dynamic execution and are not included in the unknown-command count.

Verbose output continues to include the original Operation, arguments, resolution, wrapper information, and source location. The summary does not replace or modify those details.
