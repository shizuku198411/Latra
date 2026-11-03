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

## Unknown command summary

The report summary groups resolved `command-invocation` operations that do not appear in any embedded command, file, target, interpreter, or upload rule. Counts are reported by SDK and hook file, with deduplicated command names for each file.

“Unknown” means that Latra has no behavioral knowledge for the command. It does not mean that the executable is missing from the container, invalid, or dangerous. Common shell utilities and project-specific tools can therefore appear in this inventory until explicit knowledge is added. Commands whose names cannot be resolved statically are handled as dynamic execution and are not included in the unknown-command count.

Verbose output continues to include the original Operation, arguments, resolution, wrapper information, and source location. The summary does not replace or modify those details.
