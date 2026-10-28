<p align="center"><img src="docs/cop.png" alt="cop badge: a steel shield with a keyhole" width="160"></p>

# cop

cop (cached one password) caches explicitly requested 1Password fields for local child processes.
It supports the `op` CLI and desktop Go SDK. 1Password owns authentication and biometric prompts.

## Local milestone

The local service and CLI work on macOS and Linux. Windows is not supported.
Projects start empty. You authorize exact account/reference pairs before requesting or delivering their values.
No approval keys, signed policies, TPM, Secure Enclave, companion app, or session harness is required.

The service serializes resolutions and exposes `queued`, `active`, `resolved`, and `failed` request metadata.
Identical concurrent requests within one project share a resolution.
Cache entries remain separate across projects and accounts.

Values live only in process memory. The service stores allowlists on disk, but never stores credential values or encrypted recovery copies.
Standalone and topcop restart preserve allowlists and reload every authorized key through 1Password.
Replicas reload from topcop instead.
Startup loads readable and signing-only keys through a serialized queue.
The SDK groups each project's keys by account and calls `ResolveAll` once per group, using one authenticated client. Use `cop status` to inspect active, queued, resolved, and failed loads.
The socket remains available during loading. Requests for the same key share its startup load.
Failed loads remain uncached; other loads continue. Clear and revoke cancel matching startup loads.

## Build and check

Install Go 1.26.10 or later, a C compiler, and Make.
The service uses Go and the supported Go SSH library. The daemon includes the SDK integration with pinned dependencies and requires CGO.
`make build` builds `cop` (CLI) and `copd` (daemon). Install both binaries together.
An internal `copd` subprocess loads the native library from the installed 1Password desktop app.

```sh
make check
make build
./bin/cop --help
```

`make check` runs formatting checks, vet, and race-enabled tests with a fake `op` executable.
Tests need no vault, credentials, network service, or running cop service.
Lifecycle and concurrency checks exercise both fake `op` and fake SDK workers.
The SDK module dependencies must be available for building and checking the worker.

## Install

`cop` starts `copd` from its own directory, so install both binaries together.
`make install` copies them to `~/.local/bin`. Set `PREFIX` to choose another location.

```sh
make install                  # or: make install PREFIX=/usr/local
cop version
```

Builds take their version from `git describe`; a plain `go build` reports `dev`.
Make sure the install directory is on your `PATH`.
Keep `copd` running under your service manager, such as a launchd agent or a systemd user unit.
Run `cop setup` afterwards to install the agent skill.

cop's socket lives at `COP_HOME/service.sock`. Unix sockets limit that path to about 100 bytes.
If `copd` reports "cannot bind local socket", choose a shorter `COP_HOME`.
`COP_HOME` must be a real directory, not a symlink, that only you can access.

## Agent skill

Run `cop setup` to install the bundled skill in existing Codex and Claude configuration directories.
It discovers default homes, recognized named profiles, `CODEX_HOME`, and `CLAUDE_CONFIG_DIR`.
Use `cop skill install --root /path/to/agent-home` for a specific profile.
`cop skill show` prints the bundled guide without contacting the daemon or 1Password.

The installer preserves symlinked skills and files changed outside cop's installer.
Run setup again after upgrading cop. Agent sessions may need to restart before they discover the new skill.
Setup changes no agent hooks, MCP registrations, Git settings, or credential authorizations.

## Standalone use

The following commands select a project explicitly outside Rex. Inside Rex, use the session defaults described below.

Install and authenticate 1Password CLI before using real references.
With desktop integration, 1Password handles its own approval prompts.
Terminal password entry is not supported inside the service; authenticate separately when desktop integration is unavailable.

Start the desktop SDK service in one terminal:

```sh
./bin/copd --resolver sdk
```

Enable SDK integration in the 1Password desktop app's Developer settings.
Select the desktop account name or UUID explicitly. Prefer a verified vault ID in references when display names differ.
The desktop approval grants temporary account-wide access; cop still enforces its exact project allowlist.
Locking 1Password does not clear values already cached by cop. Those values expire or can be cleared explicitly.

The `op` adapter remains the default for compatibility:

```sh
./bin/copd
```

In another terminal, create an empty project:

```sh
./bin/cop project create example
```

Set `ACCOUNT` and `REF` to your explicit account selector and exact field reference.
Copy the reference from 1Password. cop never enumerates vaults or discovers additional fields.

```sh
./bin/cop allow --project example --account "$ACCOUNT" --ref "$REF"
./bin/cop request --project example --account "$ACCOUNT" --ref "$REF"
./bin/cop status
```

`allow` changes local configuration without contacting 1Password.
`request` resolves and caches the value without printing it.
Watch `status` from another terminal while 1Password prompts; the active request identifies the project, account, and reference.

Deliver one cached field through a child environment variable:

```sh
./bin/cop run --project example --account "$ACCOUNT" --ref "$REF" \
  --env SERVICE_TOKEN -- your-command its-arguments
```

Each `run` delivers one reference. Additional references can be authorized incrementally.
The child replaces the CLI process, preserving terminal input, signals, and exit status.
The CLI never prints the value. The child controls its own output and can disclose its environment.

Clear a project's values while retaining its allowlist:

```sh
./bin/cop clear --project example
```

Remove one authorization and its cached value:

```sh
./bin/cop revoke --project example --account "$ACCOUNT" --ref "$REF"
```

Clear and revoke cancel matching queued or active resolutions. Late results cannot refill the cache.
A value already delivered to a process cannot be recalled.
Stop the service with Control-C. After restart, the service automatically resolves saved authorizations through the selected adapter again.

## Rex session context

Inside a Rex terminal, inspect context without contacting cop's service or 1Password:

```sh
./bin/cop context
```

The output contains only `mode`, `project`, `session_id`, `server_endpoint`, `server_host_id`, and `execution_host_id`.
The project equals the current Rex session label exactly. All panes in that session use the same project.

Create that project and use its default context:

```sh
./bin/cop project create
./bin/cop allow --account "$ACCOUNT" --ref "$REF"
./bin/cop request --account "$ACCOUNT" --ref "$REF"
./bin/cop run --account "$ACCOUNT" --ref "$REF" --env SERVICE_TOKEN -- your-command
./bin/cop clear
```

`revoke` also defaults to the session project.
An explicit project, including the name in `project create`, must match the session label.
A different `--project` is refused before contacting the cop service or fetching a secret.
Projects still start empty; discovery grants no reference access.

Discovery uses the inherited `REX_SESSION`, `REX_SERVER`, and `REX_BLOCK` values:

| Metadata | Source and meaning |
| --- | --- |
| Project | Exact label from `rex session inspect "$REX_SESSION" --json` |
| Session ID | Full stable Rex session ID, checked against lookup results |
| Server host ID | `host_id` from `rex whoami --json`; identifies the server's machine/account file environment |
| Execution host ID | `block.host_id` from inspection of the inherited block within the supplied session |
| Server endpoint | Connection address reported by Rex; not a host identity |

Rex defines equal host IDs as servers that see the same files, normally the same machine and operating-system account.
The server host and execution host can differ for remote panes. The viewing client's machine is never used.
The block ID helps locate the execution host; it is not returned as project scope or sent to cop's service.
The execution host describes Rex's block placement, not proof that an inherited environment still matches the calling process.

Every project operation discovers context again. No focused session, active tab, or viewing client supplies a fallback.
A renamed session selects its new label on the next command; existing project allowlists are not renamed or migrated.
Two sessions with the same label select the same existing cop project. Their stable session IDs remain distinct metadata.
Labels must satisfy cop's project-name rules: 1–64 ASCII letters, digits, underscores, or hyphens, starting with a letter or digit.
Invalid labels are refused without trimming, slug conversion, or case changes.

All three context variables are required when any is present, including empty values.
Missing variables, stale IDs, missing host IDs, conflicting responses, and failed lookups cause errors, even with an explicit project.
The block variable is required to distinguish the execution host from a potentially remote server.
Rex queries disable server autostart, ignore `REX_CLIENT`, and have bounded duration and output.
The cop adapter invokes the installed Rex CLI; it adds no host transport or network listener.

When all three variables are absent, `cop context` reports `standalone` without invoking Rex.
`cop context --project NAME` can inspect an explicit standalone project selection without a running cop service.
Ordinary standalone key operations continue to require an explicit project.
`copd` and the service-wide `status` command remain independent of Rex discovery.

Environment variables and same-user CLI lookups provide context, not tamper-proof authentication.
These IDs add no host authorization, cryptographic keys, session credentials, or changes to service ownership.
`COP_HOME` still selects the local service. Remote pane metadata never redirects secrets or changes cache ownership.

## Signing-only cache

Cop can cache unencrypted Ed25519 signing keys in locked memory and serve signatures without returning the private key.
The key leaves 1Password during resolution. Git and SSH receive signatures, not private-key bytes.
Signing keys share the resolution queue and TTL rules with readable credentials, but have distinct authorization and cache identities.

Set `ACCOUNT` and `SIGNING_REF` to the explicit account and exact private-key field reference.
Set `PUBLIC_KEY` to a file containing the corresponding public SSH key.
Inside Rex, the session label supplies the project. Outside Rex, add `--project NAME` to each command.

```sh
./bin/cop allow --account "$ACCOUNT" --ref "$SIGNING_REF" --use ssh-sign --public-key "$PUBLIC_KEY"
./bin/cop request --account "$ACCOUNT" --ref "$SIGNING_REF" --use ssh-sign --public-key "$PUBLIC_KEY"
./bin/cop ssh-run --purpose sign --account "$ACCOUNT" --ref "$SIGNING_REF" --public-key "$PUBLIC_KEY" -- git commit -m "Change"
./bin/cop ssh-run --purpose auth --account "$AUTH_ACCOUNT" --ref "$AUTH_REF" --public-key "$AUTH_PUBLIC_KEY" -- git push --dry-run origin main
```

Authorize the authentication identity separately with its exact account, reference, and public key, using `allow --use ssh-sign`.
Both identities use signing-only storage, but commit signing and authentication can select different keys.
`--purpose` is required. `sign` configures commit signing and disables Git SSH transport; `auth` configures transport and disables Git signing.
These child Git settings prevent accidental reuse; they do not restrict the cryptographic purpose of arbitrary agent requests.

`ssh-run` prewarms the key and creates a private temporary agent socket for its child.
Child-only Git overrides select cop's agent, `ssh-keygen`, and the expected public key. Global Git configuration is unchanged.
The wrapper uses `ssh -F /dev/null`, so personal SSH aliases, proxies, and IdentityFile settings do not apply.
Known-host verification remains enabled. Use a direct SSH Git remote, not an HTTPS remote, for this transport.
The wrapper writes only a temporary public key file; private keys never enter files or environment variables.
The socket closes when the child exits. Clear, revoke, expiry, and service restart invalidate cached signing material.
A later request can resolve again under the remaining allowlist, subject to 1Password authentication.
To revoke a signing authorization, use the same account, reference, use, and public-key file with `revoke`.

The signature endpoint verifies authority for each signature. It does not enforce repository names, destinations, or spending limits.
The same-user trust boundary still applies. Key parsing and signing create transient heap copies beyond the locked cache.
RSA and encrypted private-key files are not implemented.
See the [signing-cache specification](docs/signing-cache.md).

## Configuration and limits

The default home is `cop` under Go's user configuration directory.
Set `COP_HOME` to an absolute private directory to use another home; use the same setting for service and CLI.
The home must belong to the current user with no group or other permissions.
The service creates the home with mode `0700` and the Unix socket with mode `0600`.

Use CLI commands to change allowlists while the service runs.
The service loads `projects.json` at startup; external edits require a restart.
Configuration saves are atomic and synchronized to disk. A save failure stops further access until restart.
A lock prevents two services from using the same home; restart removes a stale socket after acquiring that lock.

| Setting | Default | Bound |
| --- | --- | --- |
| `copd --ttl` | `168h` (seven days) | Positive Go duration; hits do not extend expiry |
| `copd --op-timeout` | `2m` | Positive, at most `5m`; startup and refill loads count from activation; ordinary requests include queue time |
| `copd --op` | `op` from PATH | Trusted executable; selected once at startup |
| `copd --resolver` | `op` | `op`, `sdk`, or `none` for a replica without a local resolver |
| `copd --tailscale` | Disabled | Enable replication on the local Tailscale IPv4 address |
| `copd --port` | `8787` | Tailscale listener port |
| Pending resolutions | None | 64 distinct ordinary requests; startup and refills queue saved authorizations |
| Cache entries | None | 128 entries, at most 64 KiB each |
| Request history | Empty on restart | Last 128 records plus unfinished startup and refill loads, metadata only |

Expired values are refused immediately and erased by the next idle cleanup tick, within one second.
The lifetime uses Go's monotonic clock. A cache hit never contacts 1Password.
Set a different lifetime with `copd --ttl 336h` (fourteen days).
Expiry alone does not contact 1Password. The next request for an expired key refills every authorized key in that project.
The refill clears that project's remaining cached values and serializes resolutions through 1Password.
Other projects retain their own cached or expired state until requested. Concurrent requests share the refill jobs.
Inside Rex, the project equals the session label; all panes share that project. Standalone usage selects the project explicitly.
1Password controls authentication and prompts; a refill does not force a new biometric prompt when 1Password still grants access.
Failed loads remain uncached and can be retried. Clear and revoke cancel matching refill jobs.
An offline hit works until expiry; a miss still needs normal 1Password access.
Disconnected CLI requests remain accepted work until completion, invalidation, or their original deadline.

References match exactly, including their spelling. Query parameters and wildcard fields are unsupported.
Use stable account, vault, and item IDs when available to avoid renamed or ambiguous selectors.
Known private-key field names are refused for readable access. Signing-only access uses a separate `ssh-sign` authorization.
This field-name check cannot detect private keys stored under other names; authorize only ordinary readable fields.

Environment names must use uppercase letters, digits, and underscores, without a leading digit.
Process-control names and the `OP_`, `COP_`, `REX_`, `LD_`, and `DYLD_` prefixes are reserved.
The adapter removes ambient Connect and service-account credentials so explicit personal account selection remains meaningful.

## Trust and memory limits

cop trusts the local user, local configuration, and selected resolver executable.
Any process running as that user can edit allowlists or access the socket and request values.
Project names scope configuration; they do not prove a process's repository membership.
This milestone does not isolate hostile processes belonging to the same user or protect against root.

Cached values occupy locked anonymous memory. If memory locking fails, resolution fails without retaining the value.
Clear, revoke, expiry, and shutdown overwrite cached bytes before releasing those pages.
The service and delivery CLI disable core dumps and expose no profiling endpoint.

Subprocess output, Unix socket traffic, JSON encoding, and child environments create temporary copies outside the locked cache.
Go and the operating system do not guarantee that every temporary copy is erased or protected from swap and hibernation.
cop never intentionally writes those copies to files. This is not a claim of complete forensic erasure.
The child and 1Password have their own memory and persistence behavior.

Status and configuration contain project names, account selectors, and references. These are sensitive metadata, not secret values.
`op` stdout is captured; stderr is discarded. Failures produce fixed messages without forwarding subprocess output.
The SDK path passed a live test with one explicitly authorized reference: resolution, cache reuse, child delivery, clear, expiry, and restart.
The test printed no value, length, or hash. Multi-account routing and all desktop approval states remain unverified.
SDK failures use fixed messages. Worker stdout and stderr are discarded; values travel through a private inherited pipe.
Ordinary misses, startup loads, and expiry refills reuse an account-bound worker across project batches.
A refill worker retains one SDK client per account and performs one bulk resolution per project batch.
Workers exit after nine idle minutes, on timeout, or when the daemon stops. Cop sends no authorization keepalive requests.
1Password can reuse an existing authorization or request approval. Cop cannot guarantee a biometric prompt count.
Separate workers isolate account state and enforce deadlines at the process level.
1Password authorization is process-bound and expires after ten idle minutes or when the account locks.
SDK sessions and temporary result copies remain in worker memory; the memory-erasure limitations above also apply to these workers.

## Tailscale replication

Start `copd --resolver sdk --tailscale` on the machine with desktop 1Password access.
Start `copd --resolver none --tailscale` on a replica that needs no local vault access.
Both machines need a running Tailscale client and permission to reach the configured TCP port.
The listener binds only to the local Tailscale address. Standalone `copd` has no network listener.

Set `TOPCOP` and `REPLICA` to their exact Tailscale IP addresses with port, such as `100.64.0.10:8787`.
On the chosen topcop, explicitly admit the replica:

```sh
cop connect --topcop local "$REPLICA"
```

On the replica, connect back to inherit the selected topcop:

```sh
cop connect "$TOPCOP"
cop status
```

For each additional cop, run `cop connect "$NEW_COP"` on any existing member.
Then run `cop connect "$EXISTING_COP"` on the new cop. The new cop inherits the group's topcop.
Admission requires a local CLI action on an existing member; sharing the tailnet alone grants no credential access.
Every enrolled member can admit peers and change the shared project allowlist.
Groups with conflicting topcops are refused. Automatic election, failover, and group merging are not implemented.

All project authorizations and cached keys replicate by default, including signing-only keys.
Topcop's allowlist replaces the joining cop's local allowlist. Treat joining as adoption of the group's credential authority.
Only metadata is stored in `network.json` and `projects.json`; replicated values remain in locked memory.
Replicas pull snapshots every two seconds. Expiry never extends during transfer.
Requests for missing keys and project mutations go to topcop. Expiry-triggered refills remain project-scoped.
Signing happens locally from the replicated key, while read and export commands still refuse signing-only identities.

A disconnected replica can use its existing unexpired cache. It cannot refill or change shared authorizations until topcop returns.
Cached delivery, signing, and status on a replica do not wait for network calls to topcop.
Clear and revoke take effect on other replicas after their next successful sync.
An offline replica can retain previously authorized keys until their original expiry; immediate offline revocation is impossible.
Restarted replicas recover topology and authorizations, then refill memory from topcop without invoking a local resolver.
Restarted topcop reloads authorized keys through 1Password. No secret recovery copies exist on disk.

Transport uses Tailscale encryption, direct Tailscale addresses, and stable node IDs checked through the installed Tailscale CLI.
Cop does not create Tailscale identities, modify ACLs, enable Funnel, or expose the local CLI API over TCP.
Peer access is machine-level trust, not isolation between operating-system users on an enrolled machine.
Tailscale administrators, trusted cop operators, and processes with equivalent machine access remain within that trust boundary.
Snapshot encoding and transport create temporary heap copies, subject to the memory limits described above.

`cop serve` remains a compatibility alias that executes the adjacent `copd` binary.
The SDK subprocess is an internal daemon mode, not a third installed command.

## Later work and licensing

See the [scope and implementation plan](docs/extraction-plan.md).
The [desktop Go SDK evaluation](docs/desktop-sdk-evaluation.md) records the probe, source findings, and subsequent cache integration.
Tailscale replication is implemented. Automatic topcop failover, action/spending enforcement, and native UI remain deferred.
Varlock support is outside scope.

This milestone is independent new code. No reference source, fixtures, or artwork were copied.
The project license is still pending. Any future source reuse needs recorded permission and compatible licensing.

The adapter uses documented [`op read`](https://developer.1password.com/docs/cli/reference/commands/read/) and
[global account/cache flags](https://developer.1password.com/docs/cli/reference/).
