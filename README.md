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
Restart preserves allowlists and starts with an empty cache.

## Build and check

Install Go 1.26.10 or later, a C compiler, and Make.
The service uses Go and the supported Go SSH library. The separate SDK worker has pinned dependencies and requires CGO.
`make build` builds both binaries; keep `cop-sdk-worker` beside `cop` when installing.
The SDK worker loads the native library from the installed 1Password desktop app.

```sh
make check
make build
./bin/cop --help
```

`make check` runs formatting checks, vet, and race-enabled tests with a fake `op` executable.
Tests need no vault, credentials, network service, or running cop service.
Lifecycle and concurrency checks exercise both fake `op` and fake SDK workers.
The SDK module dependencies must be available for building and checking the worker.

## Standalone use

The following commands select a project explicitly outside Rex. Inside Rex, use the session defaults described below.

Install and authenticate 1Password CLI before using real references.
With desktop integration, 1Password handles its own approval prompts.
Terminal password entry is not supported inside the service; authenticate separately when desktop integration is unavailable.

Start the desktop SDK service in one terminal:

```sh
./bin/cop serve --resolver sdk
```

Enable SDK integration in the 1Password desktop app's Developer settings.
Select the desktop account name or UUID explicitly. Prefer a verified vault ID in references when display names differ.
The desktop approval grants temporary account-wide access; cop still enforces its exact project allowlist.
Locking 1Password does not clear values already cached by cop. Those values expire or can be cleared explicitly.

The `op` adapter remains the default for compatibility:

```sh
./bin/cop serve
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
Stop the service with Control-C. After restart, the next authorized request resolves through the selected adapter again.

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
`serve` and the service-wide `status` command remain independent of Rex discovery.

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
RSA, encrypted private-key files, and topcop distribution are not implemented.
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
| `serve --ttl` | `5m` | Positive, at most `1h`; hits do not extend expiry |
| `serve --op-timeout` | `2m` | Positive, at most `5m`; includes queue time |
| `serve --op` | `op` from PATH | Trusted executable; selected once at startup |
| `serve --resolver` | `op` | `op` or `sdk` |
| `serve --sdk-worker` | `cop-sdk-worker` beside `cop` | Trusted executable; selected once at startup |
| Pending resolutions | None | 64 distinct requests |
| Cache entries | None | 128 entries, at most 64 KiB each |
| Request history | Empty on restart | Last 128 records, metadata only |

Expired values are refused immediately and erased by the next idle cleanup tick, within one second.
The lifetime uses Go's monotonic clock. A cache hit never contacts 1Password.
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
Each miss starts a separate SDK worker, avoiding shared account state and allowing process-level deadline enforcement.

## Later work and licensing

See the [scope and implementation plan](docs/extraction-plan.md).
The [desktop Go SDK evaluation](docs/desktop-sdk-evaluation.md) records the probe, source findings, and subsequent cache integration.
Networking, multi-host recovery, action/spending enforcement, and native UI are deferred.
Varlock support is outside scope.

This milestone is independent new code. No reference source, fixtures, or artwork were copied.
The project license is still pending. Any future source reuse needs recorded permission and compatible licensing.

The adapter uses documented [`op read`](https://developer.1password.com/docs/cli/reference/commands/read/) and
[global account/cache flags](https://developer.1password.com/docs/cli/reference/).
