<p align="center"><img src="docs/cop.png" alt="cop badge: a steel shield with a keyhole" width="160"></p>

# cop

cop (cached one password) caches 1Password fields in memory and hands them to the programs you choose.
You allow each account and field reference explicitly. Cached requests reuse the value without contacting 1Password.

**cop never writes secrets to disk.** It holds values only in locked memory. It saves the list of allowed references, never the values, and keeps no encrypted backup. When copd stops, the values are gone. See [Security](#security) for the swap caveat.

cop also signs Git commits and authenticates SSH connections. Git and SSH receive signatures, not private keys.

cop is built for [Rex](#rex-sessions). In Rex, cop selects the project from the session label, so you never type a project name.
Panes with the same label share that project's allowed fields.

It runs on macOS and Linux. It does not support Windows.

## How it works

- `copd` is the daemon. It holds values in locked memory and never writes them to files.
- `cop` is the CLI. It talks to `copd` over a Unix socket.
- A **project** is a named list of fields you allow. Every project starts empty.
- cop reads fields through the `op` CLI or the 1Password desktop SDK. 1Password still handles sign-in and biometric prompts.
- Cached values expire after seven days. When an expired field is requested, cop reloads every field in that project.

## Install

You need Go 1.26.10 or later, a C compiler, and Make. `copd` uses cgo for the desktop SDK.

```sh
make check      # formatting, vet, and race tests; needs no vault or network
make install    # installs cop and copd to ~/.local/bin
cop version
```

Set `PREFIX` to install somewhere else, such as `make install PREFIX=/usr/local`.
Install `cop` and `copd` in the same directory, because `cop` starts `copd` from its own directory.

To install the bundled agent skill for Codex and Claude, run `cop setup`. Run it again after each upgrade.
`cop skill show` prints the skill.

## Start the daemon

Pick how cop reads from 1Password:

- **Desktop SDK:** turn on SDK integration in the 1Password app's Developer settings. Then run `copd --resolver sdk`.
- **`op` CLI:** install the 1Password CLI and sign in first, because `copd` cannot answer password prompts. Then run `copd`.

Keep `copd` running under a service manager, such as a launchd agent or a systemd user unit.
Desktop approval gives cop temporary access to the whole account. cop still checks each project's allowlist.

In the examples below, set `ACCOUNT` to your 1Password account and `REF` to an exact field reference copied from 1Password.

## Rex sessions

In a Rex terminal, cop uses the session label as the project. You can leave out `--project`.

```sh
cop context                                    # shows the session's project
cop project create
cop allow   --account "$ACCOUNT" --ref "$REF"
cop run     --account "$ACCOUNT" --ref "$REF" --env SERVICE_TOKEN -- your-command
```

- All panes with the same session label share one project.
- The CLI refuses an explicit `--project` that differs from the session label.
- cop checks the session on every project command. It never guesses from the focused tab or window.
- If you rename a session, the next command uses the new label. The old project stays as it was.

The label is a default selection, not isolation from other processes running as you.
See [Rex session context](docs/rex-context.md) for how cop reads the session.

## Without Rex

Outside Rex, pass `--project` to every project command:

```sh
cop project create example
cop allow   --project example --account "$ACCOUNT" --ref "$REF"
cop request --project example --account "$ACCOUNT" --ref "$REF"
cop run     --project example --account "$ACCOUNT" --ref "$REF" --env SERVICE_TOKEN -- your-command
```

- `allow` adds the field to the project. It does not contact 1Password.
- `request` loads the field into the cache. It never prints the value.
- `run` starts `your-command` with the value in `SERVICE_TOKEN`. Each `run` delivers one field.

## Other commands

| Command | What it does |
| --- | --- |
| `cop status` | Shows projects, cached fields, and loads in progress. Never shows values. |
| `cop clear` | Empties the project's cache and keeps its allowlist. |
| `cop revoke --account A --ref R` | Removes one field and its cached value. |
| `cop context` | Shows which project cop would use here. |

Locking 1Password does not clear cop's cache. Use `clear` or `revoke` to remove values before they expire.
cop cannot recall a value it has already given to a process. The process can print or save it.
On restart, a standalone daemon or topcop reloads allowed fields through 1Password. A replica reloads from topcop instead.

## Signing keys

cop can hold an unencrypted Ed25519 SSH key and sign with it. Git and SSH get signatures, never the key.
Set `SIGN_REF` to the key's private-key field and `SIGN_PUB` to a file with its public key.
Outside Rex, add `--project NAME` to each command.

```sh
cop allow --account "$ACCOUNT" --ref "$SIGN_REF" --use ssh-sign --public-key "$SIGN_PUB"
cop ssh-run --sign --account "$ACCOUNT" --ref "$SIGN_REF" --public-key "$SIGN_PUB" -- git commit -m "Change"
cop ssh-run --auth --account "$ACCOUNT" --ref "$AUTH_REF" --public-key "$AUTH_PUB" -- git push --dry-run origin main
```

- `--sign` sets up commit signing for the child and turns off Git's SSH transport.
- `--auth` sets up SSH transport and turns off signing. Allow the authentication key separately.
- `ssh-run` gives the child a private agent socket that closes when the child exits. It leaves your global Git settings alone.
- It runs `ssh -F /dev/null`, so your SSH config and aliases do not apply. Use a direct SSH remote, not HTTPS. Host key checks stay on.
- `cop run` and other read commands refuse signing keys.

To revoke a signing key, pass the same account, reference, `--use ssh-sign`, and `--public-key` file to `cop revoke`.
RSA and encrypted key files are not supported. See the [signing cache design](docs/signing-cache.md).

## Settings

`COP_HOME` holds cop's state. It defaults to `cop` in your user config directory, such as `~/Library/Application Support/cop` on macOS.
It must be an absolute path to a real directory that you own, with no group or other permissions. Use the same `COP_HOME` for `cop` and `copd`.
The socket is `COP_HOME/service.sock`. Unix limits socket paths to about 100 bytes, so keep `COP_HOME` short.

| `copd` flag | Default | Notes |
| --- | --- | --- |
| `--resolver` | `op` | `op`, `sdk`, or `none` for a replica |
| `--ttl` | `168h` | Cache lifetime. Using a value does not extend it. |
| `--op-timeout` | `2m` | At most `5m`. Ordinary requests count queue time. Startup and refill loads count from when loading starts. |
| `--op` | `op` on `PATH` | The `op` executable |
| `--tailscale` | off | Turns on replication |
| `--port` | `8787` | Replication port |

The cache holds up to 128 fields of 64 KiB each. Ordinary requests have a 64-job limit. Startup and refill loads queue separately.
References must match exactly. Query parameters and wildcards are not supported. Use account, vault, and item IDs where you can, because names can change.
Change allowlists with the CLI. If you edit `projects.json` by hand, restart `copd`.

## Replication over Tailscale

Several machines can share one cache. One machine, the **topcop**, talks to 1Password. The others are **replicas** that copy from it.

On the machine with 1Password:

```sh
copd --resolver sdk --tailscale
cop connect --topcop local REPLICA_IP:8787
```

On the replica:

```sh
copd --resolver none --tailscale
cop connect TOPCOP_IP:8787
```

To add another machine, run `cop connect NEW_IP:8787` on any member, then `cop connect MEMBER_IP:8787` on the new machine.

- The listener binds only to the Tailscale address. Without `--tailscale`, `copd` has no network listener.
- Replicas copy the cache every two seconds. Copying never extends expiry.
- A replica signs locally and serves cached fields while topcop is offline. Requests for fields it does not have go to topcop.
- While topcop is offline, a replica cannot load new fields or change shared allowlists.
- Clear and revoke reach a replica on its next sync. An offline replica keeps its keys until they expire.
- On sync, topcop's allowlist replaces the joining machine's allowlist. All keys replicate, including signing keys.
- Every member can admit machines and change shared allowlists.
- cop refuses to merge groups with different topcops. It has no automatic failover.

Being on the same tailnet grants nothing. A member must run `cop connect` first.

## Security

cop trusts your OS user. Any process running as you can use the socket and read values.
Cached values use locked memory. cop does not write values to files on purpose, but temporary copies can reach swap or hibernation files.
See [Security model and limits](docs/security.md) before you rely on cop.

## More

- [Scope and plan](docs/extraction-plan.md)
- [Desktop SDK evaluation](docs/desktop-sdk-evaluation.md)
- [`op read` reference](https://developer.1password.com/docs/cli/reference/commands/read/)

cop is released under the [MIT License](LICENSE).
