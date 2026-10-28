---
name: cop
description: Use cop for cached 1Password credentials, Git commit signing, SSH push authentication, and cop replication diagnostics. Apply when cop is configured or explicitly requested.
metadata:
  generated-by: cop
---

# Cop

`cop` is the CLI. `copd` owns the memory-only cache and talks to 1Password or the selected topcop.
Plain Git and SSH commands do not automatically use cop.

## Select context and identity

Run `cop context` to inspect project selection and `cop status` to inspect saved authorizations, cache metadata, and resolution failures.
Inside Rex, the project must equal the session label. All panes share that project.
Outside Rex, add `--project NAME` to project commands.
Do not unset Rex variables to bypass a project mismatch. Resolve the intended session or project first.

Use the exact account and reference already authorized for the project.
If a new reference is needed, obtain it from the user or maintained project configuration; do not enumerate or guess vault contents.
A skill does not authorize adding credentials, enrolling machines, pushing code, or expanding the task.

For an authorized new project or reference:

```sh
cop project create
cop allow --account "$ACCOUNT" --ref "$REF"
cop request --account "$ACCOUNT" --ref "$REF"
```

Projects start empty. `allow` saves authorization metadata; `request` fills the cache without printing the value.
For ordinary readable credentials, deliver only to the intended child:

```sh
cop run --account "$ACCOUNT" --ref "$REF" --env SERVICE_TOKEN -- your-command
```

Do not deliver credentials to echo, debugging output, persistent files, or unrelated processes.

## Git signing and SSH authentication

Commit signing and push authentication may use different keys. Select each identity explicitly.
`PUBLIC_KEY` names a file containing the matching public SSH key, never a private-key file.
Use `cop status` or maintained configuration to find the authorized public identity.

```sh
cop allow --account "$ACCOUNT" --ref "$SIGN_REF" --use ssh-sign --public-key "$SIGN_PUBLIC_KEY"
cop ssh-run --sign --account "$ACCOUNT" --ref "$SIGN_REF" --public-key "$SIGN_PUBLIC_KEY" -- git commit -m "Change"

cop allow --account "$ACCOUNT" --ref "$AUTH_REF" --use ssh-sign --public-key "$AUTH_PUBLIC_KEY"
cop ssh-run --auth --account "$ACCOUNT" --ref "$AUTH_REF" --public-key "$AUTH_PUBLIC_KEY" -- git push origin main
```

Run `allow` only when adding that exact authorization is within the user's task.
For existing authorizations, use `ssh-run` directly.
`--sign` configures commit signing and disables Git SSH transport. `--auth` configures SSH transport and refuses commit signing.
Use separate invocations for commit and push; do not combine them in one invocation.
A plain `git push` can use another SSH agent and trigger unrelated 1Password key prompts.
The wrapper ignores personal SSH configuration. Use a direct SSH remote, not an SSH alias or HTTPS URL.
Private signing keys stay behind cop's signing interface; read and export commands refuse them.

## Approval, expiry, and failures

1Password controls account authorization and biometric prompts. Cop does not bypass them.
The SDK reuses an account-bound worker across project batches and ordinary misses; idle workers exit after nine minutes.
Startup and expired-project refills batch keys once per account per project.
A worker timeout or restart can require fresh approval. Do not repeatedly retry a failed approval.
Inspect `cop status`, report the failed project/account and reason, and wait when user action is needed.

Keys expire after seven days by default; `copd --ttl DURATION` configures the lifetime.
A request for an expired key refills that project's authorized keys. Other projects retain their own cache state.
`cop clear` removes a project's cache; `cop revoke --account "$ACCOUNT" --ref "$REF"` removes that authorization.
For signing authorizations, include the matching `--use ssh-sign --public-key FILE` with `revoke`.
Restarting the daemon clears memory and reloads authorized keys. Do not restart merely to inspect status.

## Replication

`cop status` identifies this node, topcop, connection state, and the last sync.
Stale cache entries cannot be refreshed while topcop is unreachable; unexpired entries can work offline.
Replicas preserve original expiry. Clear and revoke reach disconnected replicas only after reconnection.

For an authorized initial connection, run `cop connect --topcop local PEER_IP:8787` on the selected topcop.
Then run `cop connect TOPCOP_IP:8787` on the joining cop.
For another member, run `cop connect NEW_IP:8787` on an existing member, then connect back from the new cop.
Joining cops inherit the existing topcop and adopt its project allowlist. All project keys replicate by default.
Enrollment trusts the machine and permits the member to admit peers and change shared authorizations.
Do not enroll a machine or change authority just to repair a failed Git operation.
