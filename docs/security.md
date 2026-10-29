# Security model and limits

Owner: cop maintainers. Updated: 2026-10-28.

cop keeps credential values out of files, but it trusts your OS user. This page lists what cop protects, what it does not, and why.

## Trust boundary

cop trusts your OS user, cop's configuration, and the resolver executable you choose.
Any process running as your user can use the socket, change allowlists, and request values.
A project name groups authorizations. It does not prove that a process belongs to a repository.
cop does not defend against hostile processes under your user, or against root.

Status and configuration hold project names, account selectors, and references. Treat them as sensitive metadata. They never hold secret values.

## Memory

cop stores cached values in locked anonymous memory. If locking fails, the request fails and cop keeps nothing.
Clear, revoke, expiry, and shutdown overwrite cached bytes before cop frees the pages.
copd and `cop run` disable core dumps. cop has no profiling endpoint.

Some copies live briefly outside locked memory:

- `op` output, socket traffic, and JSON encoding
- the child process environment
- key parsing and signing
- snapshot encoding for replication
- SDK sessions and results inside worker processes

Go and the OS do not guarantee that these copies are erased or kept out of swap and hibernation.
cop never writes them to files on purpose, but it makes no claim of complete forensic erasure.
The child process and 1Password control their own memory and persistence. A child can print or save the value it receives.

## Resolvers

- **`op`:** cop captures stdout and discards stderr. Errors are fixed messages, so cop never forwards `op` output.
  cop removes ambient Connect and service-account credentials, so your explicit account choice holds.
- **SDK:** workers send values back through a private inherited pipe. cop discards worker stdout and stderr.
  Each account gets its own worker process, which enforces deadlines.
  A worker exits after nine idle minutes, on timeout, or when copd stops. cop sends no keepalive requests.
  1Password authorization is bound to the process. It expires after ten idle minutes or when the account locks.
  1Password decides whether to reuse an approval or prompt again, so cop cannot promise a prompt count.
  Desktop approval grants temporary account-wide access. cop still checks each project's exact allowlist.

Locking 1Password does not clear cop's cached values. Use `cop clear` or `cop revoke` to remove them before they expire.

The SDK path passed one live test with a single reference: resolution, cache reuse, delivery, clear, expiry, and restart.
Multi-account routing and the full range of desktop approval states remain unverified.

## Loads, cancellation, and expiry

- Clear and revoke cancel matching queued or active loads. A late result cannot refill the cache.
- If the CLI disconnects, cop still finishes the accepted load, unless clear, revoke, or the deadline stops it first.
- When an expired field is requested, cop clears the rest of that project's cache, then reloads every allowed field in the project.

## Home directory

`COP_HOME` must be an absolute path. It must be owned by your user ID, with no group or other permissions.
copd creates it with mode `0700` and the socket with mode `0600`. cop refuses a symlinked home.
A lock stops two daemons from using the same home. Configuration saves are atomic and synced to disk.

## Readable fields and environment names

cop refuses readable access to known private-key field names. Use an `ssh-sign` authorization for signing keys.
The check matches names only. It cannot find a private key stored under another name, so authorize only ordinary fields.

Environment names use uppercase letters, digits, and underscores, and cannot start with a digit.
cop reserves process-control names and the `OP_`, `COP_`, `REX_`, `LD_`, and `DYLD_` prefixes.

## Signing

The signing endpoint checks authorization for every signature.
It does not limit repositories, destinations, or spending.
`--sign` and `--auth` set Git options for the child to prevent mistakes. They do not limit what an SSH agent request can sign.
See the [signing cache design](signing-cache.md).

## Replication

Replication uses Tailscale encryption, direct Tailscale addresses, and stable node IDs from the Tailscale CLI.
Each side checks the other's node ID when a connection opens. A replica keeps its connection to topcop open and reuses that check, because WireGuard binds a connection to one node.
Topcop names each state with an HMAC token. The HMAC key is random and changes when copd starts, so the token reveals nothing about values.
cop does not create Tailscale identities, change ACLs, enable Funnel, or expose the local CLI over TCP.

Enrolling a peer trusts the whole machine, not one OS user on it.
Every member can admit peers and change the shared allowlist.
All keys replicate, including signing keys. On sync, topcop's allowlist replaces the joining machine's local allowlist.
The listener binds only to the Tailscale address. Without `--tailscale`, copd has no network listener.
While topcop is unavailable, a replica cannot change shared authorizations.
Tailscale admins, cop operators, and anyone with the same machine access sit inside this boundary.
To narrow it, limit the cop port to your machines with a Tailscale ACL.
