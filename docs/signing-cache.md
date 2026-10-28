# Local signing cache

Owner: cop maintainers. Updated: 2026-10-27.
Status: implemented and tested locally on macOS; Linux cross-build verified.

Cop resolves an explicitly authorized private key through 1Password once, then signs from locked process memory until cache expiry.
Private keys leave 1Password for this purpose, but never leave cop through its client read or delivery interfaces.
The first implementation supports unencrypted Ed25519 SSH keys. RSA and encrypted key files are deferred.

## Authority and lifetime

An authorization binds project, account, exact reference, use `ssh-sign`, and the expected public key.
Readable credentials retain their separate use. No signing authorization permits a readable request.
The same account/reference pair cannot have both readable and signing authorizations in the configuration.
Resolution verifies that the private key matches the expected public identity before caching.
The existing serialized queue, cache limits, fixed TTL, clear, revoke, and restart behavior apply.
Expiry causes a new resolution through 1Password; signatures do not extend cache lifetime.
Revocation and clear prevent late resolver completion from restoring the key.
Each signature rechecks authorization and expiry while holding the cache lock.

## Interfaces

`allow`, `revoke`, and `request` accept `--use ssh-sign --public-key FILE`.
`cop ssh-run` wraps a child with a temporary protected SSH-agent socket for one authorized identity.
`--purpose sign` selects a commit-signing identity and `ssh-keygen`; Git SSH transport is disabled.
`--purpose auth` selects an authentication identity for SSH transport; Git commit signing is disabled.
The purpose is mandatory. Each invocation selects exactly one identity.
Both use `ssh-sign` storage and require separate allowlist entries when references or public keys differ.
These child Git defaults prevent accidental identity reuse; they are not cryptographic restrictions on agent payloads.
The wrapper uses the session project inside Rex, or an explicit standalone project outside Rex.
The command's project selection lasts for that wrapper's lifetime.
The proxy supports identity listing and signing only. Adding, removing, locking, and exporting keys are refused.
The service returns signatures and public metadata, never signing-key material.
Signing payloads and signature values are not logged or persisted by cop.
Git itself persists signatures in commits, as intended.

## Trust and portability

The local user and protected Unix socket remain the trust boundary; this does not isolate hostile same-user processes.
An authorized SSH signing client can use the key wherever it is trusted. Project selection does not enforce repository destinations.
Retained keys occupy locked anonymous memory; parsing and cryptographic operations create transient Go heap copies.
Cop clears owned private buffers where possible. Complete forensic erasure of library/runtime copies is not guaranteed.
The agent and signing code target macOS and Linux; desktop resolution requires a usable local 1Password installation.
Topcop replicates authorized signing material into enrolled cops' locked memory over Tailscale.
Replicas preserve the original expiry and enforce signing-only use. See the README for peer admission and offline revocation limits.

## Validation

Use generated synthetic keys to prove signature verification, public-key matching, refusal of reads, expiry, revoke, and restart.
Exercise OpenSSH agent requests and child Git configuration without a live vault.
Live acceptance uses only the operator's exact key reference and expected public key.
No test may fetch a guessed private-key reference or publish a test commit.

Generated-key tests verified signatures through the service, the OpenSSH agent protocol, and a real temporary Git commit.
They covered public-key mismatch, project isolation, export refusal, expiry, clear, revoke, restart, and unsupported agent operations.
A live test resolved the explicitly authorized GitHub key once, signed and verified a temporary commit, and authenticated a dry-run push.
Both signing and GitHub authentication reused the same cached resolution. No test commit was published.
Cross-compilation does not establish Linux runtime behavior. Remote loading and topcop recovery remain unimplemented.

## Provenance

Penfold was inspected read-only to understand its memory-only signing model. No implementation source was copied.
Use the supported Go SSH implementation in `golang.org/x/crypto/ssh` for parsing and agent protocol handling.
Its BSD-style license requires retaining the upstream notice when distributing binaries.
Cop's project license remains undecided.
