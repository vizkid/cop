# Local caching first

Owner: cop maintainers. Updated: 2026-10-27.
Status: local scope ratified; implementation and deferred work are distinguished below.

The local milestone replaces the earlier signed-policy extraction proposal.
Trusted local configuration is sufficient for local caching. 1Password owns authentication and biometric approval.

## Ratified local scope

- Support `op` users, without Varlock or a generic provider framework.
- Create empty projects and authorize exact requested account/reference pairs incrementally.
- Cache values in service memory with configurable expiry, defaulting to seven days, and explicit invalidation.
- Serialize interactive resolutions so every prompt has attributable request metadata.
- Expose queued, active, resolved, and failed states without secret values.
- Deliver values only through an explicitly requested child environment.
- Use a protected local Unix socket, with an explicit same-user trust boundary.

Local caching requires no custom approval keys, signed policies, TPM, Secure Enclave, or companion application.
It requires no Penfold, Rex, provider-account harness, or repository role model.

## Implemented

| Component | Behavior |
| --- | --- |
| CLI | Create projects, allow/revoke exact references, request, run, clear, and inspect status |
| Optional Rex context | Session-label project defaults and separate server/execution host metadata; no new authorization or service routing |
| Local configuration | Metadata-only allowlists, atomic durable writes, private files, and one service writer |
| Resolution queue | One active resolver subprocess; coalesced requests; bounded queue, deadlines, and history |
| Adapters | Default `op read`, or opt-in desktop SDK worker; exact account/reference selection and bounded secret delivery |
| Cache | Project/account/reference keys, locked anonymous memory, fixed expiry, cleanup, and no persistent values |
| Invalidation | Clear/revoke cancel pending work and prevent late installation; delivery rechecks the completed request |
| Local transport | HTTP messages over a private Unix socket; no TCP listener or host discovery |
| Status | Project allowlists, request states, failure reasons, and cache expiry; no credential values |

The adapters rely on supported 1Password commands and the desktop Go SDK. It does not reimplement the vault or bypass authentication.
Startup queues all saved authorizations while the socket remains available.
SDK startup and expiry refills batch references by project and account, with one client and one bulk call per group.
Failures do not stop other loads. Clear and revoke cancel matching startup loads.
A request for an expired key refills its project, including keys that have not expired.
Other projects retain their own cached or expired state. 1Password controls authentication during each resolution.
A failed resolution is not cached. A later request can retry.
A cache hit can work offline until its existing expiry; a restart cannot recover values without resolving again.

The [README](../README.md) records commands, limits, and the exact memory and trust boundaries.
Tests use synthetic values and fake subprocesses. Live SDK resolution, cache reuse, child delivery, clear, expiry, and restart passed with an explicitly authorized reference.

## Validation

The test suite covers:

- Empty projects, incremental authorization, and refusal across project/account/reference boundaries.
- Cache reuse without expiry extension, expiry cleanup, clear, revoke, and process restart.
- Concurrent requests that share a resolution and distinct requests that never overlap prompts.
- Active and queued status, completion, redacted failures, and invalidation during resolution.
- Subprocess argument selection, timeout, excessive output, NUL rejection, and failure-output suppression.
- Private socket/configuration permissions and refusal of duplicate service startup.
- Child environment delivery and absence of values from cop status, service logs, and persistent files.

`make check` runs vet and race-enabled tests. `make build` produces the `cop` CLI and `copd` daemon.
Cross-compilation checks portability; runtime tests establish behavior only on the host where they run.

## Rex context extension

The project name must equal the Rex session label. All panes share the session's project context.
The CLI validates inherited session and block IDs through the installed Rex CLI before selecting that project.
Server and execution host IDs describe distinct machine/account file environments when the block runs remotely.
The viewing client's identity and endpoint strings never substitute for execution host identity.

`cop context` inspects metadata without the service or 1Password.
Partial, stale, ambiguous, or failed discovery refuses project operations; an explicit project cannot bypass a different session label.
Outside Rex, explicit standalone selection remains supported without invoking Rex.
Environment discovery is trusted context, not authentication. No authorization, networking, cache ownership, or service routing changes accompany this extension.

Focused tests use fake Rex replies and an executable fixture.
They cover multiple panes, remote host distinctions, label changes, missing metadata, mismatched overrides, and preserved standalone behavior.
The installed schema was checked through `server.status`, `session.describe_block`, and live metadata-only CLI inspection.

## Deferred work

1. Extend Tailscale replication with explicit authority migration and operational recovery after multi-host validation.
   Initial selection, inherited topcop authority, default project replication, and offline cache use are implemented.
2. Extend the implemented Ed25519 signing-only cache to additional algorithms after review.
   The separate signing endpoint never returns private-key material. See [the signing spec](signing-cache.md).
3. Define action/spending charters independently of credential allowlists.
   Credential access alone does not enforce an action or spending limit.
4. Add an optional menu-bar companion that presents request metadata during 1Password prompts.
   The CLI and service remain usable without that companion.

Tailscale replication now extends this milestone. Action enforcement, spending enforcement, and native UI remain deferred.
Future signed authority must not become a retroactive prerequisite for the ratified local flow.

## Reference and licensing record

The earlier read-only inspection used reference revision `7dec4904b8a17e506670cd193829808444acf6cc`.
`docs/specs/KEY_ACCESS_SPEC.md` supersedes the older credential grant and renewal designs.
Its signed policy, fleet, and session-role dependencies are not prerequisites for this implementation.
Old per-read/signature quotas and Commander renewal flows are excluded.

The inspected source had no tracked source license; its NOTICE covered artwork.
No source, fixtures, artwork, or private documents were imported. The local milestone consists of independent new code.
The cop license remains undecided. Future source copying requires explicit permission and compatible licensing first.
