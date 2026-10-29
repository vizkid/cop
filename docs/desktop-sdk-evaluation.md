# Desktop Go SDK evaluation

Owner: cop maintainers. Updated: 2026-10-29.
Status: desktop resolution verified live; optional SDK cache integration implemented.

The desktop SDK is a candidate for local resolution with approval in 1Password.
An isolated probe compiles against v0.4.1 and tests the proposed process boundary without contacting a vault.
A live test reached desktop approval, which the operator approved.
A subsequent probe initialized the desktop client but reported that no vault matched the reference query.
With operator permission, a metadata-only vault listing established a mismatch between the supplied vault label and the API title.
Replacing that label with the observed vault ID resolved the same authorized item and field successfully.
copd now does this itself: when the SDK reports no vault match, it lists vault titles and types once and retries with the ID of the single matching vault (`internal/desktop/batch.go`).
The probe discarded the value without printing its contents, length, or hash.
No item enumeration, service configuration change, or credential persistence was needed.

## Verified interface and behavior

- `WithDesktopAppIntegration` selects an explicit account name or UUID.
  The SDK does not document sign-in URLs as account selectors.
  The supplied sign-in domain worked in this live test; prefer documented selectors for portable use.
- `WithIntegrationInfo` supplies the integration name and version.
- `Secrets().Resolve` accepts an exact reference and returns a Go string.
- Desktop authentication needs the SDK integration enabled in 1Password settings.
- Approval grants temporary access to the entire authorized account, including its built-in Private vault.
  Approval expires after ten minutes of inactivity or when the account locks.
  This approval is not a project or field allowlist.

Sources: [SDK setup](https://www.1password.dev/sdks) and
[authentication concepts](https://www.1password.dev/sdks/concepts#1password-desktop-app).

## Source inspection findings

These findings apply to `github.com/1password/onepassword-sdk-go` v0.4.1.
They are source observations, not live account tests.

| Finding | Consequence |
| --- | --- |
| Desktop mode loads a native library supplied by the installed 1Password app | No separate SDK server; macOS and Linux desktop builds need CGO |
| `GetSharedLibCore` initializes a process-global core and its account name only once | Avoid mixing desktop accounts in one process pending upstream clarification |
| Desktop `InitClient` and `Invoke` receive contexts but call the native library synchronously without checking them | A context deadline alone cannot enforce cop's resolution timeout |
| Resolution returns strings through JSON and native response buffers | Temporary secret copies cannot all be erased or locked by cop |
| The SDK exposes account-wide item and vault operations | Restrict cop's integration to exact-reference resolution |

The global account selector appears in the outer IPC request; initialization also includes client configuration.
Actual routing across multiple accounts remains unverified. Do not claim a demonstrated cross-account disclosure.

Inspect the pinned [desktop core](https://github.com/1Password/onepassword-sdk-go/blob/v0.4.1/internal/shared_lib_core.go),
[native bridge](https://github.com/1Password/onepassword-sdk-go/blob/v0.4.1/internal/shared_lib_core_unix.go),
and [client builder](https://github.com/1Password/onepassword-sdk-go/blob/v0.4.1/client_builder.go).

## Isolated probe

The probe lives in a separate Go module at `experiments/desktop-sdk`.
The main cop module also uses the Go SSH library for its signing agent.
The probe neither connects to the cop service nor reads or changes its allowlists.
It is a developer diagnostic, not an authorized cop delivery path.

Build and test from that directory:

```sh
go mod verify
go vet ./...
go test -race -count=1 ./...
go build -o ../../bin/cop-sdk-eval .
../../bin/cop-sdk-eval
```

The default invocation reports the build without creating an SDK client.
Synthetic tests cover exact selectors, invalid selections, oversized values, NUL rejection, error redaction, and worker deadlines.
They do not establish native prompt behavior, account routing, or SDK persistence behavior.

For an intentional live test, set `ACCOUNT` to the desktop account name or UUID.
Set `REF` to an explicitly authorized ordinary readable field.

```sh
../../bin/cop-sdk-eval --live --account "$ACCOUNT" --ref "$REF"
```

The parent starts one worker process for one account and reference.
It discards worker stdout and stderr and enforces a one-minute deadline by killing the process group.
Fixed worker exit codes distinguish initialization and resolution failures without forwarding SDK error text.
Both processes disable core dumps. Success prints only a fixed result message.
The worker discards the resolved string without printing its value, length, or hash.
No secret value is sent back to the parent or written by the probe.
1Password and its native library retain their own memory and persistence behavior.

## Implemented cache integration

`cop serve --resolver sdk` keeps the existing queue, allowlists, cache, status, and service ownership.
Each miss starts a disposable SDK worker with the explicitly selected account and reference.
The parent enforces deadlines outside the native call and discards worker logs.
The worker sends its value through inherited file descriptor 3, which must be a pipe.
The parent bounds delivery and rejects failed worker output before caching.
The standalone probe remains separate and never delivers a value.
`make build` builds the worker beside cop; `make check` checks both modules.

A live isolated service passed initial resolution, cache reuse, child delivery, clear, expiry, and restart checks.
Synthetic lifecycle and concurrency tests run through both adapters.
They check authorization isolation, failure suppression, secret-free persistence, and process restart behavior.

Further desktop validation must cover denial, app lock, prompt cancellation, and two distinct account UUIDs.
Check whether killing a worker removes its prompt and whether approvals survive worker replacement.
Decide how desktop account UUIDs map to existing CLI account selectors without silently changing allowlists.
Keep cache expiry distinct from desktop approval expiry: locking 1Password does not automatically clear cop's existing cache.
The supported `op` adapter remains the default; SDK use is explicit.

## Dependencies and licensing

The SDK v0.4.1 repository is MIT-licensed; its license permits this dependency evaluation.
The SDK README states that API and service usage is governed separately by 1Password's API terms.
The probe and worker import the SDK rather than copying its implementation.
The installed proprietary desktop library is not copied or redistributed.
The nested `go.mod` and `go.sum` pin the dependency graph and checksums.
The SDK's MIT notice is retained beside the probe.
Before distributing SDK-linked binaries, retain all required dependency notices and review the applicable API terms.
This evaluation does not select cop's project license.

Sources: [SDK license](https://github.com/1Password/onepassword-sdk-go/blob/v0.4.1/LICENSE) and
[SDK README](https://github.com/1Password/onepassword-sdk-go/blob/v0.4.1/README.md).
