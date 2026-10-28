# cop

cop is a standalone tool for 1Password users. Read the README and extraction proposal before changing its architecture.

- Keep credential policies separate from action and spending charters.
- Use supported 1Password APIs or the `op` CLI. Do not replace the vault.
- Keep standalone usage independent of terminal managers, session harnesses, and provider accounts.
- Inside Rex, the project must equal the session label. Treat discovered IDs as metadata, not authentication.
- Never persist credential values, including encrypted recovery copies.
- Keep signing-only keys inaccessible through read and export operations.
- Record source provenance and compatible licensing before reusing external code.
- Use synthetic fixtures. Keep credentials, personal machine details, and private project content out of the repository.
- Label proposals separately from implemented behavior.
- Run `make check` and `make build` after code changes.

The local milestone uses trusted configuration and delegates authentication to 1Password.
Do not require custom approval keys or signed policies for local caching.
Networking, multi-host sync, action/spend enforcement, and native UI remain deferred.
Read the README for the same-user trust boundary and temporary-memory limitations.
