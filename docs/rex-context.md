# Rex session context

Owner: cop maintainers. Updated: 2026-10-28.

Inside a Rex terminal, cop selects the project from the Rex session label. This page explains how cop finds that label and when it refuses.

## What cop reads

cop reads the inherited `REX_SESSION`, `REX_SERVER`, and `REX_BLOCK` variables, then asks the installed Rex CLI.

| Field | Source |
| --- | --- |
| `project` | The exact label from `rex session inspect "$REX_SESSION" --json` |
| `session_id` | The full Rex session ID, checked against the lookup |
| `server_host_id` | `host_id` from `rex whoami --json` |
| `execution_host_id` | `block.host_id` for the inherited block in that session |
| `server_endpoint` | The connection address Rex reports. It is not a host identity. |

`cop context` prints `mode` and the fields above that apply. It contacts neither copd nor 1Password.

Rex gives two servers the same host ID when they see the same files: normally the same machine and OS account.
The server host and the execution host can differ for remote panes. cop never uses the viewing client's machine.
cop needs the block ID to find the execution host, but never returns it or sends it to copd.

## Rules

- cop checks the context again on every project command. Status, connect, setup, and daemon commands do not use it. It never falls back to a focused session, active tab, or viewing client.
- An explicit `--project`, including the name in `project create`, must equal the session label. cop refuses a different name before it contacts copd.
- If you rename a session, the next command uses the new label. cop does not rename or migrate the old project.
- Two sessions with the same label share one project.
- A label must be 1 to 64 ASCII letters, digits, underscores, or hyphens, and must start with a letter or digit. cop refuses other labels as they are. It does not trim them or change their case.
- If any of the three variables is set, all three must be set. Missing variables, stale IDs, conflicting answers, and failed lookups are errors, even with `--project`.
- Rex lookups do not autostart the server, ignore `REX_CLIENT`, and have limits on time and output size.

If none of the three variables is set, `cop context` reports `standalone` without running Rex. Outside Rex, every key command needs `--project`.
`copd` and `cop status` never use Rex.

## Trust

These variables and lookups tell cop which project you mean. They do not prove who you are.
Any process running as your user can set them. They add no authorization, keys, or credentials.
`COP_HOME` still selects the local service. Metadata from a remote pane never redirects secrets.
