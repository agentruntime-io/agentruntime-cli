# AgentRuntime CLI

Command-line client for [AgentRuntime](https://agentruntime.io) Platform MCP. Run workflows, approve
human tasks, browse the connector catalog, and manage tenant data, vault secrets and personal access
tokens from your terminal, or call any Platform MCP tool directly.

One static binary, no runtime to install. Windows, macOS and Linux (amd64 and arm64).

## Install

**Windows (PowerShell)**

```powershell
irm https://github.com/agentruntime-io/agentruntime-cli/releases/latest/download/install.ps1 | iex
```

**macOS / Linux**

```sh
curl -fsSL https://github.com/agentruntime-io/agentruntime-cli/releases/latest/download/install.sh | sh
```

The installers need no admin rights, verify a SHA-256 checksum, and install two commands:
`agentruntime` and the short alias `agent`.

> If another tool on your machine already owns `agent` (for example the Cursor CLI), whichever
> comes first on your `PATH` wins. `agentruntime` always runs this CLI, and the installer warns you
> when it detects a clash.

Update later with `agentruntime upgrade`. Build from source with Go:

```sh
git clone https://github.com/agentruntime-io/agentruntime-cli && cd agentruntime-cli
go build -o agentruntime .
```

## Quick start

```sh
agentruntime login                 # paste a personal access token (PAT)
agentruntime whoami                # confirm workspace and projects
agentruntime workflows list
agentruntime run <workflow-id> --wait
```

## Commands

| Area | Commands |
|---|---|
| Auth and config | `login`, `logout`, `whoami`, `status`, `profile` |
| Workflows | `run`, `await`, `inspect`, `approve`, `reject`, `workflows`, `runs`, `tasks` |
| Raw tools | `tools list`, `tools describe`, `tools call` (alias: `call`) |
| Platform | `catalog`, `tenantdata`, `vault`, `pats`, `analytics`, `projects` |
| Maintenance | `upgrade`, `version` |

Run `agentruntime <command> --help` for details and examples.

## Configuration

Precedence: flags > environment > saved profile > defaults.

| Setting | Flag | Environment |
|---|---|---|
| Token | `--pat` | `AGENTRUNTIME_PAT` |
| Endpoint | `--url` | `AGENTRUNTIME_MCP_URL` |
| Profile | `--profile` | `AGENTRUNTIME_PROFILE` |

Profiles are stored per user in `agentruntime/config.json` under your OS config directory (owner-only
permissions). Use `agentruntime profile list|use|remove` to manage them.

## Scripting and coding agents

- `--json` prints raw JSON; `--no-color` disables colors.
- Exit codes: `0` success, `1` error or failed run, `2` usage error, `3` run is waiting for approval.
- `approve` shows the approval gate and asks for confirmation; pass `--yes` in scripts.

## License

[Apache-2.0](LICENSE)
