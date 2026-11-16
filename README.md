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
| Platform | `catalog`, `tenantdata`, `secrets` (alias `vault`), `pats`, `analytics`, `projects` |
| Maintenance | `upgrade`, `version` |

Run `agentruntime <command> --help` for details and examples.

## Configuration

Precedence: flags > environment > saved profile > defaults.

| Setting | Flag | Environment |
|---|---|---|
| Token | `--pat` | `AGENTRUNTIME_PAT` |
| Endpoint | `--url` | `AGENTRUNTIME_MCP_URL` |
| Profile | `--profile` | `AGENTRUNTIME_PROFILE` |
| API address (`secrets run`, `check`, `get`) | `--api-url` | `AGENTRUNTIME_API_URL` |

Profiles are stored per user in `agentruntime/config.json` under your OS config directory (owner-only
permissions). Use `agentruntime profile list|use|remove` to manage them.

## Secrets in scripts

`secrets` lists and saves workspace secrets, and hands them to a program without `.env` files.
(`vault` is the older name for the same command and still works.)

```sh
agentruntime secrets list --scope tenant
agentruntime secrets set live/stripe --data-file stripe.json --create --scope tenant   # --update merges
agentruntime secrets run --env STRIPE_KEY=workspace/live/stripe#API_KEY -- python job.py
agentruntime secrets run --env-from workspace/live/stripe#API_KEY,WEBHOOK_SECRET -- ./deploy.sh
agentruntime secrets run --secret-file .env=workspace/live/app#DB_USER,DB_PASS -- docker compose up
agentruntime secrets check workspace/live/stripe#API_KEY
agentruntime secrets get workspace/live/stripe#API_KEY --print                # terminal only
agentruntime secrets history live/stripe --scope tenant                       # who changed it, never values
agentruntime secrets deleted --scope tenant                                   # Recently deleted
```

**References.** `[secret:]<room>/<path>[#<field>]`. The room is `my` (your own secrets),
`project` (the project of your access key) or `workspace`. With `#field` the value is that one
field; without it, the whole secret. A name with no room works only when exactly one room holds
it. Otherwise the command fails and lists the rooms; it never picks one. A first segment of
`my`, `project` or `workspace` is always a room: write `workspace/my/...` for a workspace folder
called `my`.

**What you need.** The same access key as every other command, with the **Fetch secret values**
scope (`secrets:fetch`) and the secrets chosen for it in the Console (Settings > API keys). The
key's owner must still be allowed to view each secret, and the workspace must allow fetching.
`run`, `check` and `get` call the API directly (the Platform MCP never returns a value). The API
address is derived from the MCP address (`mcp.` becomes `api.`); override it with `--api-url`
or `AGENTRUNTIME_API_URL`. Plain `http` is accepted only for the exact hosts `localhost`, `127.0.0.1`
and `::1` (not for a name that merely ends in `.localhost`).

**`secrets run`.**

- All references are fetched in **one** call, all or nothing: if any one cannot be resolved,
  nothing is fetched and the command is not started. `check` first if you want to know.
- `--env NAME=REF#FIELD` sets one variable (NAME) from one field. An explicit `--env` wins over
  `--env-from` and may use any valid variable name.
- `--env-from REF#F1,F2` sets one variable per field **you name**: the field name, upper-cased
  (`db_pass` sets `DB_PASS`). Only the named fields are fetched, and nothing else the secret holds
  ever becomes a variable, so a field that someone adds to the secret later cannot change how the
  command runs (a field called `GOFLAGS` or `PIP_INDEX_URL` could change how a build runs, and no
  list of such names is ever complete). REF alone, or `REF#*`, is refused. A field name must be
  plain ASCII letters, digits and `_` (checked before upper-casing, so a letter such as the dotless
  `ı` cannot turn into an ASCII one), and must not start with `AGENTRUNTIME_`, which is reserved for
  this tool's own settings. For another variable name use `--env NAME=REF#FIELD`. All of this is
  checked before anything is fetched. Each field you name is one reference, and one call carries at
  most 20.
- `--secret-file PATH=REF` writes a secret to a file and removes it when the command ends, also on a
  signal or a failure. An existing file is never overwritten. On macOS and Linux the file is
  owner-only (`0600`); **on Windows it is not**: it keeps the permissions of its folder, so put it in
  a folder only you can read.
  - A dotenv file (`.env`, `*.env`) needs the fields named, `REF#F1,F2`, and only those are written
    (the keys are the field names as they are stored). A program that loads a dotenv file turns
    every key into an environment variable, so what a secret happens to hold must not decide what is
    written; REF alone, or `REF#*`, is refused. Keys follow the rules of `--env-from`, and a `.` or
    `-` is refused as well, because bash reads such a line as a command. A dotenv file is written only
    in forms that bash (`source`), docker compose and python-dotenv read back identically; a value
    that no such form can carry (for example one that mixes `'` with `$`, or holds `${`, a NUL or a
    carriage return) is an error naming the field. Use a `.json` file for it.
  - A JSON file (`*.json`) is not loaded into an environment, so `REF` writes the whole secret as a
    JSON object; `REF#F1,F2` writes just those fields.
- The command does **not** inherit `AGENTRUNTIME_PAT` (your access key), so the key does not end up
  in its environment or its logs by accident. This is accident prevention, not a barrier: a program
  running as you can still read the key file, or the environment of the `agentruntime` process
  itself (`/proc/$PPID/environ` on Linux). `--pass-key` lets the key through for a command that runs
  `agentruntime` itself.
- The command's exit code passes through (`126`/`127` if it cannot be started, `128+n` if a signal
  ended it). Standard input passes through untouched. The first `Ctrl-C`/`SIGTERM` is forwarded;
  a second one kills the command.
- **Masking.** Standard output and standard error of the command are filtered. Replaced with
  `***`: every fetched value, its whitespace-trimmed form (a value stored with a trailing newline
  is usually printed without it), each line of a multi-line value (a PEM file printed one line at
  a time), and the base64, URL-encoded and JSON-escaped forms of these. A piece shorter than 8
  characters is never masked (the CLI says so once on standard error when a value is that short).
  Each value is masked line by line for at most 256 distinct lines (the longest first); lines
  beyond that are not masked individually, though the value as a whole still is. Every line costs
  time on everything the command prints, and this keeps a value of thousands of lines from making
  the output crawl.
  **Not masked:** hex, a changed case, base64 broken over several lines, base64 of `user:value`,
  and anything else the command transforms. Masking is accident prevention only (a script that
  prints its environment); it cannot stop a program that wants to leak a value it holds. Because
  the output is filtered, the command sees pipes, not a terminal, on stdout and stderr (unless no
  fetched value can be masked).
- A value is never printed by the CLI, never part of a command line, and never written to disk
  unless you ask for `--secret-file`. `--timeout` limits the fetch, not the command.

**`secrets check`** takes the same `REF#F1,F2` form and answers for each named field.

**`secrets get --print`** prints a value only when standard output is a terminal; piped or redirected
(which is how a coding agent's shell runs) it refuses with exit code 2 and fetches nothing. Use
`run` or `--secret-file` to give a value to a program. What it prints can contain any character the
secret's author put there, so control characters (other than newline and tab), the escape character
and the 8-bit control range are shown as `\xNN` instead of being sent to the terminal, where they
could move the cursor or write to the clipboard. `vault read` was removed.

**`secrets set`** takes `--create` (fail if it exists) or `--update` (merge: a field given with a blank
value keeps its stored value; `--remove-key NAME` deletes a field). `--scope` names the room:
`user`, `project`, `tenant`, `shared`. It also takes settings flags, see
[Version history, recovery and settings](#version-history-recovery-and-settings).

> **Keep values off the command line.** A value written as `-d key=value` or `--data '{...}'` is part
> of the command line, so it ends up in your shell history and in the process list. Give the values
> in a file instead: `--data-file FILE` (a JSON object; `--data-file -` reads it from standard input,
> for example `... --data-file - < stripe.json`; PowerShell has no `<`, so use `--data-file stripe.json`
> there) or `-d key=@FILE` (the field's value is the content of `FILE`, trailing line breaks removed).
> The inline forms stay available for blank values (`-d field=` keeps the stored value with
> `--update`) and for non-secret fields.

## Version history, recovery and settings

Every save of a secret is a new version, and a deleted secret can be brought back. These commands
call the API directly with the same access key as every other command (rights are the key owner's).
**None of them shows a secret's value**: history lists who changed a secret, when, and the *names* of the
fields they added, changed or removed. A person views an older value in the Console.

```sh
agentruntime secrets history live/stripe --scope tenant            # versions: when, who, which field names
agentruntime secrets restore live/stripe --version 2 --scope tenant  # write version 2 back as a NEW version
agentruntime secrets deleted --scope tenant                        # Recently deleted (and expired secrets)
agentruntime secrets undelete live/stripe --scope tenant
agentruntime secrets delete live/stripe --scope tenant             # to Recently deleted when the workspace supports it
agentruntime secrets delete live/stripe --scope tenant --destroy --confirm live/stripe   # for good
```

`--scope` is `user`, `project` or `tenant` (the default) for all of them. A secret shared with you is
read-only: use the room it really lives in. Every command takes `--json` and `--api-url`.

- **`history <path>`** (alias `versions`) shows how many versions are kept, the auto-expire time,
  the description and labels, and one row per version still kept: number, state (`current`, `available`,
  `deleted`, `destroyed`), time, who saved it (the user id, and the name when the API gives one), its kind
  (`create`, `update`, `restore`, `settings`, or `unknown`) and what changed (`restored from version N`,
  `added A; changed B; removed C`: field names only). A version saved before history was recorded has
  kind `unknown`, no author and no field names. Text from the
  server (paths, field names, labels) is shown with control and invisible characters escaped.
- **`restore <path> --version N`** writes version N back as a **new** current version. Nothing is lost:
  the version it replaces stays in the history. You never see the value; the API reads and writes it.
  `already_current` (it is the current version), `conflict` (the secret changed meanwhile, nothing was
  written) and `version_unavailable` (that version is gone) are answered in plain words.
- **`deleted`** lists a room's Recently deleted secrets: deleted ones and ones whose auto-expire passed
  (why: `deleted` or `expired`). When the workspace cannot recover deleted secrets it says so and exits
  `0`; with `--json` the answer is `{"supported": false, "items": []}` (and `{"supported": true, ...}`
  otherwise). Only people who may delete in that room can list them.
- **`undelete <path>`** brings a secret back with its versions, owner and sharing. A secret that expired
  comes back with its auto-expire turned off, so it does not vanish again at the next save.
- **`delete <path>`** says `Moved <path> to Recently deleted` when the API answers that it can be
  recovered (header `X-Recoverable: true`), and `Deleted <path> permanently` otherwise (including an older
  API that does not say). It asks first unless you pass `--yes`.
- **`delete <path> --destroy --confirm <path>`** deletes for good, every version, also from Recently
  deleted. It refuses unless `--destroy` and `--confirm` are both given, `--confirm` repeats the path
  exactly (same case, no extra space), and `--scope` is given (a permanent delete never lands in a room you
  did not name). It does not ask again: `--confirm` is the confirmation. The API accepts it from an access
  key and the Console, not from an AI client.

**Settings flags of `secrets set`**, applied after the save through the API:

| Flag | Meaning |
|---|---|
| `--description TEXT` | what the secret is for, up to 500 characters (`""` clears it) |
| `--label k=v` | set a label (repeatable); `--label k` is a tag with no value. Key: lower-case letters, digits, `.`, `_`, `-`, up to 40 characters; value up to 100 characters; at most 10 labels |
| `--remove-label k` | remove a label (repeatable) |
| `--keep-versions N` | keep the last N versions (1 to 100), or `default` (the workspace default) |
| `--expire-after DURATION` | the secret moves to Recently deleted this long after it was last saved: `1h`, `7d`, `90d`, `2w` (1 hour to 365 days; units `s`, `m`, `h`, `d`, `w`), or `never` |

- Every flag is checked before anything is saved, so a typo never leaves a saved secret with settings
  that were not applied.
- Labels you do not name are kept. The API replaces the labels as a whole, so `--label` and
  `--remove-label` first read the current labels and write the merged set back: two people changing
  labels at the same moment can overwrite each other.
- `--keep-versions` and `--expire-after` save **one more version** of the secret (that is how they apply at
  once). A lower `--keep-versions` removes the oldest versions for good. With `--expire-after` every save
  restarts the clock, and after the time the secret is in Recently deleted: a script that reads it stops
  finding it. They need the secret's owner or a room manager; description and labels need the right to
  change the secret.
- With settings flags and **no data**, only the settings change and no new version is saved
  (`agentruntime secrets set live/stripe --label env=prod`). `--create` and `--update` need data.
- If the save works and the settings step fails, the command says so on standard error and exits `1`:
  the secret is saved. A left-out `--scope` means the workspace room for both steps.
- With `--json` and settings flags, standard output is one object, `{"saved": {...}, "settings": {...}}`
  (`saved` is `null` when nothing was saved, `settings` is `null` when the settings step failed).

## Scripting and coding agents

- `--json` prints raw JSON; `--no-color` disables colors.
- Exit codes: `0` success, `1` error or failed run, `2` usage error, `3` run is waiting for approval.
- `approve` shows the approval gate and asks for confirmation; pass `--yes` in scripts.
- `secrets history`, `deleted`, `restore`, `undelete`, `delete` and `set` with settings flags keep `--json` output valid
  (one JSON document on standard output; errors go to standard error). No command shows a secret's value.
- `secrets check --json` prints `{"items":[{"ref":...,"resolves":...}]}` and exits `1` when any reference does not
  resolve. `secrets run` passes the command's exit code through. No `secrets` command prints a value to a
  non-terminal.

## License

[Apache-2.0](LICENSE)
