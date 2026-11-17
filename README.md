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
# or sign in with a code you approve in the Console (a short-lived key that can only fetch secrets):
# agentruntime login --device --ref 'workspace/live/*'
agentruntime whoami                # confirm workspace and projects
agentruntime workflows list
agentruntime run <workflow-id> --wait
```

## Commands

| Area | Commands |
|---|---|
| Auth and config | `login` (`--device` signs in with a code), `logout`, `whoami`, `status`, `profile` |
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
| API address (`secrets run`, `check`, `get`, `render`, `handover`, history and the rest, and `login --device`) | `--api-url` | `AGENTRUNTIME_API_URL` |

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
agentruntime secrets render app.conf.tmpl --output app.conf                   # fill a config file; it stays on disk
agentruntime secrets handover workspace/live/stripe#API_KEY                   # a one-time key for someone else
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

## Hand over a secret once

`secrets handover` gives one secret to one person (or one machine) without ever pasting the value into
a chat or an email. It makes a **one-time access key**: it can fetch exactly this secret, exactly
once, and stops working after `--ttl` (1 minute to 24 hours, default 1 hour), whichever comes first.
You send the key (the way you would send a password); the person fetches the value with it.

**What the key can fetch depends on the reference, and the server enforces it:** with `#FIELD` the key
can fetch **only that one field** of the secret (not its other fields); without `#FIELD` it can fetch
the **whole secret**, every field in it. The output says which of the two the token gives, and both
usage lines carry the reference exactly as you gave it, `#FIELD` included.

```sh
agentruntime secrets handover workspace/live/stripe#API_KEY            # only the field API_KEY, valid for 1 hour
agentruntime secrets handover workspace/live/stripe --ttl 15m          # the whole secret, 15 minutes
```

```
One-time key for workspace/live/stripe#API_KEY
It can fetch only the field API_KEY of that secret, and nothing else (not its other fields).
It works once, then it stops. It is valid for 1h (until 2026-11-16T12:00:00Z), whichever ends first.
Anyone who has it can read this value once. Do not paste it into an AI tool.

pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

To use it, put the key where <token> is (the reference is the one you gave, and the only one the key can fetch):
  AGENTRUNTIME_PAT=<token> agentruntime secrets get 'workspace/live/stripe#API_KEY' --print
  curl -sS -X POST <api>/v1/secrets/fetch -H "Authorization: Bearer <token>" ...
```

- The reference **must name its room** (`my/`, `project/` or `workspace/`). A name without a room is
  refused: a hand-over never guesses which secret you meant. `#FIELD` hands over one field; without
  it, the whole secret.
- You must be allowed to view the secret, your own access key must be allowed to fetch it, and the
  workspace must allow fetching. The key works once and then answers `uses_exhausted`; it cannot read
  any other secret. Every hand-over is written to the workspace's audit log, and the key shows up in
  the Console under Settings, API keys, Short-lived access, where it can be revoked.
- **The token is printed only when standard output is a terminal, and only once.** Redirected or piped
  (which is how a coding agent's shell runs) the command refuses with exit code 2 and makes nothing,
  **with or without `--json`**: a key whose token cannot be shown to anyone would only be a loose end.
  It never writes the token to a file. With `--json` on a terminal the token is part of the JSON
  (`{"ref","expires_at","uses","token"}`).
- A hand-over cannot be made through an AI client (`handover_not_for_ai_clients`).

## Render a config file

`secrets render` fills a template with secrets and writes the result, for a program that wants its
secrets in a config file instead of in its environment.

```sh
agentruntime secrets render app.conf.tmpl --output app.conf
agentruntime secrets render app.conf.tmpl --output app.conf --replace
agentruntime secrets render app.conf.tmpl --output -            # print it, on a terminal only
```

The template is a Go `text/template`:

```
database_url = postgres://app:{{ secret "workspace/live/db#PASSWORD" }}@db.example.test/app
stripe_key   = {{ secret "workspace/live/stripe#API_KEY" | quote }}
{{ range $name, $value := fields "workspace/live/app" }}{{ $name }}={{ $value | quote }}
{{ end }}
```

| Function | What it gives |
|---|---|
| `secret "REF#FIELD"` | one field of a secret, as text |
| `fields "REF"` | every field of a secret as a map: `range` over it, write `(fields "REF").NAME`, or `index (fields "REF") "odd-name"` |
| `json` | a value as JSON (a string with its quotes, a `fields` map as an object) |
| `b64enc` | standard base64 of a string |
| `quote` | a string in double quotes with Go escapes (as Helm's `quote`) |

`printf`, `if`, `range`, `with` and `define` work as in any Go template. To write a literal `{{`, put
`{{ "{{" }}` in the template. A name that is not in the secret is an **error**, never an empty string
(also with `index`).

- **Every reference is a quoted string written out in the template.** Not a variable, not a pipeline
  result, not an expression (`secret $name`, `secret (printf ...)` and `printf ... | secret` are
  refused). The CLI reads the template first, collects every reference, and refuses anything else, so
  what a template can read is fixed by its text. All of them are fetched in **one** call, at most 20
  different references, all or nothing: more than 20 is refused before any call, and if one reference
  cannot be resolved, or the template fails, **nothing is written**. A whole secret (`fields`) is one
  reference; so is each `secret "REF#FIELD"`. The same rules apply as for the other commands: the
  `secret:` prefix, `my/`, `project/`, `workspace/`, a name with no room works only when one room
  holds it.
- **A new file** is created with owner-only permissions (`0600` on macOS and Linux; **on Windows it
  is not**: it keeps the permissions of its folder). An existing file is **never overwritten**.
- **`--replace`** replaces an existing regular file: the new content is written to a new owner-only
  file beside it and renamed over it, so a reader sees the old file or the whole new one, and a failure
  leaves the old one in place. The new file does not inherit the old file's permissions. A link or a
  folder is refused, and the template itself cannot be the output.
- **`--output -`** prints the result, only when standard output is a terminal (characters a terminal
  would act on are shown as `\xNN`); redirected or piped it refuses with exit code 2, before anything
  is fetched. `--replace` and `--json` make no sense with it.
- **The rendered file contains your secrets in plain text and stays on disk.** That is what it is
  for. Keep it out of version control and remove it when you no longer need it. `secrets run
  --secret-file` is the command that removes its file when the program ends. Anything the template
  prints into the file is not masked.
- The same fetch rules as `run`: the key needs the **Fetch secret values** scope and the secrets on its
  list. Nothing is fetched for a mistake the CLI can see first (a bad template, a template that
  would not finish, an existing output file, no terminal for `--output -`), so a one-time key is not
  used up by a typo.
- **A template runs after the fetch, when a one-use key is already spent, so it is held to limits.**
  Before the fetch the CLI refuses a template that calls itself (directly or through other
  templates; it would overflow the stack of the program, which cannot be caught), calls a template
  that is not defined in the file, nests `if`, `range` or `with` more than 50 deep or calls templates
  more than 100 deep in a row, writes a number above 1000000 inside `{{ }}`, nests loops over
  written-out numbers past 1000000 iterations in all, or has a `printf` format with a width or
  precision above 4096, a `*` or `[n]`, a verb that does not end in a letter, or more than 256 verbs.
  While the template runs, `printf`, `print`, `println`, `html`, `js`, `urlquery`, `json`, `b64enc`
  and `quote` stop any one value at 1 MiB and all the text they build at 16 MiB, and `printf`,
  `print`, `println`, `html`, `js` and `urlquery` refuse a map of fields as an argument (use `json`,
  or `range`); the output stops at 8 MiB and the whole run at 10 seconds. Nothing is written in any
  of these cases.
- **These limits are not a promise about the memory or the time of every possible template.** What
  is limited is the text those functions build (per value and in all), the output, and the 10
  seconds. A loop that builds no text runs until the 10 seconds are up, and so does a loop whose
  count does not come from a number written in the template (a variable, a length, a loop split
  across templates): the check before the fetch sees only loops over written-out numbers. A run that
  is stopped cannot be interrupted, only left behind, and keeps using a processor until the command
  exits (which it does at once).
- **An error from a running template is a fixed sentence and a line number**
  (`the template failed at line 3: a name that is not in the secret was used`). The template
  engine's own messages can quote a secret's value (ranging over a string prints it), and a masker
  cannot take out a value of one or two characters, so none of the engine's text is shown.

## Sign in with a code

`login --device` signs you in without pasting a key: on a laptop, on a server you reached over SSH, or
anywhere you would rather not keep a long-lived key. The CLI prints a short code and an address. You open
the address in a browser, sign in to the Console, check what the terminal is asking for, narrow it if you
like, and approve it. The CLI then saves a **short-lived access key** in a profile (the one you name with `--profile`,
else the current one), together with
the moment it stops working (`expires_at`, RFC 3339), and says so.

> **Only run `login --device` yourself, only approve your own sign-ins, and check the workspace and the approver
> it shows when it finishes** (`Approved for workspace ... by t***@example.com`). Someone who says "send me the code,
> I will approve it" approves from *their* account, and `secrets run` would then use values from *their* workspace,
> which could change how a program runs. The first line it prints is the API host it talks to.

```sh
agentruntime login --device --ref 'workspace/live/*'
agentruntime login --device --ref workspace/live/stripe --ref my/deploy --ttl 4h --profile laptop
agentruntime login --device --all --scope vault:read --open
```

```
API: api.agentruntime.io
To sign in, open this address in a browser (on any device) and enter the code:

  https://console.example.com/device
  code: BCDF-2345

or open this address, which has the code in it:
  https://console.example.com/device?code=BCDF-2345

This asks for: fetching workspace/live/*, for up to 1h (the approver may narrow this)
Device: my-laptop
Approve it only if you started this from your own terminal just now.
The code works for 10m. Waiting for approval (Ctrl-C to cancel)...
✔ signed in until 2026-11-16 17:04 UTC (in 59 minutes); fetch only
  Approved for workspace Acme by t***@example.com
  Check that this is your workspace and your own account: secrets fetched with this key come from that workspace.
  Scopes: secrets:fetch
  Secrets it may fetch: workspace/live/*
```

- **You say which secrets the key may fetch**: one `--ref` for each secret or folder (`workspace/live/stripe`,
  `workspace/live/*`, `my/*`; the room is `my`, `project` or `workspace`, a `*` may only be the whole last
  part, no `#field`), at most 100, or `--all` for everything the approver may view. A name without a room,
  `shared/`, `..` and invisible characters are refused before anything is sent. The person approving can
  **narrow** the request (fewer secrets, a shorter time, fewer scopes) and never widen it; the CLI shows what
  was granted.
- **The key can only fetch secrets.** It carries the scope `secrets:fetch`, always; `--scope vault:read` adds
  listing secret names. So it is "fetch only": `secrets run`, `get`, `check` and `render` work, commands that
  need more rights (`whoami`, `workflows`) may be refused. It stops working after `--ttl` (1 minute to 8 hours,
  default 1 hour); a person can revoke it earlier in the Console under Settings, API keys, Short-lived access.
  The workspace's fetch switch and the owner's rights are checked on every use, as for any access key.
- **Approve a code only if you started it from your own terminal just now.** The code is not a secret, but
  approving someone else's code would give them access. The CLI prints the code and the address even when its
  output is piped (so a coding agent can show them to you); it opens a browser only with `--open`, and then only
  an `https` address on the API's own domain (a different domain is shown with a warning and never opened).
- **Which server.** `login --device` always prints `API: <host>` first. An `agentruntime.io` host (or `localhost`,
  `127.0.0.1`, `::1`) is used as it is. For any other host, whether it comes from `--api-url`, `AGENTRUNTIME_API_URL`
  or the Platform MCP address, it prints a loud warning and asks you to **type the host name** before anything is
  sent; without a terminal it refuses unless you pass `--yes`. `--open` is refused for such a host. That server decides
  which page you are shown and which key you get. The key is saved with the host that issued it (`issued_by_host` in
  the profile). **Every command that sends the saved key to a server (the API commands and the Platform MCP
  commands) refuses to send it to a host other than the one that issued it** unless you pass `--yes`, and then it
  prints a warning and sends it. A flag, `AGENTRUNTIME_API_URL` or `AGENTRUNTIME_MCP_URL` that points somewhere
  else is how that happens by mistake. A key given with `--pat` or `AGENTRUNTIME_PAT`, and commands that send
  nothing (`profile`, `logout`, `version`), are not affected. A host name must be **plain ASCII** (letters,
  digits, `.`, `-`; write an international name in its `xn--` form): any other character is refused, because some
  (the dotted capital I, the Kelvin sign) look like, or case-fold to, ASCII letters, so a lookalike could pass
  for an AgentRuntime host. Only `agentruntime.io` and the names under it count as AgentRuntime hosts. The host
  printed on the first line, stored in the profile, compared and dialled is one and the same value.
- **Who approved.** When it finishes it prints `Approved for workspace <name> by <masked approver>` from what the server
  sends (the workspace id when there is no name). Check it: the key fetches from that workspace.
- **Waiting.** The CLI polls at the interval the server gives (default 5 seconds), waits longer when the server
  says `slow_down`, retries a failed poll a few times, and stops when the code's lifetime (10 minutes) is over.
  `Ctrl-C` cancels and nothing is saved. The default `--timeout` does not apply to the wait; a `--timeout` you
  give does. A denied or expired code is explained in plain words and saves nothing.
- **The key is delivered exactly once** and is saved only in the config file (owner-only permissions on macOS and
  Linux, written to a temp file and renamed so a failed save leaves the old config alone). **The CLI never prints
  the key or the device code**, in any message, and `profile list` shows when a short-lived key ends instead of any
  part of it. If the config cannot be written, that is found before the code is shown. `AGENTRUNTIME_PAT` in your
  environment still overrides the saved key, and the CLI says so.
- **The device name is your machine's host name** by default, and it is sent to the API so the approver can recognise
  the terminal. `--device-name NAME` sends another name; `--device-name ""` sends a generic one (`AgentRuntime CLI`)
  instead of the host name.
- **It will not replace a key that does not expire by accident.** A profile that holds a key with no expiry (one
  you pasted) makes the command refuse, because the new key can only fetch secrets: use `--profile NAME` to keep
  both, or `--replace` to replace it. A key from an earlier sign-in (it has an expiry) is renewed without asking.
  `--replace` says that the old key was removed from the profile; it is not revoked on the server, so revoke it in
  the Console if you no longer need it. `logout` removes the saved key from the profile; it does not revoke it, so revoke a key you no longer trust in the
  Console.
- **The profile is not made current.** The CLI saves the key into the profile you named with `--profile` (or the
  current one) and leaves the current profile alone, so `whoami` and `workflows` keep using your normal key. Use
  `--profile NAME` (or `AGENTRUNTIME_PROFILE`) to use the fetch-only key. The config is read again just before the key
  is saved, so a profile changed in another terminal while you waited is not overwritten, and a key that does not
  expire that appeared there meanwhile is not replaced without `--replace`. The expiry the server reports is limited to
  8 hours from now (a later one is cut back, with a note).
- Like every call the CLI makes with a key, these two calls need an `https` API address (plain `http` only for
  `localhost`, `127.0.0.1` and `::1`), never follow a redirect, cap the size of an answer and time out. They carry no
  access key. The API address comes from `--api-url`, `AGENTRUNTIME_API_URL` or the Platform MCP address, as for
  the other commands, and is not saved in the profile.

## Short-lived keys

Some access keys are short-lived: a one-time key from `secrets handover`, or a key that a sign-in made
for a few hours (`login --device` saves it in the profile with its `expires_at`). When the key in use has under 10 minutes left, `run`, `check`, `get` and `render` say
so on standard error (`note: this key expires in 7 minutes`); the server reports the expiry in the
`X-Key-Expires` header of its answer. A key that does not expire is never mentioned. If a key saved in a
profile has an expiry that has passed and the server answers `401`, the CLI says "your short-lived key
expired; sign in again". A key you give with `--pat` or `AGENTRUNTIME_PAT` has no stored expiry.

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
  non-terminal. `secrets render --output PATH` prints one JSON summary with `--json`
  (`{"written":...,"replaced":...,"bytes":...,"references":...}`, no value). `secrets handover` refuses to run when
  standard output is not a terminal, with or without `--json`; on a terminal `--json` includes the token.
- `login --device` prints the code and the address on standard output even when it is piped (the code is not a secret), never
  the key or the device code, and ignores `--json`. Exit codes: `0` signed in, `1` denied, expired, or failed, `2` bad flags,
  `130` Ctrl-C. Nothing is saved unless it ends with `0`.

## License

[Apache-2.0](LICENSE)
