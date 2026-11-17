package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/agentruntime-io/agentruntime-cli/internal/bffclient"
	"github.com/agentruntime-io/agentruntime-cli/internal/render"
	"github.com/agentruntime-io/agentruntime-cli/internal/secrets"
)

const secretsLong = `Workspace secrets: list and save them, and use them from scripts without
.env files.

  agentruntime secrets list --scope tenant
  agentruntime secrets set my-app/stripe --data-file stripe.json --create --scope user
  agentruntime secrets run --env STRIPE_KEY=workspace/live/stripe#API_KEY -- python job.py
  agentruntime secrets check workspace/live/stripe#API_KEY
  agentruntime secrets get workspace/live/stripe#API_KEY --print   # terminal only
  agentruntime secrets history live/stripe --scope tenant          # who changed it, never values
  agentruntime secrets restore live/stripe --version 2 --scope tenant
  agentruntime secrets deleted --scope tenant                      # Recently deleted
  agentruntime secrets undelete live/stripe --scope tenant
  agentruntime secrets render app.conf.tmpl --output app.conf      # fill a config file; it stays on disk
  agentruntime secrets handover workspace/live/stripe#API_KEY      # a one-time key for someone else (terminal only)

A secret reference is  [secret:]<room>/<path>[#<field>]  where the room is my
(your own secrets), project (the key's project) or workspace. With #field it is
that one value; without it, the whole secret. A name without a room works only
when exactly one room holds it; otherwise the command fails and lists the rooms.
run's --env-from and --secret-file take several fields at once, which you name
yourself: REF#FIELD1,FIELD2.

list and set go through Platform MCP like every other command. run, check, get and
render call the API directly with the same access key, and need a key that carries
the "Fetch secret values" scope (secrets:fetch) and the secrets chosen for it. The
version commands (history, restore, deleted, undelete, delete, and the settings
flags of set) also call the API directly with the same key; none of them ever
shows a secret's value. 'vault' is an older name for this command and still works.

render fills a config-file template and writes the file, which stays on disk.
handover makes a one-time key so that someone else can fetch one secret once; it
prints the key's token only to a terminal.

When the access key in use is short-lived and has under 10 minutes left, run,
check, get and render say so on standard error.`

// scopeHelp names the rooms of the Secrets page in the Console.
const scopeHelp = "room: user (My secrets), project, tenant (workspace) or shared (shared with you; read-only)"

func (a *App) secretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secrets",
		Aliases: []string{"vault"},
		Short:   "Workspace secrets: list, save, and use them in scripts without .env files",
		Long:    secretsLong,
		Args:    cobra.ArbitraryArgs,
		// A parent that is not runnable would print help and exit 0 for an unknown
		// word, so `vault read` would look like it worked.
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if args[0] == "read" {
				return &ExitErr{Code: ExitUsage, Err: errors.New(
					"`read` was removed: secret values are not readable through Platform MCP any more. " +
						"Use `agentruntime secrets run` or --secret-file to hand a value to a program")}
			}
			return &ExitErr{Code: ExitUsage, Err: fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())}
		},
	}
	cmd.AddCommand(
		a.secretsListCmd(), a.secretsSetCmd(), a.secretsDeleteCmd(),
		a.secretsRunCmd(), a.secretsCheckCmd(), a.secretsGetCmd(),
		a.secretsHistoryCmd(), a.secretsRestoreCmd(), a.secretsDeletedCmd(), a.secretsUndeleteCmd(),
		a.secretsHandoverCmd(), a.secretsRenderCmd(),
	)
	return cmd
}

// ---- list / set (Platform MCP tools; delete, history and the rest are in secrets_versions.go) ---

func (a *App) secretsListCmd() *cobra.Command {
	var scope, prefix string
	var limit int
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List secret names and rights (never values)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := map[string]any{}
			setIf(req, "scope", scope)
			setIf(req, "path", prefix)
			setIf(req, "limit", limit)
			return a.call1(cmd, "vault_secrets_list", req)
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", scopeHelp)
	cmd.Flags().StringVar(&prefix, "path", "", "folder to list inside the room")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum entries")
	return cmd
}

func (a *App) secretsSetCmd() *cobra.Command {
	var scope, dataJSON, dataFile, apiURL string
	var kv, removeKeys []string
	var create, update bool
	var description, keepVersions, expireAfter string
	var labels, removeLabels []string
	cmd := &cobra.Command{
		Use:   "set <path>",
		Short: "Create or update a secret (the value is never printed back)",
		Long: `Saves a secret. Without --create or --update the whole secret is replaced.

  --create  fails if the secret already exists
  --update  merges into the existing secret: a field given with a blank value
            keeps its stored value, --remove-key NAME deletes a field

Keep values off the command line. A value written as -d key=value or --data is
part of the command line, so it lands in your shell history and in the process
list. Give the values in a file instead: --data-file FILE (a JSON object; "-"
reads it from standard input) or -d key=@FILE (the field's value is the content
of FILE, trailing line breaks removed).

Settings, applied after the save through the API with the same access key:

  --description TEXT       what the secret is for (up to 500 characters; "" clears it)
  --label k=v              set a label (repeatable); --label k is a tag with no value
  --remove-label k         remove a label (repeatable)
  --keep-versions N        keep the last N versions (1 to 100), or "default"
  --expire-after DURATION  the secret moves to Recently deleted this long after it
                           was last saved: 1h, 7d, 90d (1 hour to 365 days), or "never"

Labels you do not name are kept. They are read and written back as a whole, so
two people changing labels at the same moment can overwrite each other.
--keep-versions and --expire-after save one more version of the secret so that
they apply at once, and a lower --keep-versions removes the oldest versions
for good. With settings flags and no data, only the settings change and no new
version is saved. If the save works and the settings step fails, the command
says so and exits 1: the secret is saved.`,
		Example: `  agentruntime secrets set integrations/stripe --data-file stripe.json --create
  agentruntime secrets set integrations/stripe --data-file - --create < stripe.json
  agentruntime secrets set integrations/stripe -d api_key=@api_key.txt --update
  agentruntime secrets set integrations/stripe -d webhook_secret= --update    # blank keeps the stored value
  agentruntime secrets set integrations/stripe --update --remove-key webhook_secret
  agentruntime secrets set integrations/gcp --data-file service-account.json --scope tenant
  agentruntime secrets set integrations/stripe --description "Payments key" --label env=prod --label stripe
  agentruntime secrets set integrations/stripe --keep-versions 5 --expire-after 90d
  agentruntime secrets set integrations/stripe --remove-label stripe --expire-after never`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if create && update {
				return &ExitErr{Code: ExitUsage, Err: errors.New("--create and --update cannot be combined")}
			}
			if len(removeKeys) > 0 && !update {
				return &ExitErr{Code: ExitUsage, Err: errors.New("--remove-key needs --update")}
			}
			data, err := mergeArgs(dataJSON, dataFile, kv, a.In)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			for i, k := range removeKeys {
				removeKeys[i] = strings.TrimSpace(k)
				if removeKeys[i] == "" {
					return &ExitErr{Code: ExitUsage, Err: errors.New("--remove-key needs a field name")}
				}
				if _, both := data[removeKeys[i]]; both {
					return &ExitErr{Code: ExitUsage, Err: fmt.Errorf("field %q is both set and removed", removeKeys[i])}
				}
			}
			plan, err := buildSettingsPlan(cmd, description, labels, removeLabels, keepVersions, expireAfter)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			haveData := len(data) > 0 || len(removeKeys) > 0
			switch {
			case !haveData && plan.empty():
				return &ExitErr{Code: ExitUsage, Err: errors.New("no data: use --data-file FILE (or - for stdin), -d key=@FILE, or -d key=value / --data (these two put the value on the command line)")}
			case !haveData && (create || update):
				return &ExitErr{Code: ExitUsage, Err: errors.New("--create and --update save data: give data, or leave them out to change only the settings")}
			}
			// Everything the settings step needs is checked before the save, so a typo or a missing key
			// never leaves a saved secret with settings that were not applied.
			var room string
			var api *bffclient.Client
			if !plan.empty() {
				if room, err = vaultScope(scope); err != nil {
					return &ExitErr{Code: ExitUsage, Err: err}
				}
				if api, err = a.apiClient(apiURL); err != nil {
					return err
				}
			}
			var saved any
			if haveData {
				req := map[string]any{"path": args[0], "data": data}
				switch {
				case create:
					req["mode"] = "create"
				case update:
					req["mode"] = "update"
				}
				setIf(req, "remove_keys", removeKeys)
				setIf(req, "scope", scope)
				if plan.empty() {
					return a.call1(cmd, "vault_secrets_upsert", req)
				}
				// Both steps must act on the same room, so the save is sent the room the settings step uses (a left-out
				// scope means the workspace room, what the API uses when it is not told).
				req["scope"] = room
				if saved, err = a.invoke(cmd, "vault_secrets_upsert", req, false); err != nil {
					return err
				}
				if !a.flags.json {
					if err := a.emit(saved); err != nil {
						return err
					}
				}
			}
			details, err := a.applySettings(cmd, api, room, args[0], plan)
			if err != nil {
				if a.flags.json {
					_ = render.JSON(a.Out, map[string]any{"saved": saved, "settings": nil})
				}
				if haveData {
					return &ExitErr{Code: ExitError, Err: fmt.Errorf("the secret was saved, but its settings were not changed: %w", err)}
				}
				return &ExitErr{Code: ExitError, Err: fmt.Errorf("the settings were not changed: %w", err)}
			}
			if a.flags.json {
				return render.JSON(a.Out, map[string]any{"saved": saved, "settings": details})
			}
			a.printSettingsDone(a.Out, args[0], plan)
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", scopeHelp)
	cmd.Flags().StringVar(&dataJSON, "data", "", "secret data as a JSON object (on the command line: stays in shell history; prefer --data-file)")
	cmd.Flags().StringVar(&dataFile, "data-file", "", "secret data JSON file (\"-\" for stdin); keeps values out of the command line")
	cmd.Flags().StringArrayVarP(&kv, "field", "d", nil, "secret field as key=@file (value read from a file; preferred) or key=value (stays in shell history); repeatable; blank keeps the stored value with --update")
	cmd.Flags().BoolVar(&create, "create", false, "create only: fail if the secret already exists")
	cmd.Flags().BoolVar(&update, "update", false, "merge into the existing secret (blank value keeps the stored one)")
	cmd.Flags().StringArrayVar(&removeKeys, "remove-key", nil, "field to delete from the secret (repeatable; needs --update)")
	cmd.Flags().StringVar(&description, "description", "", "what the secret is for, up to 500 characters (\"\" clears it)")
	cmd.Flags().StringArrayVar(&labels, "label", nil, "label k=v (repeatable); --label k is a tag with no value; labels you do not name are kept")
	cmd.Flags().StringArrayVar(&removeLabels, "remove-label", nil, "label to remove (repeatable)")
	cmd.Flags().StringVar(&keepVersions, "keep-versions", "", "keep the last N versions (1 to 100) or \"default\"; saves one more version; a lower N removes the oldest for good")
	cmd.Flags().StringVar(&expireAfter, "expire-after", "", "move to Recently deleted this long after the last save: 1h, 7d, 90d (1 hour to 365 days) or \"never\"; saves one more version")
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp+" (used for the settings flags)")
	return cmd
}

// ---- API access (fetch, check, get) ------------------------------------------------

const apiURLHelp = "API address (default: derived from the Platform MCP URL, mcp. becomes api.; env " + bffclient.EnvAPIURL + ")"

// apiClient builds the API client from the same access key every other command uses.
func (a *App) apiClient(apiURL string) (*bffclient.Client, error) {
	if err := a.loadConfig(); err != nil {
		return nil, err
	}
	if a.resolved.Token == "" {
		return nil, &ExitErr{Code: ExitError, Err: errors.New("not logged in: run `agentruntime login` or set AGENTRUNTIME_PAT")}
	}
	base := strings.TrimSpace(apiURL)
	if base == "" {
		base = strings.TrimSpace(os.Getenv(bffclient.EnvAPIURL))
	}
	if base == "" {
		d, err := bffclient.DeriveAPIURL(a.resolved.URL)
		if err != nil {
			return nil, &ExitErr{Code: ExitError, Err: fmt.Errorf("%w; pass --api-url or set %s", err, bffclient.EnvAPIURL)}
		}
		base = d
	}
	c, err := bffclient.New(base, a.resolved.Token)
	if err != nil {
		return nil, &ExitErr{Code: ExitError, Err: err}
	}
	return c, nil
}

// explainAPI turns a client error into a CLI error. Server answers carry a fixed
// sentence and code; nothing here can hold a value.
func (a *App) explainAPI(err error) error {
	var ae *bffclient.APIError
	if !errors.As(err, &ae) {
		return a.explain(err)
	}
	// A 401 for a key the profile says has expired is that, not a mystery: say so.
	if ae.Status == http.StatusUnauthorized && a.storedKeyExpired() {
		return &ExitErr{Code: ExitError, Err: errors.New("your short-lived key expired; sign in again")}
	}
	msg := ae.Error()
	switch {
	case ae.Code == "ambiguous_ref" && len(ae.Rooms) > 0:
		msg += fmt.Sprintf("\nThe name exists in: %s. Write the room in front of the name (for example %s/<name>) to choose one.",
			strings.Join(ae.Rooms, ", "), ae.Rooms[0])
	case ae.Code == "rate_limited" && ae.RetryAfter != "":
		msg += fmt.Sprintf("\nTry again in %s seconds.", ae.RetryAfter)
	}
	return &ExitErr{Code: ExitError, Err: errors.New(msg)}
}

// storedKeyExpired reports whether the key in use is the saved profile's and the expiry stored with it has passed.
// A key from a flag or the environment has no stored expiry, so this is false for it.
func (a *App) storedKeyExpired() bool {
	exp := a.resolved.TokenExpiresAt
	return !exp.IsZero() && !a.nowTime().Before(exp)
}

// keyExpiryWarning is how close to its end a key must be before a command says so.
const keyExpiryWarning = 10 * time.Minute

// noteKeyExpiry tells the person, on standard error, that the key is about to stop working. The server reports the
// expiry of a key that has one in a header of the fetch and check answers; nothing is said for a key that does not
// expire or has more than keyExpiryWarning left.
func (a *App) noteKeyExpiry(c *bffclient.Client) {
	exp, ok := c.KeyExpires()
	if !ok {
		return
	}
	left := exp.Sub(a.nowTime())
	if left >= keyExpiryWarning {
		return
	}
	fmt.Fprintf(a.Err, "%s this key expires in %s\n", a.stderr.Yellow("note:"), timeLeft(left))
}

// timeLeft says how long is left in whole minutes, rounded down, so it never promises more than there is.
func timeLeft(d time.Duration) string {
	switch m := int(d / time.Minute); {
	case m < 1:
		return "less than a minute"
	case m == 1:
		return "1 minute"
	default:
		return fmt.Sprintf("%d minutes", m)
	}
}

// fetch makes the one API call for refs. The command timeout applies to the call only. When the key is close to
// its end, the person is told.
func (a *App) fetch(cmd *cobra.Command, c *bffclient.Client, refs []string) (map[string]bffclient.Value, error) {
	ctx, cancel := a.context(cmd)
	defer cancel()
	values, err := c.Fetch(ctx, refs)
	if err != nil {
		return nil, a.explainAPI(err)
	}
	a.noteKeyExpiry(c)
	return values, nil
}

// parseRef parses one reference; a failure names where it came from, never the text.
func parseRef(label, s string) (secrets.Ref, error) {
	r, err := secrets.Parse(s)
	if err != nil {
		return secrets.Ref{}, fmt.Errorf("%s: %w", label, err)
	}
	return r, nil
}

// uniqueRefs returns each distinct normalized reference once, in first-seen order.
func uniqueRefs(refs []secrets.Ref) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range refs {
		if s := r.String(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func tooManyRefs(n int) error {
	return fmt.Errorf("at most %d different references per command (got %d; every field named after a # counts as one)", secrets.MaxRefsPerCall, n)
}

func (a *App) secretsCheckCmd() *cobra.Command {
	var apiURL string
	cmd := &cobra.Command{
		Use:   "check <ref>...",
		Short: "Say whether each reference would resolve for this access key (no value returned)",
		Long: `Asks the server whether each reference would resolve for this access key right
now, without returning a value or using up one of the key's uses. Prints "ok"
or "not available" per reference. "not available" never says why: the secret
may be missing, not on the key's list, or not viewable by the key's owner.

A reference may name several fields, REF#F1,F2, the way run's --env-from does;
each field is answered on its own line.

Exit code 0 when every reference resolves, 1 when any does not.`,
		Example: `  agentruntime secrets check workspace/live/stripe#API_KEY my/deploy
  agentruntime secrets check workspace/live/stripe#API_KEY,WEBHOOK_SECRET`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var parsed []secrets.Ref
			for i, s := range args {
				label := fmt.Sprintf("argument %d", i+1)
				// REF#F1,F2 checks each named field, the way run takes them.
				named, err := secrets.ParseNamed(s)
				switch {
				case err == nil:
					parsed = append(parsed, named.Refs()...)
				case errors.Is(err, secrets.ErrNoFieldNames):
					r, err := parseRef(label, s) // a whole secret (there is no '#')
					if err != nil {
						return &ExitErr{Code: ExitUsage, Err: err}
					}
					parsed = append(parsed, r)
				case errors.Is(err, secrets.ErrWildcardFields):
					return &ExitErr{Code: ExitUsage, Err: fmt.Errorf("%s: '*' is not accepted: name the fields (REF#F1,F2), or leave out '#*' to check the whole secret", label)}
				default:
					return &ExitErr{Code: ExitUsage, Err: fmt.Errorf("%s: %w", label, err)}
				}
			}
			refs := uniqueRefs(parsed)
			if len(refs) > secrets.MaxRefsPerCall {
				return &ExitErr{Code: ExitUsage, Err: tooManyRefs(len(refs))}
			}
			c, err := a.apiClient(apiURL)
			if err != nil {
				return err
			}
			ctx, cancel := a.context(cmd)
			defer cancel()
			items, err := c.Check(ctx, refs)
			if err != nil {
				return a.explainAPI(err)
			}
			a.noteKeyExpiry(c)
			byRef := make(map[string]bool, len(items))
			for _, it := range items {
				byRef[it.Ref] = it.Resolves
			}
			out := make([]bffclient.CheckItem, 0, len(refs))
			for _, r := range refs {
				ok, answered := byRef[r]
				if !answered {
					return &ExitErr{Code: ExitError, Err: errors.New("the server did not answer for every reference")}
				}
				out = append(out, bffclient.CheckItem{Ref: r, Resolves: ok})
			}
			allOK := true
			for _, it := range out {
				allOK = allOK && it.Resolves
			}
			if a.flags.json {
				if err := render.JSON(a.Out, map[string]any{"items": out}); err != nil {
					return err
				}
			} else {
				for _, it := range out {
					status := a.stdout.Green("ok")
					if !it.Resolves {
						status = a.stdout.Red("not available")
					}
					fmt.Fprintf(a.Out, "%s: %s\n", it.Ref, status)
				}
			}
			if !allOK {
				return &ExitErr{Code: ExitError}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}

// stdoutIsTerminal reports whether standard output is a terminal.
func (a *App) stdoutIsTerminal() bool {
	if a.isTTYOut != nil {
		return a.isTTYOut()
	}
	f, ok := a.Out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// printForTerminal renders what a person asked to see on their terminal, and
// shows any character a terminal would act on as \xNN (see terminalSafe). A value
// is arbitrary text that whoever can write the secret chose, so it must not be
// able to move the cursor, change the window title or write to the clipboard.
func (a *App) printForTerminal(render func(io.Writer) error) error {
	var buf bytes.Buffer
	if err := render(&buf); err != nil {
		return err
	}
	safe, n := terminalSafe(buf.String())
	if _, err := io.WriteString(a.Out, safe); err != nil {
		return err
	}
	if n > 0 {
		fmt.Fprintf(a.Err, "%s %d control character(s) in the value are shown as \\xNN; the value itself is unchanged\n", a.stderr.Yellow("note:"), n)
	}
	return nil
}

// terminalSafe returns s with every character a terminal would act on, rather
// than show, replaced by \xNN (the character's code in hex), and how many were
// replaced. That is every control character except newline and tab: ESC starts
// the sequences that move the cursor, set the window title or write to the
// clipboard, and a carriage return can overwrite what was printed before it. DEL
// and the C1 range U+0080 to U+009F go too, since many terminals read those as
// the 8-bit forms of the same controls. A byte that is not valid UTF-8 is shown
// the same way.
func terminalSafe(s string) (string, int) {
	var sb strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&sb, `\x%02x`, s[i])
			n++
		case r == '\n' || r == '\t':
			sb.WriteRune(r)
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			fmt.Fprintf(&sb, `\x%02x`, r)
			n++
		default:
			sb.WriteString(s[i : i+size])
		}
		i += size
	}
	return sb.String(), n
}

func (a *App) secretsGetCmd() *cobra.Command {
	var printIt bool
	var apiURL string
	cmd := &cobra.Command{
		Use:   "get <ref> --print",
		Short: "Print one secret value, only when standard output is a terminal",
		Long: `Prints a secret value for a person at a terminal. When standard output is
redirected or piped (which is always the case for a coding agent's shell) it
refuses with exit code 2 and fetches nothing, so a value cannot land in an AI
tool's context by accident. To give a value to a program use "secrets run" or
--secret-file.

With #field the value is printed as it is; for a whole secret, as JSON. Control
characters in a value (other than newline and tab), the escape character and the
8-bit control range are shown as \xNN, so a value cannot move the cursor or write
to the clipboard through your terminal.`,
		Example: `  agentruntime secrets get workspace/live/stripe#API_KEY --print`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !printIt {
				return &ExitErr{Code: ExitUsage, Err: errors.New(
					"add --print to show the value (it prints only on a terminal); to give it to a program use `agentruntime secrets run`")}
			}
			if !a.stdoutIsTerminal() {
				return &ExitErr{Code: ExitUsage, Err: errors.New(
					"refusing to print a secret value: standard output is not a terminal. " +
						"Use `agentruntime secrets run` or --secret-file to hand the value to a program")}
			}
			ref, err := parseRef("reference", args[0])
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			c, err := a.apiClient(apiURL)
			if err != nil {
				return err
			}
			key := ref.String()
			values, err := a.fetch(cmd, c, []string{key})
			if err != nil {
				return err
			}
			v := values[key]
			if v.IsObject != ref.Whole() {
				return &ExitErr{Code: ExitError, Err: errors.New("unexpected answer from the server (wrong kind of value)")}
			}
			var shown any = v.String
			if v.IsObject {
				shown = v.Fields
			}
			switch {
			case a.flags.json:
				return a.printForTerminal(func(w io.Writer) error {
					return render.JSON(w, map[string]any{"values": map[string]any{key: shown}})
				})
			case v.IsObject:
				return a.printForTerminal(func(w io.Writer) error { return render.JSON(w, shown) })
			}
			return a.printForTerminal(func(w io.Writer) error {
				_, err := fmt.Fprintln(w, v.String)
				return err
			})
		},
	}
	cmd.Flags().BoolVar(&printIt, "print", false, "print the value (terminal only)")
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}
