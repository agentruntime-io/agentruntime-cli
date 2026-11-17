package cli

// `agentruntime secrets handover`: give one secret to one person (or one machine) once.
//
// The command asks the API for a one-time access key: it can fetch exactly one secret, exactly once, and stops
// working within 24 hours. The value itself never moves; the person who receives the key fetches it. The key's
// token is shown only here, only to a terminal, only once, and is never written to a file.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/bffclient"
	"github.com/agentruntime-io/agentruntime-cli/internal/render"
	"github.com/agentruntime-io/agentruntime-cli/internal/secrets"
)

const handoverLong = `Makes a one-time access key for one secret and prints its token, so you can hand
the secret to someone without ever pasting the value into a chat or an email.

The key can fetch exactly what you name, exactly once, and stops working after
--ttl (1 minute to 24 hours, default 1h), whichever comes first. Whoever holds the
token can read the value once, so send it the way you would send a password, and
never paste it into an AI tool. The token is shown only here. You must be allowed
to view the secret, and your access key must be allowed to fetch it. Fetching must
be on for the workspace.

The reference must name its room (my/, project/ or workspace/); a name without a
room is refused, because a hand-over never guesses. What the key can fetch depends
on whether the reference has #FIELD, and the server enforces it:

  REF#FIELD   the key can fetch only that one field of the secret, nothing else
              (not the other fields of the same secret)
  REF         the key can fetch the whole secret: every field in it

The token is printed only when standard output is a terminal. Redirected or piped
(which is always the case for a coding agent's shell) the command refuses with
exit code 2 and makes nothing, with or without --json: a key whose token cannot be
shown to anyone would only be a loose end. It never writes the token to a file.
With --json on a terminal the token is part of the JSON.

Whoever receives the token uses it like any access key, with the same REF you gave
here (the command prints both lines for you):

  AGENTRUNTIME_PAT=<token> agentruntime secrets get REF --print
  curl -X POST <api>/v1/secrets/fetch -H "Authorization: Bearer <token>" ...

Every hand-over is written to the workspace's audit log.`

func (a *App) secretsHandoverCmd() *cobra.Command {
	var ttl, apiURL string
	cmd := &cobra.Command{
		Use:   "handover <ref> [--ttl 1h]",
		Short: "Make a one-time key that lets someone fetch one secret once (terminal only)",
		Long:  handoverLong,
		Example: `  agentruntime secrets handover workspace/live/stripe#API_KEY
  agentruntime secrets handover workspace/live/stripe --ttl 15m
  agentruntime secrets handover my/deploy#TOKEN --ttl 24h`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := parseRef("reference", args[0])
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			if ref.Room == "" {
				return &ExitErr{Code: ExitUsage, Err: errors.New(
					"a hand-over needs the room in the name: my/<name>, project/<name> or workspace/<name> (it never guesses a room)")}
			}
			seconds, err := parseHandoverTTL(ttl)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			if !a.stdoutIsTerminal() {
				// Nothing is made, with or without --json: the token is shown only on a terminal, so a key made here
				// would be one nobody can use, a loose end that stays valid until it expires.
				return &ExitErr{Code: ExitUsage, Err: errors.New(
					"refusing to make a one-time key: standard output is not a terminal, so its token could not be shown safely " +
						"(this holds with --json too). Run this in a terminal and give the token to the person who needs it")}
			}
			c, err := a.apiClient(apiURL)
			if err != nil {
				return err
			}
			ctx, cancel := a.context(cmd)
			defer cancel()
			res, err := c.Handover(ctx, ref.String(), seconds)
			if err != nil {
				return a.explainAPI(err)
			}
			if err := checkHandoverAnswer(ref, res); err != nil {
				return err
			}
			return a.printHandover(c, ref, seconds, res)
		},
	}
	cmd.Flags().StringVar(&ttl, "ttl", "1h", "how long the key stays valid, from 1m to 24h: 15m, 1h, 24h (it also stops after one use)")
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}

// parseHandoverTTL reads --ttl: a whole number with a unit s, m, h or d (90s, 15m, 1h, 1d), or a Go duration such
// as 1h30m, from one minute to 24 hours.
func parseHandoverTTL(s string) (int, error) {
	if secs, ok := parseSpanSeconds(s, bffclient.MinHandoverTTLSeconds, bffclient.MaxHandoverTTLSeconds); ok {
		return secs, nil
	}
	return 0, fmt.Errorf("--ttl must be from 1m to 24h, for example 15m, 1h or 24h (got %q)", s)
}

// parseSpanSeconds reads a lifetime: a whole number with a unit s, m, h or d (90s, 15m, 1h, 1d), or a Go duration
// such as 1h30m. ok is false when it cannot be read, is not a whole number of seconds, or is outside lo to hi
// seconds.
func parseSpanSeconds(s string, lo, hi int) (secs int, ok bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, false
	}
	var d time.Duration
	if unit := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour}[t[len(t)-1]]; unit != 0 {
		if n, err := strconv.Atoi(t[:len(t)-1]); err == nil && n >= 1 && n <= 86400 {
			d = time.Duration(n) * unit
		}
	}
	if d == 0 {
		var err error
		if d, err = time.ParseDuration(t); err != nil {
			return 0, false
		}
	}
	if d%time.Second != 0 || d < time.Duration(lo)*time.Second || d > time.Duration(hi)*time.Second {
		return 0, false
	}
	return int(d / time.Second), true
}

// checkHandoverAnswer makes sure the key the server made is the one that was asked for, before the token is shown.
// What the output tells the person (what the key can fetch, that it works once) comes from what they typed, so it is
// only true if the answer says the same: a key for another reference, or one that can be used more than once, is not
// handed on. The key exists by then, so the message says where to revoke it.
func checkHandoverAnswer(asked secrets.Ref, res *bffclient.HandoverResult) error {
	const revoke = "Its token was not printed and nothing was shared. Revoke the key under Settings, API keys, Short-lived access (or let it expire)."
	if res.Ref != asked.String() {
		answered := "no reference"
		if res.Ref != "" {
			answered = "the reference " + safeLine(truncateRunes(res.Ref, 120))
		}
		return &ExitErr{Code: ExitError, Err: fmt.Errorf(
			"the server made a one-time key for %s, not for the reference you asked for (%s). %s",
			answered, safeLine(asked.String()), revoke)}
	}
	if res.Uses != 1 {
		return &ExitErr{Code: ExitError, Err: fmt.Errorf(
			"the server made a key that can be used %d times, not once as a hand-over must be. %s", res.Uses, revoke)}
	}
	return nil
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// printHandover shows the result. It is called only when standard output is a terminal. The token appears once;
// the lines that tell the receiver what to do carry a <token> placeholder, not the token, and name the same reference
// that was sent, #FIELD included, because the key can fetch exactly that and nothing else.
func (a *App) printHandover(c *bffclient.Client, ref secrets.Ref, ttlSeconds int, res *bffclient.HandoverResult) error {
	if a.flags.json {
		return render.JSON(a.Out, map[string]any{"ref": res.Ref, "expires_at": res.ExpiresAt, "uses": res.Uses, "token": res.Token})
	}

	refText := ref.String()
	expires := ""
	if res.ExpiresAt != "" {
		expires = " (until " + safeLine(res.ExpiresAt) + ")"
	}
	w := a.Out
	fmt.Fprintf(w, "One-time key for %s\n", a.stdout.Bold(safeLine(refText)))
	if ref.Whole() {
		fmt.Fprintln(w, "It can fetch the WHOLE secret (every field in it), and nothing else.")
	} else {
		fmt.Fprintf(w, "It can fetch only the field %s of that secret, and nothing else (not its other fields).\n", safeLine(ref.Field))
	}
	fmt.Fprintf(w, "It works once, then it stops. It is valid for %s%s, whichever ends first.\n", humanDuration(ttlSeconds), expires)
	fmt.Fprintln(w, "Anyone who has it can read this value once. Do not paste it into an AI tool.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, res.Token)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "To use it, put the key where <token> is (the reference is the one you gave, and the only one the key can fetch):")
	fmt.Fprintf(w, "  AGENTRUNTIME_PAT=<token> agentruntime secrets get %s --print\n", shellQuote(refText))
	fmt.Fprintf(w, "  curl -sS -X POST %s/v1/secrets/fetch -H \"Authorization: Bearer <token>\" -H \"Content-Type: application/json\" -d %s\n",
		safeLine(c.BaseURL()), shellSingleQuote(curlBody(refText)))
	return nil
}

// curlBody is the request body for fetching one reference.
func curlBody(ref string) string {
	b, _ := json.Marshal(map[string][]string{"refs": {ref}})
	return string(b)
}

// shellSingleQuote wraps s in single quotes for a POSIX shell.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
