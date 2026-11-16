package cli

// History, restore, Recently deleted, undelete, permanent delete, and the settings flags of `secrets set`.
//
// These commands call the API directly with the same access key as every other command (the Platform MCP cannot
// show the X-Recoverable header that tells a delete from a recoverable one). None of them reads or prints a secret's
// value: history shows who changed a secret and the NAMES of the fields they changed, never what is in them.

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/bffclient"
	"github.com/agentruntime-io/agentruntime-cli/internal/render"
)

const (
	keepVersionsMin = 1
	keepVersionsMax = 100
	expireMinSecs   = 3600     // 1 hour
	expireMaxSecs   = 31536000 // 365 days
	maxLabels       = 10
	maxDescription  = 500
	maxLabelValue   = 100
)

// labelKeyRE is the key of a label: lower-case letters, digits, dot, underscore and dash, starting with a letter or digit.
var labelKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)

// vaultScope checks --scope of the commands that act on one secret. A left-out scope is the workspace room (what
// the API uses when it is not told). A secret shared with you is read-only, so it is refused here with a pointer
// to its real room.
func vaultScope(scope string) (string, error) {
	switch s := strings.ToLower(strings.TrimSpace(scope)); s {
	case "":
		return "tenant", nil
	case "user", "project", "tenant":
		return s, nil
	case "shared":
		return "", errors.New("a secret shared with you is read-only here: use the room it really lives in (--scope user, project or tenant)")
	default:
		return "", fmt.Errorf("--scope must be user, project or tenant (got %q)", scope)
	}
}

// vaultScopeHelp is the --scope help of the commands in this file.
const vaultScopeHelp = "room: user (My secrets), project or tenant (workspace; the default)"

// safeLine makes text from the server fit on one line of a terminal: control characters, the escape character and
// the invisible format characters (zero-width, direction marks) are shown as \xNN or \uNNNN, and runs of white space
// become one space. A secret's path, a field name, a label or a description is whatever its author typed.
func safeLine(s string) string {
	safe, _ := terminalSafe(s)
	var sb strings.Builder
	for _, r := range safe {
		if unicode.Is(unicode.Cf, r) {
			fmt.Fprintf(&sb, `\u%04x`, r)
			continue
		}
		sb.WriteRune(r)
	}
	return strings.Join(strings.Fields(sb.String()), " ")
}

func joinSafe(list []string) string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, safeLine(s))
	}
	return strings.Join(out, ", ")
}

// humanDuration writes a number of seconds the way --expire-after reads it: 7d, 36h, 90m.
func humanDuration(secs int) string {
	switch {
	case secs%86400 == 0:
		return fmt.Sprintf("%dd", secs/86400)
	case secs%3600 == 0:
		return fmt.Sprintf("%dh", secs/3600)
	case secs%60 == 0:
		return fmt.Sprintf("%dm", secs/60)
	}
	return fmt.Sprintf("%ds", secs)
}

// parseExpireAfter reads --expire-after: "never", or a whole number with a unit s, m, h, d or w (1h, 7d, 90d).
func parseExpireAfter(s string) (bffclient.OptInt, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "never" {
		return bffclient.Reset(), nil
	}
	bad := fmt.Errorf("--expire-after must be never, or a whole number with a unit (s, m, h, d, w), from 1h to 365d: for example 1h, 7d or 90d (got %q)", s)
	if len(t) < 2 {
		return bffclient.OptInt{}, bad
	}
	unit := map[byte]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[t[len(t)-1]]
	n, err := strconv.Atoi(t[:len(t)-1])
	if unit == 0 || err != nil || n < 1 || n > expireMaxSecs {
		return bffclient.OptInt{}, bad
	}
	secs := n * unit
	if secs < expireMinSecs || secs > expireMaxSecs {
		return bffclient.OptInt{}, fmt.Errorf("--expire-after must be between 1h and 365d (got %q)", s)
	}
	return bffclient.Number(secs), nil
}

// parseKeepVersions reads --keep-versions: "default", or a number from 1 to 100.
func parseKeepVersions(s string) (bffclient.OptInt, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "default" {
		return bffclient.Reset(), nil
	}
	n, err := strconv.Atoi(t)
	if err != nil || n < keepVersionsMin || n > keepVersionsMax {
		return bffclient.OptInt{}, fmt.Errorf("--keep-versions must be default, or a number from %d to %d (got %q)", keepVersionsMin, keepVersionsMax, s)
	}
	return bffclient.Number(n), nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// parseLabel reads --label k=v, or --label k for a tag (a label with no value).
func parseLabel(s string) (key, value string, err error) {
	key, value, _ = strings.Cut(s, "=")
	key = strings.TrimSpace(key)
	if !labelKeyRE.MatchString(key) {
		return "", "", fmt.Errorf("--label key %q must be lower-case letters, digits, '.', '_' or '-', start with a letter or digit, and be at most 40 characters", key)
	}
	if len([]rune(value)) > maxLabelValue || hasControl(value) {
		return "", "", fmt.Errorf("--label %s: the value must be at most %d characters, with no control characters", key, maxLabelValue)
	}
	return key, value, nil
}

// settingsPlan is what the settings flags of `secrets set` ask for.
type settingsPlan struct {
	change      bffclient.SettingsChange // description, keep-versions and expire-after
	addLabels   map[string]string
	dropLabels  []string
	labelsAsked bool
}

func (p settingsPlan) empty() bool {
	return p.change.Empty() && !p.labelsAsked
}

// buildSettingsPlan checks every settings flag before anything is sent, so a typo never leaves a half-done change.
func buildSettingsPlan(cmd *cobra.Command, description string, labels, removeLabels []string, keep, expire string) (settingsPlan, error) {
	var p settingsPlan
	if cmd.Flags().Changed("description") {
		if len([]rune(description)) > maxDescription || hasControl(description) {
			return p, fmt.Errorf("--description must be at most %d characters, with no control characters", maxDescription)
		}
		d := description
		p.change.Description = &d
	}
	p.addLabels = map[string]string{}
	for _, l := range labels {
		k, v, err := parseLabel(l)
		if err != nil {
			return p, err
		}
		if _, dup := p.addLabels[k]; dup {
			return p, fmt.Errorf("--label %s is given twice", k)
		}
		p.addLabels[k] = v
	}
	seen := map[string]bool{}
	for _, k := range removeLabels {
		k = strings.TrimSpace(k)
		if !labelKeyRE.MatchString(k) {
			return p, fmt.Errorf("--remove-label %q is not a valid label key", k)
		}
		if _, both := p.addLabels[k]; both {
			return p, fmt.Errorf("label %q is both set and removed", k)
		}
		if !seen[k] {
			seen[k] = true
			p.dropLabels = append(p.dropLabels, k)
		}
	}
	p.labelsAsked = len(p.addLabels) > 0 || len(p.dropLabels) > 0
	if len(p.addLabels) > maxLabels {
		return p, fmt.Errorf("a secret has at most %d labels", maxLabels)
	}
	var err error
	if cmd.Flags().Changed("keep-versions") {
		if p.change.KeepVersions, err = parseKeepVersions(keep); err != nil {
			return p, err
		}
	}
	if cmd.Flags().Changed("expire-after") {
		if p.change.ExpireAfterSeconds, err = parseExpireAfter(expire); err != nil {
			return p, err
		}
	}
	return p, nil
}

// savesAVersion reports whether the settings change makes the API save one more version (keep-versions and expire-after do, so they apply at once).
func (p settingsPlan) savesAVersion() bool {
	return p.change.KeepVersions.Set || p.change.ExpireAfterSeconds.Set
}

// applySettings sends the settings after the save. Labels are replaced as a whole by the API, so --label and
// --remove-label first read the secret's current labels and change only the ones named.
func (a *App) applySettings(cmd *cobra.Command, c *bffclient.Client, scope, path string, p settingsPlan) (*bffclient.Details, error) {
	ctx, cancel := a.context(cmd)
	defer cancel()
	change := p.change
	if p.labelsAsked {
		h, err := c.History(ctx, scope, path)
		if err != nil {
			return nil, fmt.Errorf("could not read the current labels, so no label was changed: %s", a.explainAPI(err))
		}
		merged := map[string]string{}
		for k, v := range h.Labels {
			merged[k] = v
		}
		for _, k := range p.dropLabels {
			delete(merged, k)
		}
		for k, v := range p.addLabels {
			merged[k] = v
		}
		if len(merged) > maxLabels {
			return nil, fmt.Errorf("a secret has at most %d labels (it would have %d)", maxLabels, len(merged))
		}
		change.Labels = merged
	}
	d, err := c.UpdateSettings(ctx, scope, path, change)
	if err != nil {
		return nil, fmt.Errorf("%s", a.explainAPI(err))
	}
	return d, nil
}

// describe lists the settings the plan changes, for the line printed after they changed.
func (p settingsPlan) describe() string {
	var parts []string
	if p.change.Description != nil {
		parts = append(parts, "description")
	}
	if p.labelsAsked {
		parts = append(parts, "labels")
	}
	if p.change.KeepVersions.Set {
		parts = append(parts, "keep-versions")
	}
	if p.change.ExpireAfterSeconds.Set {
		parts = append(parts, "expire-after")
	}
	return strings.Join(parts, ", ")
}

// ---- history ------------------------------------------------------------------------

func (a *App) secretsHistoryCmd() *cobra.Command {
	var scope, apiURL string
	cmd := &cobra.Command{
		Use:     "history <path>",
		Aliases: []string{"versions"},
		Short:   "Show who changed a secret and when (never the values)",
		Long: `Shows a secret's versions: the number, when, who saved it, what kind of save it
was, and the NAMES of the fields it added, changed or removed. It never shows a
value. Older values can be viewed in the Console, by a person.

Also shown: how many versions are kept, when the secret expires (if it does), its
description and labels. 'state' is current, available, deleted or destroyed.

--json prints the same as JSON.`,
		Example: `  agentruntime secrets history live/stripe --scope tenant
  agentruntime secrets history my-app/db --scope user --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			room, err := vaultScope(scope)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			c, err := a.apiClient(apiURL)
			if err != nil {
				return err
			}
			ctx, cancel := a.context(cmd)
			defer cancel()
			h, err := c.History(ctx, room, args[0])
			if err != nil {
				return a.explainAPI(err)
			}
			if a.flags.json {
				return render.JSON(a.Out, h)
			}
			a.printHistory(args[0], room, h)
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", vaultScopeHelp)
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}

// versionSummary says what a version did beyond its kind (which has its own column): where a restore came from,
// and the field names it added, changed and removed.
func versionSummary(v bffclient.Version) string {
	var parts []string
	switch v.Kind {
	case "restore":
		if v.RestoredFrom > 0 {
			parts = append(parts, fmt.Sprintf("restored from version %d", v.RestoredFrom))
		} else {
			parts = append(parts, "restored from an older version")
		}
	case "settings":
		parts = append(parts, "settings changed")
	case "unknown":
		parts = append(parts, "saved before history was recorded")
	}
	if len(v.KeysAdded) > 0 {
		parts = append(parts, "added "+joinSafe(v.KeysAdded))
	}
	if len(v.KeysChanged) > 0 {
		parts = append(parts, "changed "+joinSafe(v.KeysChanged))
	}
	if len(v.KeysRemoved) > 0 {
		parts = append(parts, "removed "+joinSafe(v.KeysRemoved))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "; ")
}

func (a *App) printHistory(path, scope string, h *bffclient.History) {
	fmt.Fprintf(a.Out, "%s (%s)  current version %d\n", a.stdout.Bold(safeLine(path)), scope, h.CurrentVersion)
	if h.KeepVersions == nil {
		fmt.Fprintln(a.Out, "Keeps:        the workspace default number of versions")
	} else {
		fmt.Fprintf(a.Out, "Keeps:        the last %d versions\n", *h.KeepVersions)
	}
	switch {
	case h.ExpireAfterSeconds == nil:
		fmt.Fprintln(a.Out, "Auto-expire:  never")
	case h.ExpiresAt != nil && *h.ExpiresAt != "":
		fmt.Fprintf(a.Out, "Auto-expire:  %s after the last save (expires %s)\n", humanDuration(*h.ExpireAfterSeconds), safeLine(*h.ExpiresAt))
	default:
		fmt.Fprintf(a.Out, "Auto-expire:  %s after the last save\n", humanDuration(*h.ExpireAfterSeconds))
	}
	if h.Description != "" {
		fmt.Fprintf(a.Out, "Description:  %s\n", safeLine(h.Description))
	}
	if len(h.Labels) > 0 {
		fmt.Fprintf(a.Out, "Labels:       %s\n", labelList(h.Labels))
	}
	fmt.Fprintln(a.Out)
	if len(h.Versions) == 0 {
		fmt.Fprintln(a.Out, a.stdout.Dim("(no versions listed)"))
		return
	}
	rows := make([][]string, 0, len(h.Versions))
	for _, v := range h.Versions {
		by := "-"
		switch {
		case v.WrittenByName != "" && v.WrittenByUserID != "":
			by = safeLine(v.WrittenByName) + " (" + safeLine(v.WrittenByUserID) + ")"
		case v.WrittenByName != "":
			by = safeLine(v.WrittenByName)
		case v.WrittenByUserID != "":
			by = safeLine(v.WrittenByUserID)
		}
		when := safeLine(v.WrittenAt)
		if when == "" {
			when = "-"
		}
		state := safeLine(v.State)
		if state == "" {
			state = "-"
		}
		kind := safeLine(v.Kind)
		if kind == "" {
			kind = "-"
		}
		rows = append(rows, []string{strconv.Itoa(v.Version), state, when, by, kind, versionSummary(v)})
	}
	render.Table(a.Out, a.stdout, []string{"version", "state", "when", "by", "kind", "what"}, rows, 80)
}

// labelList writes labels as k=v, a label with no value as the bare key, in key order.
func labelList(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if v := labels[k]; v != "" {
			out = append(out, safeLine(k)+"="+safeLine(v))
		} else {
			out = append(out, safeLine(k))
		}
	}
	return strings.Join(out, ", ")
}

// ---- restore ------------------------------------------------------------------------

func (a *App) secretsRestoreCmd() *cobra.Command {
	var scope, apiURL string
	var version int
	cmd := &cobra.Command{
		Use:   "restore <path> --version N",
		Short: "Write an older version back as a new version",
		Long: `Writes version N of a secret back as a NEW current version: nothing is lost, the
version it replaces stays in the history. You never see the value; it is read and
written inside the API. Needs the right to change the secret.

  already_current  that version already is the current one
  conflict         the secret changed in the meantime; nothing was written
  version_unavailable  that version is gone

Use "secrets history" to see the versions.`,
		Example: `  agentruntime secrets restore live/stripe --version 2 --scope tenant`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if version < 1 {
				return &ExitErr{Code: ExitUsage, Err: errors.New("--version is required: the number of the version to bring back (see `secrets history`)")}
			}
			room, err := vaultScope(scope)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			c, err := a.apiClient(apiURL)
			if err != nil {
				return err
			}
			ctx, cancel := a.context(cmd)
			defer cancel()
			res, err := c.Restore(ctx, room, args[0], version)
			if err != nil {
				return a.explainAPI(err)
			}
			if a.flags.json {
				return render.JSON(a.Out, map[string]any{"restored": true, "path": args[0], "scope": room, "restored_from": version, "version": res.Version})
			}
			if res.Version > 0 {
				fmt.Fprintf(a.Out, "Restored version %d of %s as version %d.\n", version, safeLine(args[0]), res.Version)
			} else {
				fmt.Fprintf(a.Out, "Restored version %d of %s as a new version.\n", version, safeLine(args[0]))
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&version, "version", 0, "the version to restore (required)")
	cmd.Flags().StringVar(&scope, "scope", "", vaultScopeHelp)
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}

// ---- Recently deleted ---------------------------------------------------------------

func (a *App) secretsDeletedCmd() *cobra.Command {
	var scope, apiURL string
	cmd := &cobra.Command{
		Use:   "deleted",
		Short: "List Recently deleted secrets (and secrets whose auto-expire passed)",
		Long: `Lists the room's Recently deleted secrets: ones that were deleted and ones whose
auto-expire has passed (why: deleted or expired). Only people who may delete in
that room see the list. A deleted secret keeps its versions until someone
destroys it; bring one back with "secrets undelete".

When this workspace cannot recover deleted secrets, the command says so: a delete
there is permanent. With --json the answer is {"supported": bool, "items": [...]}.`,
		Example: `  agentruntime secrets deleted --scope tenant`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			room, err := vaultScope(scope)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			c, err := a.apiClient(apiURL)
			if err != nil {
				return err
			}
			ctx, cancel := a.context(cmd)
			defer cancel()
			items, supported, err := c.Deleted(ctx, room)
			if err != nil {
				return a.explainAPI(err)
			}
			if items == nil {
				items = []bffclient.DeletedSecret{}
			}
			if a.flags.json {
				return render.JSON(a.Out, map[string]any{"supported": supported, "items": items})
			}
			if !supported {
				fmt.Fprintln(a.Out, "This workspace does not support Recently deleted: deleting a secret removes it permanently.")
				return nil
			}
			if len(items) == 0 {
				fmt.Fprintln(a.Out, a.stdout.Dim("Nothing in Recently deleted."))
				return nil
			}
			rows := make([][]string, 0, len(items))
			for _, it := range items {
				by := "-"
				switch {
				case it.DeletedByName != "":
					by = safeLine(it.DeletedByName)
				case it.DeletedByUserID != "":
					by = safeLine(it.DeletedByUserID)
				}
				when := safeLine(it.DeletedAt)
				if when == "" {
					when = "-"
				}
				why := safeLine(it.Reason)
				if why == "" {
					why = "-"
				}
				rows = append(rows, []string{safeLine(it.Path), when, by, why, strconv.Itoa(int(it.Versions))})
			}
			render.Table(a.Out, a.stdout, []string{"path", "deleted", "by", "why", "versions"}, rows, 80)
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", vaultScopeHelp)
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}

func (a *App) secretsUndeleteCmd() *cobra.Command {
	var scope, apiURL string
	cmd := &cobra.Command{
		Use:   "undelete <path>",
		Short: "Bring a secret back from Recently deleted",
		Long: `Brings a secret back from Recently deleted with its versions, owner and sharing as
they were. A secret that expired comes back with its auto-expire turned off, so
it does not vanish again at the next save; set it again with
"secrets set <path> --expire-after 7d" if you still want it. Needs the right to
delete in that room.`,
		Example: `  agentruntime secrets undelete live/stripe --scope tenant`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			room, err := vaultScope(scope)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			c, err := a.apiClient(apiURL)
			if err != nil {
				return err
			}
			ctx, cancel := a.context(cmd)
			defer cancel()
			if err := c.Undelete(ctx, room, args[0]); err != nil {
				return a.explainAPI(err)
			}
			if a.flags.json {
				return render.JSON(a.Out, map[string]any{"undeleted": true, "path": args[0], "scope": room})
			}
			fmt.Fprintf(a.Out, "Restored %s from Recently deleted.\n", safeLine(args[0]))
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", vaultScopeHelp)
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}

// ---- delete (recoverable, or permanent with --destroy --confirm) ---------------------

func (a *App) secretsDeleteCmd() *cobra.Command {
	var scope, apiURL, confirm string
	var yes, destroy bool
	cmd := &cobra.Command{
		Use:     "delete <path>",
		Aliases: []string{"rm"},
		Short:   "Delete a secret (to Recently deleted when the workspace supports it)",
		Long: `Deletes a secret. When the workspace supports it the secret goes to Recently
deleted with all its versions and can be brought back with "secrets undelete";
the command says so. Otherwise the delete is permanent, and the command says that.

--destroy --confirm <path> deletes it for good, every version, also when it is
already in Recently deleted. It refuses unless both flags are given, --confirm
repeats the path exactly, and --scope is given. It works with an access key or in
the Console, not through an AI client.`,
		Example: `  agentruntime secrets delete live/stripe --scope tenant
  agentruntime secrets delete live/stripe --scope tenant --yes
  agentruntime secrets delete live/stripe --scope tenant --destroy --confirm live/stripe`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if confirm != "" && !destroy {
				return &ExitErr{Code: ExitUsage, Err: errors.New("--confirm belongs to --destroy")}
			}
			if destroy {
				if confirm == "" {
					return &ExitErr{Code: ExitUsage, Err: errors.New("--destroy deletes the secret for good: add --confirm with the path repeated exactly (--confirm " + safeLine(path) + ")")}
				}
				if confirm != path {
					return &ExitErr{Code: ExitUsage, Err: errors.New("--confirm must repeat the path exactly as given")}
				}
				if strings.TrimSpace(scope) == "" {
					return &ExitErr{Code: ExitUsage, Err: errors.New("--destroy needs --scope (user, project or tenant), so a permanent delete never lands in a room you did not name")}
				}
			}
			room, err := vaultScope(scope)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			c, err := a.apiClient(apiURL)
			if err != nil {
				return err
			}
			if destroy {
				ctx, cancel := a.context(cmd)
				defer cancel()
				if err := c.Destroy(ctx, room, path, confirm); err != nil {
					return a.explainAPI(err)
				}
				if a.flags.json {
					return render.JSON(a.Out, map[string]any{"destroyed": true, "path": path, "scope": room})
				}
				fmt.Fprintf(a.Out, "Permanently deleted %s, every version.\n", safeLine(path))
				return nil
			}
			if err := a.confirmOrAbort(yes, fmt.Sprintf("Delete secret %s? (It goes to Recently deleted when the workspace supports that; otherwise this is permanent.)", safeLine(path))); err != nil {
				return err
			}
			ctx, cancel := a.context(cmd)
			defer cancel()
			recoverable, err := c.Delete(ctx, room, path)
			if err != nil {
				return a.explainAPI(err)
			}
			if a.flags.json {
				return render.JSON(a.Out, map[string]any{"deleted": true, "recoverable": recoverable, "path": path, "scope": room})
			}
			if recoverable {
				fmt.Fprintf(a.Out, "Moved %s to Recently deleted. Bring it back with: agentruntime secrets undelete %s --scope %s\n",
					safeLine(path), shellQuote(path), room)
			} else {
				fmt.Fprintf(a.Out, "Deleted %s permanently.\n", safeLine(path))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", vaultScopeHelp)
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&destroy, "destroy", false, "delete for good, every version (needs --confirm and --scope)")
	cmd.Flags().StringVar(&confirm, "confirm", "", "with --destroy: the path, repeated exactly")
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}

// shellQuote shows a path in a hint so that it can be copied into a shell: plain paths stay plain.
func shellQuote(s string) string {
	safe := safeLine(s)
	if safe == s && s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!&|;<>()*?[]{}#~") {
		return s
	}
	return "'" + strings.ReplaceAll(safe, "'", `'\''`) + "'"
}

// ---- helpers used by set ------------------------------------------------------------

// printSettingsDone says what the settings step changed.
func (a *App) printSettingsDone(w io.Writer, path string, p settingsPlan) {
	line := fmt.Sprintf("Updated settings of %s: %s.", safeLine(path), p.describe())
	if p.savesAVersion() {
		line += " This saved one more version so the change applies now."
	}
	fmt.Fprintln(w, line)
}
