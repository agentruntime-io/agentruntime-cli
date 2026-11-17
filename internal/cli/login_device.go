package cli

// `agentruntime login --device`: sign in without pasting a key.
//
// The CLI asks the API for a short code and prints it with an address. A person opens the address in the Console,
// signs in there, checks what the terminal is asking for, may narrow it, and approves. The CLI polls until the API
// hands over a short-lived access key (at most 8 hours, fetch only) and saves it into the profile with its expiry.
// Nothing secret is ever shown: the user code is not a secret, the device code and the key are never printed, and
// the key is delivered by the server exactly once.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/apihost"
	"github.com/agentruntime-io/agentruntime-cli/internal/bffclient"
	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

const deviceLoginLong = `Signs in without pasting a key. The CLI prints a short code and an address; you
open the address in a browser, sign in to the Console, check what this terminal
is asking for, and approve it. The CLI then saves a short-lived access key in the
current profile. The key is for fetching secrets only (agentruntime secrets run,
get, check, render), it stops working by itself after --ttl (1 minute to 8 hours,
default 1 hour), and you can revoke it in the Console under Settings, API keys,
Short-lived access.

  agentruntime login --device --ref 'workspace/live/*'
  agentruntime login --device --ref workspace/live/stripe --ref my/deploy --ttl 4h
  agentruntime login --device --all --scope vault:read --profile ci-laptop

You must say which secrets you want to be able to fetch: one --ref for each
secret or folder (workspace/live/stripe, workspace/live/*, my/*; the room is
my, project or workspace, and a * may only be the whole last part), at most 100,
or --all for everything the approver may view. The person approving can narrow
this and never widen it. The key always carries the scope secrets:fetch;
--scope vault:read adds listing secret names.

Approve a code only if you started it from your own terminal just now. The code
is not a secret, but approving someone else's code would give them access.

The CLI never prints the key and never opens a browser unless you pass --open
(it then opens only an https address on the API's own domain). It waits up to
10 minutes for the approval; Ctrl-C cancels, and nothing is saved.

The first line it prints is the API host it talks to. An agentruntime.io host (or
this machine) is used without asking. For any other host it warns, asks you to type
the host name (without a terminal it refuses unless you pass --yes), and refuses
--open: that server decides which page you are shown and which key you get.

Only run login --device yourself, only approve your own sign-ins, and check the
workspace and approver shown when it finishes (Approved for workspace ... by ...).
Someone who says "send me the code, I will approve it" approves from their own
account, and secrets run would then use values from THEIR workspace.

The key replaces the access key saved in the profile, so the command refuses
when the profile holds a key that does not expire, unless you pass --replace;
use --profile NAME to keep both. --replace removes the old key from the profile
and says so; it does not revoke it on the server. The profile is not made your
current one: pass --profile NAME (or set AGENTRUNTIME_PROFILE) to use the key. The
key is saved with the host that issued it, and the commands that send it to a server
refuse to send it to a different host unless you pass --yes. A host name must be plain
ASCII (an international name in its xn-- form). An AGENTRUNTIME_PAT in your environment still
overrides the saved key.

The machine's host name is sent as the device name, so the approver can recognise
the terminal. Pass --device-name NAME to send another name, or --device-name ""
to send a generic one instead of the host name.`

// deviceFlags are the flags that only make sense with --device.
type deviceFlags struct {
	refs       []string
	all        bool
	ttl        string
	scopes     []string
	open       bool
	deviceName string
	apiURL     string
	replace    bool

	// deviceNameSet is true when --device-name was given, even as an empty text.
	deviceNameSet bool
}

// deviceOnlyFlags are the names of the flags in deviceFlags, so using one without --device is a usage error.
var deviceOnlyFlags = []string{"ref", "all", "ttl", "scope", "open", "device-name", "api-url", "replace"}

// hostnameFn is the machine's name, the default device name. A test seam.
var hostnameFn = os.Hostname

// defaultDeviceTTL is the key's lifetime when --ttl is not given.
const defaultDeviceTTL = "1h"

const (
	// maxPollFailures is how many polls in a row may fail (network, 429, 5xx) before the CLI gives up.
	maxPollFailures = 5
	// pollBackoff is added to the polling interval for a slow_down and for a 429.
	pollBackoff = 5
	// maxPollInterval stops the interval from growing without limit.
	maxPollInterval = 60
)

// addDeviceFlags registers the device-only flags on the login command.
func addDeviceFlags(cmd *cobra.Command, f *deviceFlags) {
	fl := cmd.Flags()
	fl.StringArrayVar(&f.refs, "ref", nil, "with --device: a secret or folder the key may fetch, such as workspace/live/stripe or workspace/live/* (repeatable, at most 100)")
	fl.BoolVar(&f.all, "all", false, "with --device: ask for every secret the approver may view (instead of --ref)")
	fl.StringVar(&f.ttl, "ttl", defaultDeviceTTL, "with --device: how long the key should last, from 1m to 8h: 30m, 1h, 8h")
	fl.StringSliceVar(&f.scopes, "scope", nil, "with --device: also ask for this scope: vault:read (list secret names); secrets:fetch is always asked for")
	fl.BoolVar(&f.open, "open", false, "with --device: open the sign-in address in your browser (only an https address on the API's own domain, and only for an agentruntime.io API host)")
	fl.StringVar(&f.deviceName, "device-name", "", "with --device: the name the approver sees (default: this machine's host name; --device-name \"\" sends a generic name instead)")
	fl.StringVar(&f.apiURL, "api-url", "", "with --device: "+apiURLHelp)
	fl.BoolVar(&f.replace, "replace", false, "with --device: replace a key that does not expire in the profile (by default that is refused)")
}

// loginDevice runs the whole device sign-in.
func (a *App) loginDevice(cmd *cobra.Command, f deviceFlags) error {
	req, err := buildDeviceRequest(f)
	if err != nil {
		return &ExitErr{Code: ExitUsage, Err: err}
	}
	if err := a.loadConfig(); err != nil {
		return err
	}
	name := a.cfg.ProfileName(a.flags.profile)
	if p := a.cfg.Profiles[name]; p != nil && !f.replace && holdsLongLivedKey(p) {
		return &ExitErr{Code: ExitUsage, Err: fmt.Errorf(
			"profile %q already holds an access key that does not expire. Signing in here would replace it with a short-lived key that can only fetch secrets. "+
				"Use --profile NAME to keep both, or add --replace to replace it", name)}
	}
	base, err := a.apiBase(f.apiURL)
	if err != nil {
		return err
	}
	c, err := bffclient.NewDeviceClient(base)
	if err != nil {
		return &ExitErr{Code: ExitError, Err: err}
	}
	host, authority := c.Host(), c.Authority() // one parse: this is what is checked, shown, stored, compared and dialled
	official := a.apiHostIsOfficial(host)
	if f.open && !official {
		return &ExitErr{Code: ExitUsage, Err: errors.New(
			"--open is not allowed for an API host outside agentruntime.io: that server would choose the page that opens. Open the address yourself, if you trust it")}
	}
	// The key is shown by the server only once, so a folder that cannot be written is found before anyone is asked
	// to approve anything.
	if err := config.CheckWritable(); err != nil {
		return &ExitErr{Code: ExitError, Err: fmt.Errorf("%w; nothing was started", err)}
	}

	// The first line says which server this talks to. An API address from a flag, the environment or a profile is
	// whatever somebody put there, and the server decides the page that is shown and the key that is saved.
	fmt.Fprintf(a.Out, "API: %s\n", safeLine(authority))
	if !official {
		if err := a.confirmForeignAPI(authority, host, a.flags.yes); err != nil {
			return err
		}
	}

	ctx, cancel := a.deviceContext(cmd)
	defer cancel()

	started := a.nowTime()
	code, err := c.Start(ctx, req)
	if err != nil {
		return a.deviceFailure(ctx, "could not start the sign-in", err)
	}
	verify, complete, err := a.printDeviceCode(code, req, host)
	if err != nil {
		return err
	}
	if f.open {
		a.openSignInPage(host, verify, complete)
	}
	grant, err := a.pollDevice(ctx, c, code, started)
	if err != nil {
		return err
	}
	return a.saveDeviceKey(name, f, grant, authority)
}

// ---- which server -----------------------------------------------------------------------------------------------

// apiHostIsOfficial is apihost.Official, unless a test replaced the rule.
func (a *App) apiHostIsOfficial(host string) bool {
	if a.hostTrusted != nil {
		return a.hostTrusted(host)
	}
	return apihost.Official(host)
}

// hostOf is the host of an address as it is compared with the host that issued a key: its authority (see package
// apihost) and the text to show for it. A host that is not plain ASCII has no authority, so it never equals any
// other host, and it is shown with every character outside ASCII written as an escape.
func hostOf(address string) (authority, shown string) {
	u, err := url.Parse(address)
	if err != nil {
		return "", "(an address that cannot be read)"
	}
	if a := apihost.Authority(u); a != "" {
		return a, a
	}
	return "", apihost.Display(u.Host)
}

// confirmForeignAPI warns loudly that the API host is not an agentruntime.io host and asks a person to type its name
// before anything is sent. --yes is the answer for a script; without it and without a terminal the sign-in is refused.
func (a *App) confirmForeignAPI(authority, host string, yes bool) error {
	w := a.Err
	fmt.Fprintf(w, "%s the API host is %s, which is not an agentruntime.io host.\n", a.stderr.Red("WARNING:"), safeLine(authority))
	fmt.Fprintln(w, "  That server receives this sign-in, decides which page you are shown, and hands back the access key that is saved in your profile.")
	fmt.Fprintln(w, "  Continue only if you run that server yourself, or the person who does gave you this address on purpose.")
	if yes {
		return nil
	}
	if !a.isInteractive() {
		return &ExitErr{Code: ExitUsage, Err: errors.New(
			"refusing to use an API host outside agentruntime.io without a person to confirm it: add --yes if you mean it")}
	}
	fmt.Fprintf(w, "Type the host name (%s) to continue: ", safeLine(host))
	line, err := a.readLine()
	if err != nil || (!apihost.Same(line, host) && !apihost.Same(line, authority)) {
		fmt.Fprintln(w)
		return &ExitErr{Code: ExitError, Err: errors.New("not confirmed. Nothing was started")}
	}
	return nil
}

// checkKeyHost is called by every command that is about to send the key saved in the profile to a server. A short-lived
// key belongs to the host that issued it (login --device saves it with that host); when a flag, an environment
// variable or another profile setting points the command at a different host, sending the key there would hand it to a
// server that did not make it. That is refused, unless --yes says it is meant, and then the key is sent after a warning.
// authority is the host the command will dial (empty when its name is not plain ASCII) and shown is the text for it.
func (a *App) checkKeyHost(authority, shown string) error {
	issued := a.resolved.TokenIssuedByHost
	if issued == "" || (authority != "" && apihost.Same(issued, authority)) {
		return nil
	}
	if !a.flags.yes {
		return &ExitErr{Code: ExitError, Err: fmt.Errorf(
			"refusing to send the access key saved in profile %q to %s: it was issued by %s, and a key must only go to the host that issued it. "+
				"If a flag or an environment variable pointed this command at that host by mistake, fix it; if you mean it, add --yes",
			safeLine(a.resolved.Profile), shown, apihost.Display(issued))}
	}
	if !a.warnedKeyHost {
		a.warnedKeyHost = true
		fmt.Fprintf(a.Err, "%s the saved access key was issued by %s, but this command talks to %s (sent because of --yes)\n",
			a.stderr.Yellow("warning:"), apihost.Display(issued), shown)
	}
	return nil
}

// checkKeyHostForMCP is checkKeyHost for the commands that call Platform MCP: the host they talk to is the API host
// that goes with the Platform MCP address (mcp. becomes api.), or the address's own host when that cannot be derived.
func (a *App) checkKeyHostForMCP() error {
	if a.resolved.TokenIssuedByHost == "" {
		return nil
	}
	address := a.resolved.URL
	if d, err := bffclient.DeriveAPIURL(address); err == nil {
		address = d
	}
	authority, shown := hostOf(address)
	return a.checkKeyHost(authority, shown)
}

// ---- inputs -------------------------------------------------------------------------------------------------

// buildDeviceRequest checks every flag the way the server does, before anything is sent. No error contains the text
// that was typed: a mistyped --ref may be a pasted value.
func buildDeviceRequest(f deviceFlags) (bffclient.DeviceRequest, error) {
	scopes, err := parseDeviceScopes(f.scopes)
	if err != nil {
		return bffclient.DeviceRequest{}, err
	}
	secs, ok := parseSpanSeconds(f.ttl, bffclient.MinDeviceTTLSeconds, bffclient.MaxDeviceTTLSeconds)
	if !ok {
		return bffclient.DeviceRequest{}, fmt.Errorf("--ttl must be from 1m to 8h, for example 30m, 1h or 8h (got %q)", f.ttl)
	}
	switch {
	case f.all && len(f.refs) > 0:
		return bffclient.DeviceRequest{}, errors.New("--all and --ref cannot be combined: ask for everything, or name the secrets")
	case !f.all && len(f.refs) == 0:
		return bffclient.DeviceRequest{}, errors.New("say which secrets the key may fetch: --ref REF for each secret or folder (for example workspace/live/*), or --all")
	}
	req := bffclient.DeviceRequest{Scopes: scopes, AllowAll: f.all, TTLSeconds: secs, Name: deviceName(f.deviceName, f.deviceNameSet)}
	seen := map[string]bool{}
	for i, raw := range f.refs {
		ref, err := parseDeviceRef(raw)
		if err != nil {
			return bffclient.DeviceRequest{}, fmt.Errorf("--ref #%d: %w", i+1, err)
		}
		if !seen[ref] {
			seen[ref] = true
			req.Refs = append(req.Refs, ref)
		}
	}
	if len(req.Refs) > bffclient.MaxDeviceRefs {
		return bffclient.DeviceRequest{}, fmt.Errorf("at most %d different --ref values (got %d)", bffclient.MaxDeviceRefs, len(req.Refs))
	}
	return req, nil
}

// parseDeviceScopes checks --scope. secrets:fetch is always part of the request; vault:read may be added.
func parseDeviceScopes(list []string) ([]string, error) {
	listNames := false
	for _, s := range list {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case bffclient.ScopeFetch:
		case bffclient.ScopeListName:
			listNames = true
		default:
			return nil, fmt.Errorf("--scope accepts %s and %s only", bffclient.ScopeFetch, bffclient.ScopeListName)
		}
	}
	out := []string{bffclient.ScopeFetch}
	if listNames {
		out = append(out, bffclient.ScopeListName)
	}
	return out, nil
}

// maxDeviceRefLen is the longest secret reference a key's list may hold.
const maxDeviceRefLen = 256

// parseDeviceRef checks one entry of the key's list of secrets, the way the server does: the room my, project or
// workspace, a path of named folders, and a * only as the whole last part (workspace/live/*, workspace/*). A short
// name (no room), shared/, a #field, a comma, '..', and control or invisible characters are refused.
func parseDeviceRef(s string) (string, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "secret:")
	switch {
	case s == "":
		return "", errors.New("it is empty")
	case !utf8.ValidString(s):
		return "", errors.New("it is not valid UTF-8 text")
	case len(s) > maxDeviceRefLen:
		return "", fmt.Errorf("it is longer than %d characters", maxDeviceRefLen)
	case strings.Contains(s, "#"):
		return "", errors.New("a key lists whole secrets or folders, not fields: leave out the '#' part")
	case strings.Contains(s, ","):
		return "", errors.New("give --ref once for each secret: a comma does not separate them")
	case strings.Contains(s, `\`):
		return "", errors.New(`use '/' between folders, not '\'`)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return "", errors.New("it has control or invisible characters")
		}
	}
	segs := strings.Split(s, "/")
	for i, seg := range segs {
		switch {
		case seg == "":
			return "", errors.New("a folder name is empty (check for '//' or a leading or trailing '/')")
		case seg == "." || seg == "..":
			return "", errors.New("'.' and '..' are not allowed in a path")
		case strings.Contains(seg, "*") && (seg != "*" || i != len(segs)-1):
			return "", errors.New("'*' may only be the whole last part, as in workspace/live/*")
		}
	}
	switch segs[0] {
	case "my", "project", "workspace":
	case "shared":
		return "", errors.New("shared secrets cannot be fetched yet (for a workspace folder called shared, write workspace/shared/...)")
	default:
		return "", errors.New("start with the room: my/, project/ or workspace/ (a name without a room is not accepted for a key)")
	}
	if len(segs) < 2 {
		return "", fmt.Errorf("name something after the room, or write %s/* for all of it", segs[0])
	}
	return s, nil
}

// genericDeviceName is sent when the person asked not to send the machine's host name.
const genericDeviceName = "AgentRuntime CLI"

// deviceName is what the approver sees as the device: --device-name, else this machine's host name. Control and
// invisible characters are dropped and it is cut to 64 characters. An empty --device-name that was given on purpose
// sends a generic name instead of the host name, so the host name can be left out.
func deviceName(given string, set bool) string {
	if n := cleanDeviceName(given); n != "" {
		return n
	}
	if set {
		return genericDeviceName
	}
	if h, err := hostnameFn(); err == nil {
		if n := cleanDeviceName(h); n != "" {
			return n
		}
	}
	return genericDeviceName
}

func cleanDeviceName(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		sb.WriteRune(r)
	}
	name := strings.Join(strings.Fields(sb.String()), " ")
	if rs := []rune(name); len(rs) > 64 {
		name = strings.TrimSpace(string(rs[:64]))
	}
	return name
}

// holdsLongLivedKey reports whether a profile's saved key is one a person would not want replaced by accident: a key
// with no stored expiry (a key made in the Console and pasted). A key with an expiry came from a sign-in like this
// one, so signing in again is how it is renewed.
func holdsLongLivedKey(p *config.Profile) bool {
	if strings.TrimSpace(p.Token) == "" {
		return false
	}
	_, err := time.Parse(time.RFC3339, strings.TrimSpace(p.ExpiresAt))
	return err != nil
}

// ---- context, waiting ----------------------------------------------------------------------------------------

// deviceContext is the context of the whole sign-in: it ends on Ctrl-C and, only when --timeout was given
// explicitly, after that time. The default --timeout is shorter than the code's life and must not cut the wait.
func (a *App) deviceContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	base := cmd.Context()
	if base == nil {
		base = context.Background()
	}
	ctx, stop := a.interruptContext(base)
	if cmd.Flags().Changed("timeout") && a.flags.timeout > 0 {
		timed, cancel := context.WithTimeout(ctx, a.flags.timeout)
		return timed, func() { cancel(); stop() }
	}
	return ctx, stop
}

// interruptContext is parent, cancelled by Ctrl-C (or the test's signal channel).
func (a *App) interruptContext(parent context.Context) (context.Context, context.CancelFunc) {
	if a.signalSource != nil {
		ctx, cancel := context.WithCancel(parent)
		go func() {
			select {
			case <-a.signalSource:
				cancel()
			case <-ctx.Done():
			}
		}()
		return ctx, cancel
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

// wait sleeps for d, or until ctx ends. The clock is a test seam.
func (a *App) wait(ctx context.Context, d time.Duration) error {
	if a.sleep != nil {
		return a.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---- showing the code -----------------------------------------------------------------------------------------

// printDeviceCode shows the person the code and the address. The user code is not a secret; the device code is
// never shown. It returns the addresses it accepted: the address of the sign-in page and, when the server gave
// one, the same address with the code in it.
func (a *App) printDeviceCode(code *bffclient.DeviceCode, req bffclient.DeviceRequest, apiHost string) (verify, complete *url.URL, err error) {
	verify, err = parseVerificationURL(code.VerificationURI)
	if err != nil {
		return nil, nil, &ExitErr{Code: ExitError, Err: errors.New("unexpected answer from the server (the sign-in address is not usable); nothing was started")}
	}
	if code.VerificationURIComplete != "" {
		// A complete address that cannot be used is left out; the plain address and the code still work.
		if u, err := parseVerificationURL(code.VerificationURIComplete); err == nil {
			complete = u
		}
	}
	w := a.Out
	fmt.Fprintln(w, "To sign in, open this address in a browser (on any device) and enter the code:")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", safeLine(verify.String()))
	fmt.Fprintf(w, "  code: %s\n", a.stdout.Bold(safeLine(code.UserCode)))
	if complete != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "or open this address, which has the code in it:")
		fmt.Fprintf(w, "  %s\n", safeLine(complete.String()))
	}
	for _, u := range []*url.URL{verify, complete} {
		if u != nil && !inAPIFamily(apiHost, u.Hostname()) {
			fmt.Fprintf(w, "\nnote: this address is not on the same domain as the API (%s). Check it is the Console you expect before you sign in there.\n", safeLine(apiHost))
			break
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "This asks for: %s\n", describeAsk(req))
	fmt.Fprintf(w, "Device: %s\n", safeLine(req.Name))
	fmt.Fprintln(w, "Approve it only if you started this from your own terminal just now.")
	fmt.Fprintf(w, "The code works for %s. Waiting for approval (Ctrl-C to cancel)...\n", humanDuration(code.ExpiresIn))
	return verify, complete, nil
}

// describeAsk says in plain words what the request asks for.
func describeAsk(req bffclient.DeviceRequest) string {
	what := "fetching " + listRefs(req.Refs)
	if req.AllowAll {
		what = "fetching every secret you may view"
	}
	for _, s := range req.Scopes {
		if s == bffclient.ScopeListName {
			what += ", and listing secret names"
		}
	}
	return fmt.Sprintf("%s, for up to %s (the approver may narrow this)", what, humanDuration(req.TTLSeconds))
}

// listRefs joins the first few references and counts the rest.
func listRefs(refs []string) string {
	const show = 5
	shown := refs
	if len(shown) > show {
		shown = shown[:show]
	}
	s := joinSafe(shown)
	if len(refs) > show {
		s += fmt.Sprintf(" and %d more", len(refs)-show)
	}
	return s
}

// parseVerificationURL accepts an http or https address with a host, no user name, and only printable ASCII, since
// it is printed on a terminal and may be opened.
func parseVerificationURL(raw string) (*url.URL, error) {
	for _, r := range raw {
		if r < 0x21 || r > 0x7e {
			return nil, errors.New("not a plain address")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || !apihost.Clean(u.Hostname()) {
		return nil, errors.New("not a usable address")
	}
	return u, nil
}

// inAPIFamily reports whether host is the API's own host or a host under the API's domain: for api.example.com,
// example.com and everything under it. An IP address matches only itself.
func inAPIFamily(apiHost, host string) bool {
	// ASCII letters only: Unicode case mapping would let a lookalike host (U+0130, the Kelvin sign) pass as an official one.
	if !apihost.Clean(apiHost) || !apihost.Clean(host) {
		return false
	}
	apiHost, host = apihost.Fold(apiHost), apihost.Fold(host)
	if apiHost == host {
		return true
	}
	if net.ParseIP(apiHost) != nil || net.ParseIP(host) != nil {
		return false
	}
	root := apiHost
	if rest, ok := strings.CutPrefix(apiHost, "api."); ok && strings.Contains(rest, ".") {
		root = rest
	}
	return host == root || strings.HasSuffix(host, "."+root)
}

// mayOpen reports whether the CLI may open u in a browser: https, on the API's own domain.
func mayOpen(apiHost string, u *url.URL) bool {
	return u != nil && u.Scheme == "https" && inAPIFamily(apiHost, u.Hostname())
}

// openSignInPage opens the address when it is safe to, and says so. A failure to open is not an error: the address
// is already on the screen.
func (a *App) openSignInPage(apiHost string, verify, complete *url.URL) {
	target := complete
	if target == nil {
		target = verify
	}
	if !mayOpen(apiHost, target) || openableAddress(target.String()) != nil {
		fmt.Fprintf(a.Err, "%s not opening a browser: the address is not a plain https address on the API's own domain. Open it yourself.\n", a.stderr.Yellow("note:"))
		return
	}
	open := a.openURL
	if open == nil {
		open = openInBrowser
	}
	if err := open(target.String()); err != nil {
		fmt.Fprintf(a.Err, "%s could not open a browser. Open the address yourself.\n", a.stderr.Yellow("note:"))
	}
}

// ---- polling --------------------------------------------------------------------------------------------------

// pollDevice waits for the approval. It returns the grant, or the error to show.
func (a *App) pollDevice(ctx context.Context, c *bffclient.DeviceClient, code *bffclient.DeviceCode, started time.Time) (*bffclient.DeviceGrant, error) {
	interval := code.Interval
	deadline := started.Add(time.Duration(code.ExpiresIn) * time.Second)
	failures := 0
	for {
		next := time.Duration(interval) * time.Second
		if err := a.wait(ctx, next); err != nil {
			return nil, a.stopped(ctx)
		}
		res, err := c.Poll(ctx, code.DeviceCode)
		if err != nil {
			if ctx.Err() != nil {
				return nil, a.stopped(ctx)
			}
			if !bffclient.IsTransient(err) {
				return nil, a.deviceFailure(ctx, "the sign-in failed", err)
			}
			if failures++; failures > maxPollFailures {
				return nil, &ExitErr{Code: ExitError, Err: fmt.Errorf(
					"could not check for the approval (%d tries in a row failed; the last: %s). Nothing was saved. Run `agentruntime login --device` again", failures, scrubError(err))}
			}
			var ae *bffclient.APIError
			if errors.As(err, &ae) && ae.Status == 429 {
				interval = min(interval+pollBackoff, maxPollInterval)
				if ra, perr := strconv.Atoi(ae.RetryAfter); perr == nil && ra > interval {
					interval = min(ra, maxPollInterval)
				}
			}
		} else {
			failures = 0
			switch res.State {
			case bffclient.PollGranted:
				return res.Grant, nil
			case bffclient.PollDenied:
				return nil, &ExitErr{Code: ExitError, Err: errors.New("the sign-in was denied in the Console. Nothing was saved")}
			case bffclient.PollExpired:
				return nil, errDeviceExpired
			case bffclient.PollSlowDown:
				interval = min(interval+pollBackoff, maxPollInterval)
			}
		}
		if !a.nowTime().Before(deadline) {
			return nil, errDeviceExpired
		}
	}
}

// errDeviceExpired is shown when the code ran out, or the server says it is no longer good.
var errDeviceExpired = &ExitErr{Code: ExitError, Err: errors.New(
	"the sign-in code expired (or was already used) before it was approved. Nothing was saved. Run `agentruntime login --device` again")}

// stopped is the error for a sign-in that ended because the context did: Ctrl-C, or an explicit --timeout.
func (a *App) stopped(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &ExitErr{Code: ExitError, Err: fmt.Errorf("gave up waiting: --timeout %s passed before the code was approved. Nothing was saved", a.flags.timeout)}
	}
	return &ExitErr{Code: 130, Err: errors.New("cancelled. Nothing was saved. The code stops working by itself in a few minutes; do not approve it")}
}

// deviceFailure turns a failed call into the error to show: what failed, then the server's fixed sentence.
func (a *App) deviceFailure(ctx context.Context, what string, err error) error {
	if ctx.Err() != nil {
		return a.stopped(ctx)
	}
	return &ExitErr{Code: ExitError, Err: fmt.Errorf("%s: %s", what, scrubError(err))}
}

// scrubError is the text of an error from the API client, which never holds a body, a header or a key, made safe
// for one line of a terminal.
func scrubError(err error) string {
	var ae *bffclient.APIError
	if errors.As(err, &ae) {
		return safeLine(ae.Error())
	}
	return safeLine(err.Error())
}

// ---- saving ---------------------------------------------------------------------------------------------------

// maxDeviceKeyLife is the longest a device key may last, and deviceExpirySkew how far past it a server's expiry may
// be before it is not believed.
const (
	maxDeviceKeyLife  = time.Duration(bffclient.MaxDeviceTTLSeconds) * time.Second
	deviceExpirySkew  = 5 * time.Minute
	approvalMaskKeeps = 1 // characters of the approver's name that stay visible
)

// boundExpiry keeps the stored expiry honest: a device key lasts at most 8 hours, so an expiry later than that (and
// a small skew) is a server mistake, and the CLI treats the key as ending 8 hours from now.
func (a *App) boundExpiry(exp time.Time) (bounded time.Time, clamped bool) {
	limit := a.nowTime().Add(maxDeviceKeyLife)
	if exp.After(limit.Add(deviceExpirySkew)) {
		return limit, true
	}
	return exp, false
}

// notSaved is the error for an approved sign-in whose key could not be put in the profile. The key is shown by the
// server only once and is never printed, so the person is told it is lost, when it ends, and how to revoke it.
func notSaved(reason string, ends time.Time) error {
	return &ExitErr{Code: ExitError, Err: fmt.Errorf(
		"the sign-in was approved, but the key could not be saved (%s). It cannot be shown again and it stops working by itself at %s. "+
			"Fix that and run `agentruntime login --device` again; the unsaved key can be revoked in the Console under Short-lived access",
		safeLine(reason), formatLocal(ends))}
}

// saveDeviceKey stores the key, its expiry and the host that issued it in the profile and tells the person what they
// got. The key is never printed. The wait for the approval can be ten minutes, and another terminal may have changed
// the config meanwhile, so the config is read again here and only this profile is changed on the file as it is now.
func (a *App) saveDeviceKey(name string, f deviceFlags, grant *bffclient.DeviceGrant, issuedBy string) error {
	exp, clamped := a.boundExpiry(grant.ExpiresAt)
	fresh, err := config.Load()
	if err != nil {
		return notSaved(err.Error(), exp)
	}
	if fresh.Profiles == nil {
		fresh.Profiles = map[string]*config.Profile{}
	}
	prof := fresh.Profiles[name]
	removedLongLived := prof != nil && holdsLongLivedKey(prof)
	if removedLongLived && !f.replace {
		return notSaved(fmt.Sprintf("profile %q now holds an access key that does not expire, saved while you waited; add --replace to replace it, or use --profile NAME", name), exp)
	}
	if prof == nil {
		prof = &config.Profile{}
		fresh.Profiles[name] = prof
	}
	prof.Token = grant.Token
	prof.ExpiresAt = exp.UTC().Format(time.RFC3339)
	prof.IssuedByHost = issuedBy
	if u := strings.TrimSpace(a.flags.url); u != "" {
		prof.URL = u
	} else if prof.URL == "" {
		prof.URL = config.DefaultURL
	}
	// The current profile is left as it is: a fetch-only key must not become the one whoami and workflows use.
	if err := fresh.Save(); err != nil {
		return notSaved(err.Error(), exp)
	}
	a.cfg = fresh

	scopes, claim := describeScopes(grant.Scopes)
	left := exp.Sub(a.nowTime())
	w := a.Out
	fmt.Fprintf(w, "%s signed in until %s%s; %s\n", a.stdout.Green("✔"), formatLocal(exp), inTime(left), claim)
	fmt.Fprintf(w, "  %s\n", describeApproval(grant))
	fmt.Fprintln(w, "  Check that this is your workspace and your own account: secrets fetched with this key come from that workspace.")
	fmt.Fprintf(w, "  Scopes: %s\n", scopes)
	fmt.Fprintf(w, "  Secrets it may fetch: %s\n", describeGranted(grant))
	path, _ := config.Path()
	fmt.Fprintf(w, "  Saved to profile %q in %s\n", name, safeLine(path))
	if current := fresh.ProfileName(""); current != name {
		fmt.Fprintf(w, "  Profile %q is not your current profile (%s): use --profile %s, or set AGENTRUNTIME_PROFILE=%s, to use this key.\n",
			safeLine(name), safeLine(current), shellQuote(name), shellQuote(name))
	}
	if removedLongLived {
		fmt.Fprintf(w, "  The access key that was saved in profile %q was removed from it. It is not revoked on the server: revoke it in the Console (Settings, API keys) if you no longer need it.\n", safeLine(name))
	}
	fmt.Fprintln(w, "  Other commands that need more rights (whoami, workflows, ...) may be refused with this key.")
	if clamped {
		fmt.Fprintf(a.Err, "%s the server said this key lasts until %s, which is more than %s from now. The CLI treats it as ending at %s.\n",
			a.stderr.Yellow("note:"), formatLocal(grant.ExpiresAt), humanDuration(bffclient.MaxDeviceTTLSeconds), formatLocal(exp))
	}
	if os.Getenv("AGENTRUNTIME_PAT") != "" {
		fmt.Fprintf(a.Err, "%s AGENTRUNTIME_PAT is set in your environment and overrides the saved key. Unset it to use the key you just saved.\n", a.stderr.Yellow("note:"))
	}
	if strings.TrimSpace(f.apiURL) != "" {
		fmt.Fprintf(a.Err, "%s the API address you gave is not saved. Pass --api-url (or set %s) on later commands that need it.\n", a.stderr.Yellow("note:"), bffclient.EnvAPIURL)
	}
	return nil
}

// describeApproval says for which workspace and by whom the key was approved, as the server tells it. The workspace
// is its name, or its id when the server sent no name. Someone who says "send me the code, I will approve it" approves
// from their own account, and secrets fetched with the key then come from their workspace, so this line matters.
func describeApproval(g *bffclient.DeviceGrant) string {
	workspace := g.TenantName
	if workspace == "" {
		workspace = g.TenantID
	}
	who := maskApprover(g.ApprovedBy)
	switch {
	case workspace != "" && who != "":
		return fmt.Sprintf("Approved for workspace %s by %s", safeLine(workspace), safeLine(who))
	case workspace != "":
		return fmt.Sprintf("Approved for workspace %s (the server did not say who approved it)", safeLine(workspace))
	case who != "":
		return fmt.Sprintf("Approved by %s (the server did not say for which workspace)", safeLine(who))
	}
	return "The server did not say which workspace approved this key, or who did."
}

// maskApprover makes sure an approver's e-mail address is shown masked, even if the server sent it whole: the first
// character of the name before the @ stays and the rest is replaced, as in t***@example.com. Text without an @, or
// already masked, is left as it is.
func maskApprover(s string) string {
	local, domain, ok := strings.Cut(strings.TrimSpace(s), "@")
	if !ok || local == "" || strings.Contains(local, "*") {
		return strings.TrimSpace(s)
	}
	rs := []rune(local)
	return string(rs[:min(approvalMaskKeeps, len(rs))]) + "***@" + domain
}

// describeScopes names the scopes the key carries and says in one phrase what that allows.
func describeScopes(scopes []string) (list, claim string) {
	fetch, names, other := false, false, false
	for _, s := range scopes {
		switch s {
		case bffclient.ScopeFetch:
			fetch = true
		case bffclient.ScopeListName:
			names = true
		default:
			other = true
		}
	}
	list = joinSafe(scopes)
	if list == "" {
		list = "none"
	}
	switch {
	case other:
		return list, "the server gave it scopes this CLI does not know; check them in the Console"
	case fetch && names:
		return list, "fetch and list names only"
	case fetch:
		return list, "fetch only"
	case names:
		return list, "list names only (it cannot fetch values)"
	}
	return list, "it carries no scope the CLI uses"
}

// describeGranted says which secrets the key may fetch, as approved.
func describeGranted(g *bffclient.DeviceGrant) string {
	switch {
	case g.AllowAll:
		return "every secret you may view"
	case len(g.Refs) == 0:
		return "none listed (it fetches nothing)"
	}
	return listRefs(g.Refs)
}

// formatLocal writes a moment in the person's own time zone.
func formatLocal(t time.Time) string { return t.Local().Format("2006-01-02 15:04 MST") }

// inTime writes how long is left, for example " (in 59 minutes)", rounded down.
func inTime(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < time.Minute:
		return " (in under a minute)"
	case d < time.Hour:
		return fmt.Sprintf(" (in %d minutes)", int(d/time.Minute))
	}
	h := int(d / time.Hour)
	if m := int(d % time.Hour / time.Minute); m > 0 {
		return fmt.Sprintf(" (in %dh %dm)", h, m)
	}
	return fmt.Sprintf(" (in %dh)", h)
}
