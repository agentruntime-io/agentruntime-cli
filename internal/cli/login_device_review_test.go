package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

// Tests for the review round: which server the sign-in talks to, who approved the key, and the smaller fixes around
// saving it. Every code, key and name is fake.

// recordLaunches replaces the launcher that starts the system's browser opener with a recorder, so that no test ever
// starts a real opener, whatever the code under test decides.
func recordLaunches(t *testing.T) *[][]string {
	t.Helper()
	var launched [][]string
	orig := launch
	launch = func(name string, args ...string) error {
		launched = append(launched, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() { launch = orig })
	return &launched
}

// withStdin makes a run read its answers from text, as if typed at a terminal.
func withStdin(e *devEnv, text string, tweaks ...func(*App)) func(*App) {
	return func(a *App) {
		e.tweak(a)
		a.In = strings.NewReader(text)
		for _, t := range tweaks {
			t(a)
		}
	}
}

// foreign makes every host an unofficial one, so the confirmation can be tried against the fake API on this machine.
func foreign(a *App) { a.hostTrusted = func(string) bool { return false } }

// noTerminal gives the run a standard input that is not a terminal (a pipe, as in a script or a coding agent).
func noTerminal(t *testing.T) func(*App) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	t.Cleanup(func() { _ = r.Close() })
	return func(a *App) { a.In = r }
}

func authority(d *deviceAPI) string { return strings.TrimPrefix(d.URL, "http://") }

// ---- which server -----------------------------------------------------------------------------------------------

func TestDeviceLoginPrintsTheAPIHostAsItsFirstLine(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 0 || !strings.HasPrefix(out, "API: "+authority(d)+"\n") {
		t.Fatalf("exit %d: the first line must name the API host\n%s\n%s", code, out, errOut)
	}
	if strings.Contains(errOut, "WARNING") {
		t.Errorf("a warning for a host on this machine:\n%s", errOut)
	}
}

func TestDeviceLoginAsksForTheHostNameBeforeUsingAHostOutsideAgentRuntime(t *testing.T) {
	host := func(d *deviceAPI) string { return strings.Split(authority(d), ":")[0] }

	// Typed correctly: the warning is shown, the prompt names the host, and only then is anything sent.
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	e := newDevEnv()
	code, out, errOut := runApp(t, false, withStdin(e, host(d)+"\n", foreign), deviceArgs(d)...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"WARNING: the API host is " + authority(d) + ", which is not an agentruntime.io host.",
		"hands back the access key that is saved in your profile", "Type the host name (" + host(d) + ") to continue: ",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	if !strings.HasPrefix(out, "API: "+authority(d)+"\n") {
		t.Errorf("the API line is not first:\n%s", out)
	}
	if savedProfile(t, "default").Token != devKey {
		t.Error("the key was not saved after a confirmed sign-in")
	}

	// Not confirmed: another answer, a yes, or nothing at all. Nothing is sent and nothing is saved.
	for _, typed := range []string{"y\n", "yes\n", "evil.example\n", "\n", "", "  \n"} {
		isolate(t)
		d := newDeviceAPI(t)
		code, out, errOut := runApp(t, false, withStdin(newDevEnv(), typed, foreign), deviceArgs(d)...)
		if code != 1 || !strings.Contains(errOut, "not confirmed. Nothing was started") || d.hits() != 0 {
			t.Errorf("typed %q: exit %d hits %d\n%s\n%s", typed, code, d.hits(), out, errOut)
		}
		nothingSaved(t)
	}

	// The host with its port is accepted too, and the case does not matter.
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runApp(t, false, withStdin(newDevEnv(), strings.ToUpper(authority(d))+"\n", foreign), deviceArgs(d)...); code != 0 {
		t.Errorf("host with port: exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestDeviceLoginWithoutATerminalRefusesAForeignHostUnlessToldWithYes(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	code, out, errOut := runApp(t, false, func(a *App) { newDevEnv().tweak(a); foreign(a); noTerminal(t)(a) }, deviceArgs(d)...)
	if code != 2 || !strings.Contains(errOut, "refusing to use an API host outside agentruntime.io without a person to confirm it: add --yes if you mean it") || d.hits() != 0 {
		t.Fatalf("exit %d hits %d\n%s\n%s", code, d.hits(), out, errOut)
	}
	if !strings.Contains(errOut, "WARNING: the API host is") {
		t.Errorf("no warning:\n%s", errOut)
	}
	nothingSaved(t)

	// --yes is the script's answer; the warning is still printed.
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	code, out, errOut = runApp(t, false, func(a *App) { newDevEnv().tweak(a); foreign(a); noTerminal(t)(a) }, deviceArgs(d, "--yes")...)
	if code != 0 || !strings.Contains(errOut, "WARNING: the API host is "+authority(d)) || strings.Contains(errOut, "Type the host name") {
		t.Fatalf("--yes: exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestDeviceLoginRefusesOpenForAForeignHostEvenWithYes(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	e := newDevEnv()
	code, out, errOut := runApp(t, false, withStdin(e, "", foreign), deviceArgs(d, "--open", "--yes")...)
	if code != 2 || !strings.Contains(errOut, "--open is not allowed for an API host outside agentruntime.io") || d.hits() != 0 || out != "" || len(e.opened) != 0 {
		t.Fatalf("exit %d hits %d opened %v\n%s\n%s", code, d.hits(), e.opened, out, errOut)
	}
	nothingSaved(t)
}

func TestDeviceLoginHoldsEveryAPIAddressSourceToTheSameRule(t *testing.T) {
	// The address comes from a flag or the environment (or the Platform MCP address); a person is asked each time.
	// Nothing is typed here, so the sign-in is not confirmed and nothing is sent.
	isolate(t)
	d := newDeviceAPI(t)
	t.Setenv("AGENTRUNTIME_API_URL", d.URL)
	code, out, errOut := runApp(t, false, withStdin(newDevEnv(), "", foreign), "login", "--device", "--ref", "my/*", "--device-name", "n")
	if code != 1 || !strings.Contains(errOut, "WARNING: the API host is "+authority(d)) || !strings.Contains(errOut, "not confirmed. Nothing was started") || d.hits() != 0 {
		t.Fatalf("environment address: exit %d hits %d\n%s\n%s", code, d.hits(), out, errOut)
	}
	if !strings.HasPrefix(out, "API: "+authority(d)+"\n") {
		t.Errorf("the API line is not first:\n%s", out)
	}
}

// ---- the host that issued the key -----------------------------------------------------------------------------

func TestDeviceLoginStoresTheHostThatIssuedTheKey(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if p := savedProfile(t, "default"); p.IssuedByHost != authority(d) {
		t.Errorf("issued_by_host %q, want %q", p.IssuedByHost, authority(d))
	}
	if raw := mustRead(t, configPath()); !strings.Contains(raw, `"issued_by_host": "`+authority(d)+`"`) {
		t.Errorf("the config file has no issued_by_host:\n%s", strings.ReplaceAll(raw, devKey, "<key>"))
	}
	f, _ := config.Load()
	if r := f.Resolve(config.Overrides{}); r.TokenIssuedByHost != authority(d) {
		t.Errorf("resolved issuing host %q", r.TokenIssuedByHost)
	}
	// profile list --json says it, never the key.
	code, out, _ := run(t, "", "profile", "list", "--json")
	if code != 0 || !strings.Contains(out, `"issued_by_host": "`+authority(d)+`"`) || strings.Contains(out, devKey) {
		t.Errorf("profile list --json:\n%s", out)
	}
}

func TestPastedLoginAndLogoutDropTheIssuingHost(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-old", ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339), IssuedByHost: "other.example"}})
	if code, out, errOut := run(t, "", "login", "--token", testToken, "--url", srv.URL); code != 0 {
		t.Fatalf("login: exit %d\n%s\n%s", code, out, errOut)
	}
	if p := savedProfile(t, "default"); p.IssuedByHost != "" || p.ExpiresAt != "" || p.Token != testToken {
		t.Errorf("a pasted key kept the old key's data: %+v", p)
	}
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-old", ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339), IssuedByHost: "other.example"}})
	if code, _, _ := run(t, "", "logout"); code != 0 {
		t.Fatal("logout failed")
	}
	if p := savedProfile(t, "default"); p.IssuedByHost != "" || p.ExpiresAt != "" || p.Token != "" {
		t.Errorf("logout left %+v", p)
	}
}

// ---- who approved -----------------------------------------------------------------------------------------------

func grantWith(extra string) devAnswer {
	return ok(`{"token":"` + devKey + `","expires_at":"` + clockNow.Add(time.Hour).Format(time.RFC3339) + `","scopes":["secrets:fetch"],"refs":["workspace/live/*"]` + extra + `}`)
}

func TestDeviceLoginShowsTheWorkspaceAndTheApprover(t *testing.T) {
	const check = "Check that this is your workspace and your own account: secrets fetched with this key come from that workspace."
	cases := []struct {
		name, extra, want string
		notWant           []string
	}{
		{"name and masked approver", `,"tenant_id":"tenant-1","tenant_name":"Acme Corp","approved_by":"t***@example.com"`, "Approved for workspace Acme Corp by t***@example.com", []string{"tenant-1"}},
		{"no name: the id", `,"tenant_id":"tenant-1","approved_by":"t***@example.com"`, "Approved for workspace tenant-1 by t***@example.com", nil},
		{"no approver", `,"tenant_id":"tenant-1","tenant_name":"Acme Corp"`, "Approved for workspace Acme Corp (the server did not say who approved it)", nil},
		{"only an approver", `,"approved_by":"t***@example.com"`, "Approved by t***@example.com (the server did not say for which workspace)", nil},
		{"nothing", ``, "The server did not say which workspace approved this key, or who did.", nil},
		{"a whole address is masked by the CLI", `,"tenant_name":"Acme","approved_by":"tim.smith@example.com"`, "Approved for workspace Acme by t***@example.com", []string{"tim.smith", "tim"}},
		{"a name that is not an address is shown as it is", `,"tenant_name":"Acme","approved_by":"Tim the owner"`, "Approved for workspace Acme by Tim the owner", nil},
	}
	for _, c := range cases {
		isolate(t)
		d := newDeviceAPI(t)
		d.poll = pollScript(grantWith(c.extra))
		code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
		if code != 0 || !strings.Contains(out, "  "+c.want+"\n") || !strings.Contains(out, "  "+check+"\n") {
			t.Errorf("%s: exit %d, want %q and the check line in:\n%s\n%s", c.name, code, c.want, out, errOut)
		}
		for _, bad := range c.notWant {
			if strings.Contains(out+errOut, bad) {
				t.Errorf("%s: %q must not be shown:\n%s", c.name, bad, out)
			}
		}
		noSecrets(t, c.name, out, errOut)
	}

	// Text from the server is made safe to print.
	isolate(t)
	d := newDeviceAPI(t)
	hostile, _ := json.Marshal(map[string]string{"tenant_name": "Acme\x1b]0;pwned\x07", "approved_by": "a\x1b[2Jb"})
	d.poll = pollScript(grantWith("," + strings.TrimSuffix(strings.TrimPrefix(string(hostile), "{"), "}")))
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 0 || !strings.Contains(out, "Approved for workspace") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	noTerminalCodes(t, "approval line", out, errOut)
}

func TestMaskApprover(t *testing.T) {
	cases := map[string]string{
		"tim@example.com":       "t***@example.com",
		"t***@example.com":      "t***@example.com",
		"  tim@example.com  ":   "t***@example.com",
		"a@b.test":              "a***@b.test",
		"@example.com":          "@example.com",
		"Tim the owner":         "Tim the owner",
		"":                      "",
		"first.last@sub.x.test": "f***@sub.x.test",
	}
	for in, want := range cases {
		if got := maskApprover(in); got != want {
			t.Errorf("maskApprover(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSecretsRunHelpSaysTheValuesComeFromTheApprovingWorkspace(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "secrets", "run", "--help")
	help = flat(help)
	for _, want := range []string{
		"The values come from the workspace the access key belongs to",
		"For a key made by agentruntime login --device that is the workspace that APPROVED the sign-in",
		"Only run login --device yourself, and only approve your own sign-ins",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("secrets run --help lacks %q", want)
		}
	}
}

// ---- saving: the config is read again, only this profile changes ---------------------------------------------------

func TestDeviceLoginKeepsWhatAnotherTerminalSavedWhileItWaited(t *testing.T) {
	isolate(t)
	writeConfig(t, "work", map[string]*config.Profile{"work": {Token: "pat_FAKE-work-key-123456", URL: "https://mcp.example.test/mcp"}})
	d := newDeviceAPI(t)
	d.poll = pollScript(pending(), goodGrant())
	// While the code waits, another terminal adds a profile with its own key and makes it current.
	d.onPoll = func(n int) {
		if n != 1 {
			return
		}
		f, err := config.Load()
		if err != nil {
			t.Error(err)
			return
		}
		f.Profiles["added"] = &config.Profile{Token: "pat_FAKE-added-key-123456", URL: "https://mcp.example.test/mcp"}
		f.Current = "added"
		if err := f.Save(); err != nil {
			t.Error(err)
		}
	}
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d, "--profile", "ci")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	f, _ := config.Load()
	if f.Profiles["added"] == nil || f.Profiles["added"].Token != "pat_FAKE-added-key-123456" || f.Current != "added" {
		t.Errorf("the profile another terminal added was lost: current %q, %+v", f.Current, f.Profiles["added"])
	}
	if f.Profiles["work"] == nil || f.Profiles["work"].Token != "pat_FAKE-work-key-123456" {
		t.Errorf("the work profile changed: %+v", f.Profiles["work"])
	}
	if f.Profiles["ci"] == nil || f.Profiles["ci"].Token != devKey {
		t.Errorf("the new key was not saved: %+v", f.Profiles["ci"])
	}
	if !strings.Contains(out, `Profile "ci" is not your current profile (added)`) {
		t.Errorf("the note about the current profile does not use the current config:\n%s", out)
	}
}

func TestDeviceLoginChecksTheReplaceGuardAgainJustBeforeSaving(t *testing.T) {
	pasted := "pat_FAKE-pasted-key-123456789"
	sneak := func(d *deviceAPI) {
		d.onPoll = func(n int) {
			if n != 1 {
				return
			}
			f, _ := config.Load()
			f.Profiles["default"] = &config.Profile{Token: pasted, URL: "https://mcp.example.test/mcp"}
			if err := f.Save(); err != nil {
				t.Error(err)
			}
		}
	}
	// Without --replace: the key that appeared meanwhile is kept, and the new key is reported as not saved.
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	sneak(d)
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || !strings.Contains(errOut, `the key could not be saved (profile "default" now holds an access key that does not expire, saved while you waited; add --replace to replace it, or use --profile NAME)`) ||
		!strings.Contains(errOut, "It cannot be shown again") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if savedProfile(t, "default").Token != pasted {
		t.Error("the pasted key was replaced although the guard says no")
	}
	noSecrets(t, "guard", out, errOut)
	if strings.Contains(out+errOut, pasted) {
		t.Error("the existing key was printed")
	}
	if strings.Contains(out, "signed in") {
		t.Errorf("claimed success:\n%s", out)
	}

	// With --replace it is replaced, and the person is told.
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	sneak(d)
	code, out, errOut = runDevice(t, newDevEnv(), deviceArgs(d, "--replace")...)
	if code != 0 || savedProfile(t, "default").Token != devKey {
		t.Fatalf("--replace: exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestReplaceSaysThatTheOldKeyWasRemovedAndIsNotRevoked(t *testing.T) {
	const line = `The access key that was saved in profile "default" was removed from it. It is not revoked on the server: revoke it in the Console (Settings, API keys) if you no longer need it.`
	// A pasted key (no expiry) replaced with --replace.
	isolate(t)
	pasted := "pat_FAKE-pasted-key-123456789"
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: pasted, URL: "https://mcp.example.test/mcp"}})
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d, "--replace")...)
	if code != 0 || !strings.Contains(out, "  "+line+"\n") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if strings.Contains(out+errOut, pasted) {
		t.Error("the old key was printed")
	}
	// An earlier sign-in's key is renewed: nothing to say about a removed key.
	isolate(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-short-lived-123456", ExpiresAt: clockNow.Add(-time.Hour).Format(time.RFC3339)}})
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, _ := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 || strings.Contains(out, "was removed from it") {
		t.Errorf("renewing: exit %d\n%s", code, out)
	}
	// No old key at all: nothing either.
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, _ := runDevice(t, newDevEnv(), deviceArgs(d, "--replace")...); code != 0 || strings.Contains(out, "was removed from it") {
		t.Errorf("no old key: exit %d\n%s", code, out)
	}
}

func TestDeviceLoginNeverChangesTheCurrentProfile(t *testing.T) {
	// --profile NAME: the current profile stays, and the person is told how to use the new key.
	isolate(t)
	writeConfig(t, "work", map[string]*config.Profile{"work": {Token: "pat_FAKE-work-key-123456"}})
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d, "--profile", "fetch")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if f, _ := config.Load(); f.Current != "work" {
		t.Errorf("current profile %q, want work", f.Current)
	}
	if !strings.Contains(out, `Profile "fetch" is not your current profile (work): use --profile fetch, or set AGENTRUNTIME_PROFILE=fetch, to use this key.`) {
		t.Errorf("no note:\n%s", out)
	}

	// No --profile: the key goes into the current profile, which is already current: no note.
	isolate(t)
	writeConfig(t, "work", map[string]*config.Profile{"work": {Token: "pat_FAKE-short-lived-123456", ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339)}})
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	code, out, _ = runDevice(t, newDevEnv(), deviceArgs(d)...)
	if f, _ := config.Load(); code != 0 || f.Current != "work" || f.Profiles["work"].Token != devKey || strings.Contains(out, "is not your current profile") {
		t.Errorf("exit %d current %q\n%s", code, f.Current, out)
	}

	// The profile named by the environment: also left alone.
	isolate(t)
	writeConfig(t, "work", map[string]*config.Profile{"work": {Token: "pat_FAKE-work-key-123456"}})
	t.Setenv("AGENTRUNTIME_PROFILE", "envp")
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if f, _ := config.Load(); f.Current != "work" || f.Profiles["envp"] == nil || f.Profiles["envp"].Token != devKey {
		t.Errorf("current %q, profiles %v", f.Current, f.Profiles)
	}
}

// ---- the expiry the server reports is bounded ---------------------------------------------------------------------

func TestDeviceLoginBoundsTheExpiryToEightHours(t *testing.T) {
	grantAt := func(exp time.Duration) devAnswer {
		return ok(`{"token":"` + devKey + `","expires_at":"` + clockNow.Add(exp).Format(time.RFC3339) + `","scopes":["secrets:fetch"],"refs":["my/*"]}`)
	}
	eight := 8 * time.Hour
	cases := []struct {
		name        string
		exp         time.Duration
		wantStored  time.Duration
		wantClamped bool
	}{
		{"20 hours is cut to 8", 20 * time.Hour, eight, true},
		{"never (a year)", 365 * 24 * time.Hour, eight, true},
		{"just over the skew", eight + 6*time.Minute, eight, true},
		{"within the skew", eight + 4*time.Minute, eight + 4*time.Minute, false},
		{"exactly 8 hours", eight, eight, false},
		{"an hour", time.Hour, time.Hour, false},
		{"already past", -time.Hour, -time.Hour, false},
	}
	for _, c := range cases {
		isolate(t)
		d := newDeviceAPI(t)
		d.poll = pollScript(grantAt(c.exp))
		// The waits move the clock; make them zero by answering at once.
		e := newDevEnv()
		code, out, errOut := runDevice(t, e, deviceArgs(d, "--ttl", "8h")...)
		if code != 0 {
			t.Fatalf("%s: exit %d\n%s\n%s", c.name, code, out, errOut)
		}
		waited := 5 * time.Second // one poll interval
		want := clockNow.Add(c.wantStored)
		if c.wantClamped {
			want = clockNow.Add(waited).Add(eight) // now (after the wait) + 8 hours
		}
		got := savedProfile(t, "default").ExpiresAt
		if got != want.UTC().Format(time.RFC3339) {
			t.Errorf("%s: stored expiry %s, want %s", c.name, got, want.UTC().Format(time.RFC3339))
		}
		note := "which is more than 8h from now. The CLI treats it as ending at"
		if has := strings.Contains(errOut, note); has != c.wantClamped {
			t.Errorf("%s: note shown = %v, want %v\n%s", c.name, has, c.wantClamped, errOut)
		}
		if c.wantClamped && !strings.Contains(out, "(in 8h)") {
			t.Errorf("%s: the sign-in line does not show the bounded time:\n%s", c.name, out)
		}
	}
}

// ---- the device name -------------------------------------------------------------------------------------------------

func TestDeviceNameCanBeLeftOutOfTheRequest(t *testing.T) {
	hostnameFn = func() (string, error) { return "SECRET-HOSTNAME-1", nil }
	t.Cleanup(func() { hostnameFn = os.Hostname })

	// Default: the host name goes to the API (and the README says so).
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runApp(t, false, newDevEnv().tweak, "login", "--device", "--api-url", d.URL, "--ref", "my/*"); code != 0 || d.starts[0]["device_name"] != "SECRET-HOSTNAME-1" {
		t.Fatalf("default: exit %d name %v\n%s\n%s", code, d.starts[0]["device_name"], out, errOut)
	}
	// --device-name "": a generic name, and the host name is not sent at all.
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	code, out, errOut := runApp(t, false, newDevEnv().tweak, "login", "--device", "--api-url", d.URL, "--ref", "my/*", "--device-name", "")
	if code != 0 || d.starts[0]["device_name"] != "AgentRuntime CLI" {
		t.Fatalf("empty: exit %d name %v\n%s\n%s", code, d.starts[0]["device_name"], out, errOut)
	}
	raw, _ := json.Marshal(d.starts[0])
	if strings.Contains(string(raw)+out+errOut, "SECRET-HOSTNAME") {
		t.Errorf("the host name was sent or shown with --device-name \"\": %s\n%s", raw, out)
	}
	if !strings.Contains(out, "Device: AgentRuntime CLI") {
		t.Errorf("the device line:\n%s", out)
	}
	// A name given: that name only.
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, _, _ := runApp(t, false, newDevEnv().tweak, "login", "--device", "--api-url", d.URL, "--ref", "my/*", "--device-name", "build box"); code != 0 || d.starts[0]["device_name"] != "build box" {
		t.Errorf("named: %v", d.starts[0]["device_name"])
	}
}

// ---- the opener ------------------------------------------------------------------------------------------------------

func TestOpenableAddress(t *testing.T) {
	good := []string{
		"https://console.agentruntime.io/device?code=BCDF-2345",
		"https://console.agentruntime.io/device",
		"https://agentruntime.io",
		"https://console.example.test:8443/device?code=AB-12&next=x",
		"https://127.0.0.1:5173/device#top",
	}
	for _, a := range good {
		if err := openableAddress(a); err != nil {
			t.Errorf("%q refused: %v", a, err)
		}
	}
	bad := []string{
		"", "http://h.example/", "ftp://h.example/", "file:///etc/passwd", "javascript:alert(1)", "-https://h.example/", "HTTPS://h.example/", " https://h.example/",
		"https://h.example/a\"b", "https://h.example/a^b", "https://h.example/a|b", "https://h.example/a%20b", "https://h.example/a%", "https://h.example/a`b",
		"https://h.example/a{b", "https://h.example/a}b", "https://h.example/a<b", "https://h.example/a>b", "https://h.example/a b", "https://h.example/a\\b",
		"https://h.example/a\tb", "https://h.example/a\nb", "https://h.example/\x1b[2J", "https://h.example/\x00", "https://h.example/é",
		"https://user:pw@h.example/", "https://user@h.example/", "https://@h.example/", "https:///x", "https://", "https://?x", "https://h.example:notaport/",
		"https://h.example/a b&calc.exe", "https://h.example/\"&calc.exe&\"",
	}
	for _, a := range bad {
		if err := openableAddress(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
}

func TestTheOpenerStartsTheSystemOpenerDirectlyWithOneArgument(t *testing.T) {
	launched := recordLaunches(t)
	const address = "https://console.agentruntime.io/device?code=BCDF-2345"
	if err := openInBrowser(address); err != nil {
		t.Fatal(err)
	}
	if len(*launched) != 1 {
		t.Fatalf("started %d programs: %v", len(*launched), *launched)
	}
	got := (*launched)[0]
	want := map[string][]string{
		"windows": {"rundll32", "url.dll,FileProtocolHandler", address},
		"darwin":  {"open", address},
	}[runtime.GOOS]
	if want == nil {
		want = []string{"xdg-open", address}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("started %v, want %v", got, want)
	}
	// Never a shell: the program is not one, and the address is one argument that is the address as it is.
	for _, shell := range []string{"sh", "bash", "cmd", "cmd.exe", "powershell", "powershell.exe", "zsh"} {
		if got[0] == shell {
			t.Errorf("the opener is a shell: %v", got)
		}
	}
	if got[len(got)-1] != address {
		t.Errorf("the address was changed: %v", got)
	}
}

func TestADirtyAddressIsNotOpenedAndTheNoteSaysSo(t *testing.T) {
	// A sign-in address on the API's own host that holds a character the Windows opener would re-read.
	for _, dirty := range []string{"/device?code=A%7CB", "/device?code=A^B", "/device?code=A\"B", "/device?code=A`B"} {
		isolate(t)
		d := newDeviceAPI(t)
		host := authority(d)
		body, _ := json.Marshal(map[string]any{"device_code": devCode, "user_code": devUser, "verification_uri": "https://" + host + "/device",
			"verification_uri_complete": "https://" + host + dirty, "expires_in": 600, "interval": 5})
		d.start = func(int) devAnswer { return ok(string(body)) }
		d.poll = pollScript(goodGrant())
		e := newDevEnv()
		code, out, errOut := runDevice(t, e, deviceArgs(d, "--open")...)
		errOut = strings.ReplaceAll(errOut, notSavedNote, "")
		if code != 0 || len(e.opened) != 0 || !strings.Contains(errOut, "not opening a browser: the address is not a plain https address on the API's own domain") {
			t.Errorf("%q: exit %d opened %v\n%s\n%s", dirty, code, e.opened, out, errOut)
		}
		if !strings.Contains(out, "code: "+devUser) {
			t.Errorf("%q: the code was not shown:\n%s", dirty, out)
		}
	}
}

// ---- the grant's new fields reach the client -------------------------------------------------------------------------

func TestSavedKeyWorksWithTheRestOfTheCLIAfterTheReview(t *testing.T) {
	// The whole flow once more, end to end: sign in, then the saved key is the one the fetch commands send, and no
	// warning is printed because the same host issued it and receives it.
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(grantWith(`,"tenant_name":"Acme","approved_by":"t***@example.com"`))
	e := newDevEnv()
	if code, out, errOut := runDevice(t, e, deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	api := newVaultAPI(t)
	f, _ := config.Load()
	f.Profiles["default"].IssuedByHost = authority(&deviceAPI{Server: api.Server})
	_ = f.Save()
	e.now = clockNow.Add(30 * time.Minute)
	code, out, errOut := runApp(t, false, e.tweak, "secrets", "check", "--api-url", api.URL, "workspace/live/stripe#API_KEY")
	_ = out
	if strings.Contains(errOut, "warning:") {
		t.Errorf("a warning for the host that issued the key (exit %d):\n%s", code, errOut)
	}
	if got := api.all(); len(got) != 1 || got[0].Auth != "Bearer "+devKey || got[0].Method != http.MethodPost {
		t.Errorf("the saved key was not the one sent: %+v", got)
	}
}

func TestHelpAndReadmeWarnAboutWhoApprovesAndWhichServer(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "login", "--help")
	help = flat(help)
	text := flat(readme(t))
	text = strings.ReplaceAll(text, " > ", " ") // the warning is a quotation: each of its lines starts with "> "
	for _, want := range []string{
		"The first line it prints is the API host it talks to",
		"An agentruntime.io host (or this machine) is used without asking",
		"asks you to type the host name", "refuses --open", "--yes",
		"Only run login --device yourself, only approve your own sign-ins",
		`Someone who says "send me the code, I will approve it" approves from their own account`,
		"--replace removes the old key from the profile and says so; it does not revoke it on the server",
		"The profile is not made your current one", "refuse to send it to a different host unless you pass --allow-other-host", "A host name must be plain ASCII",
		"The machine's host name is sent as the device name",
		`--device-name ""`,
	} {
		if !strings.Contains(help, want) {
			t.Errorf("login --help lacks %q", want)
		}
	}
	for _, want := range []string{
		"**Only run `login --device` yourself, only approve your own sign-ins, and check the workspace and the approver it shows when it finishes**",
		`Someone who says "send me the code, I will approve it" approves from *their* account`,
		"`login --device` always prints `API: <host>` first", "**type the host name**", "`--yes`", "`--open` is refused for such a host",
		"`issued_by_host`", "refuses to send it to a host other than the one that issued it", "**plain ASCII**", "one and the same value",
		"Approved for workspace <name> by <masked approver>",
		"**The device name is your machine's host name** by default, and it is sent to the API", `--device-name ""`,
		"**The profile is not made current.**", "is not revoked on the server", "limited to 8 hours from now",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
}

// A config that cannot be read when the key arrives is not overwritten: the key is reported as not saved.
func TestDeviceLoginDoesNotOverwriteAConfigItCannotRead(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	d.onPoll = func(int) { _ = os.WriteFile(configPath(), []byte("{not json"), 0o600) }
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || !strings.Contains(errOut, "the sign-in was approved, but the key could not be saved (") || !strings.Contains(errOut, "It cannot be shown again") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if got := mustRead(t, configPath()); got != "{not json" {
		t.Errorf("the unreadable config was overwritten: %q", got)
	}
	noSecrets(t, "unreadable config", out, errOut)
}
