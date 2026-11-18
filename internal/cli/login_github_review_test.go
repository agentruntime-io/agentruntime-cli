package cli

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

// Review round 1 on the CI sign-in: the key is saved with the host that issued it, the current profile is left alone,
// the log says which API host the identity token goes to, and the README says where the key stays.

func ciAuthority(e *ghEnv) string { return strings.TrimPrefix(e.api.URL, "http://") }

func TestGitHubActionsLoginStoresTheHostThatIssuedTheKeyAndClearsAStaleOne(t *testing.T) {
	// Nothing recorded before: the host is stored, in the field the device sign-in uses.
	e := newGHEnv(t)
	if code, out, errOut := runGH(t, e.args()...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if p := savedProfile(t, "default"); p.IssuedByHost != ciAuthority(e) {
		t.Errorf("issued_by_host %q, want %q", p.IssuedByHost, ciAuthority(e))
	}
	if raw := mustRead(t, configPath()); !strings.Contains(raw, `"issued_by_host": "`+ciAuthority(e)+`"`) {
		t.Errorf("the config file has no issued_by_host:\n%s", strings.ReplaceAll(raw, ghKey, "<key>"))
	}
	f, _ := config.Load()
	if r := f.Resolve(config.Overrides{}); r.TokenIssuedByHost != ciAuthority(e) {
		t.Errorf("resolved issuing host %q", r.TokenIssuedByHost)
	}

	// An earlier key (from a device sign-in, say) left another host there: it is replaced with this key's host.
	e = newGHEnv(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {
		Token: "pat_FAKE-device-key-123456789", ExpiresAt: clockNow.Add(-time.Hour).Format(time.RFC3339), IssuedByHost: "old.example.test"}})
	if code, out, errOut := runGH(t, e.args()...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if p := savedProfile(t, "default"); p.Token != ghKey || p.IssuedByHost != ciAuthority(e) {
		t.Errorf("profile %+v: the stale host was kept", p)
	}
	if !strings.Contains(mustRead(t, configPath()), ciAuthority(e)) || strings.Contains(mustRead(t, configPath()), "old.example.test") {
		t.Error("the stale host is still in the config")
	}
}

func TestTheSavedCIKeyIsNotSentToAnotherHostWithoutYes(t *testing.T) {
	e := newGHEnv(t)
	if code, out, errOut := runGH(t, e.args()...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// A later command is pointed at another host (a flag, here; an environment variable would do as well).
	other := newVaultAPI(t)
	used := authority(&deviceAPI{Server: other.Server})
	args := []string{"secrets", "check", "--api-url", other.URL, "workspace/live/stripe#API_KEY"}
	code, _, errOut := runApp(t, false, fixedClock, args...)
	if code != 1 || !strings.Contains(errOut, "refusing to send the access key saved in profile \"default\" to "+used+": it was issued by "+ciAuthority(e)) || other.count() != 0 {
		t.Fatalf("exit %d, %d requests\n%s", code, other.count(), errOut)
	}
	// With --allow-other-host it goes, after a warning.
	_, _, errOut = runApp(t, false, fixedClock, append([]string{"--allow-other-host"}, args...)...)
	if !strings.Contains(errOut, "(sent because of --allow-other-host)") || other.count() != 1 {
		t.Errorf("--allow-other-host: %d requests\n%s", other.count(), errOut)
	}
	if got := other.last(); got.Auth != "Bearer "+ghKey {
		t.Errorf("the saved key was not the one sent: %+v", got)
	}
}

func TestGitHubActionsLoginNeverChangesTheCurrentProfile(t *testing.T) {
	// --profile NAME: the current profile stays, and the person is told how to use the new key.
	e := newGHEnv(t)
	writeConfig(t, "work", map[string]*config.Profile{"work": {Token: "pat_FAKE-work-key-123456"}})
	code, out, errOut := runGH(t, e.args("--profile", "ci")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if f, _ := config.Load(); f.Current != "work" || f.Profiles["work"].Token != "pat_FAKE-work-key-123456" || f.Profiles["ci"].Token != ghKey {
		t.Errorf("current %q, profiles %+v", f.Current, f.Profiles)
	}
	if !strings.Contains(out, `Profile "ci" is not your current profile (work): use --profile ci, or set AGENTRUNTIME_PROFILE=ci, to use this key.`) {
		t.Errorf("no note about the current profile:\n%s", out)
	}
	// The default profile on a fresh config: it stays the implied one, and no note is needed.
	e = newGHEnv(t)
	code, out, _ = runGH(t, e.args()...)
	if f, _ := config.Load(); code != 0 || f.Current != "" || strings.Contains(out, "is not your current profile") {
		t.Errorf("exit %d, current %q\n%s", code, f.Current, out)
	}
}

func TestGitHubActionsLoginReadsTheConfigAgainBeforeSaving(t *testing.T) {
	pasted := "pat_FAKE-pasted-key-123456789"
	e := newGHEnv(t)
	writeConfig(t, "work", map[string]*config.Profile{"work": {Token: "pat_FAKE-work-key-123456"}})
	// While the exchange is under way, another step adds a profile and a pasted key under the profile this one will use.
	e.api.onCall = func(n int) {
		f, _ := config.Load()
		f.Profiles["added"] = &config.Profile{Token: "pat_FAKE-added-key-123456"}
		f.Profiles["default"] = &config.Profile{Token: pasted}
		f.Current = "added"
		_ = f.Save()
	}
	code, out, errOut := runGH(t, e.args("--profile", "default")...)
	if code != 1 || !strings.Contains(errOut, `the key could not be saved (profile "default" now holds an access key that does not expire`) || !strings.Contains(errOut, "It cannot be shown again") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	f, _ := config.Load()
	if f.Profiles["default"].Token != pasted || f.Profiles["added"] == nil || f.Profiles["work"] == nil || f.Current != "added" {
		t.Errorf("the config another step wrote was not kept: %+v current %q", f.Profiles, f.Current)
	}
	noGHSecrets(t, "reload guard", false, out, errOut)
	if strings.Contains(out+errOut, pasted) {
		t.Error("the existing key was printed")
	}

	// A profile another step added is kept when the key is saved under another name.
	e = newGHEnv(t)
	writeConfig(t, "work", map[string]*config.Profile{"work": {Token: "pat_FAKE-work-key-123456"}})
	e.api.onCall = func(n int) {
		f, _ := config.Load()
		f.Profiles["added"] = &config.Profile{Token: "pat_FAKE-added-key-123456"}
		_ = f.Save()
	}
	if code, out, errOut := runGH(t, e.args("--profile", "ci")...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if f, _ := config.Load(); f.Profiles["added"] == nil || f.Profiles["ci"].Token != ghKey || f.Profiles["work"] == nil {
		t.Errorf("profiles %+v", f.Profiles)
	}
}

func TestGitHubActionsReplaceSaysThatTheOldKeyWasRemovedAndIsNotRevoked(t *testing.T) {
	const line = `The access key that was saved in profile "default" was removed from it. It is not revoked on the server: revoke it in the Console (Settings, API keys) if you no longer need it.`
	pasted := "pat_FAKE-pasted-key-123456789"
	e := newGHEnv(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: pasted, URL: "https://mcp.example.test/mcp"}})
	code, out, errOut := runGH(t, e.args("--replace")...)
	if code != 0 || !strings.Contains(out, "  "+line+"\n") || strings.Contains(out+errOut, pasted) {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// Nothing to say when an earlier sign-in's key is renewed.
	e = newGHEnv(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-short-lived-123456", ExpiresAt: clockNow.Add(-time.Hour).Format(time.RFC3339)}})
	if code, out, _ := runGH(t, e.args()...); code != 0 || strings.Contains(out, "was removed from it") {
		t.Errorf("renewing: exit %d\n%s", code, out)
	}
}

func TestGitHubActionsLoginSaysWhereTheKeyStaysOnARunnerThatKeepsItsHome(t *testing.T) {
	e := newGHEnv(t)
	code, out, errOut := runGH(t, e.args()...)
	if code != 0 || !strings.Contains(out, "The key stays in that file until it expires. On a runner that keeps its home folder between jobs (a self-hosted runner), use --export-env") {
		t.Errorf("exit %d\n%s\n%s", code, out, errOut)
	}
	// --export-env does not touch the profile, so it has nothing to say about it.
	e = newGHEnv(t)
	t.Setenv("GITHUB_ENV", useEnvFile(t, ""))
	if code, out, _ := runGH(t, e.args("--export-env")...); code != 0 || strings.Contains(out, "stays in that file") {
		t.Errorf("--export-env: exit %d\n%s", code, out)
	}
}

// ---- the log says where the identity token goes ----------------------------------------------------------------------

func TestGitHubActionsLoginPrintsTheAPIHostBeforeAskingGitHubForAnything(t *testing.T) {
	// The first thing on standard error, before GitHub is asked: even when GitHub then refuses, the log has the line.
	e := newGHEnv(t)
	e.gh.reply = func(int) ghAnswer { return ghAnswer{status: 403} }
	code, out, errOut := runGH(t, e.args()...)
	if code != 1 || !strings.HasPrefix(errOut, e.apiHostLine()) || out != "" || e.api.hits() != 0 {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, out, errOut)
	}
	// An agentruntime.io host and a host on this machine: no warning. (The recording transport keeps the official host
	// from being reached.)
	e = newGHEnv(t)
	outside := recordOutsideRequests(t)
	code, _, errOut = runGH(t, "login", "--github-actions", "--trust", ghTrust, "--api-url", "https://API.AgentRuntime.IO")
	if code != 1 || !strings.HasPrefix(errOut, "API host: api.agentruntime.io\n") || strings.Contains(errOut, "warning:") {
		t.Errorf("official host: exit %d\n%s", code, errOut)
	}
	if reqs := outside(); len(reqs) != 1 || reqs[0].Host != "api.agentruntime.io" || !strings.HasSuffix(reqs[0].Path, "/v1/auth/workload/exchange") {
		t.Errorf("requests %v: the identity token must go to the host that was printed", reqs)
	}
}

func TestGitHubActionsLoginWarnsForAHostOutsideAgentRuntimeAndStillGoesOn(t *testing.T) {
	e := newGHEnv(t)
	outside := recordOutsideRequests(t)
	code, out, errOut := runGH(t, "login", "--github-actions", "--trust", ghTrust, "--api-url", "https://api.example.test")
	if !strings.HasPrefix(errOut, "API host: api.example.test\n") ||
		!strings.Contains(errOut, "warning: the API host is api.example.test, which is not an agentruntime.io host. This job's identity token is sent to it") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// No question is asked: the command went on and reached the exchange (the recorder refuses to connect, so it fails).
	if reqs := outside(); len(reqs) != 1 || reqs[0].Host != "api.example.test" {
		t.Errorf("requests %v", reqs)
	}
	if e.gh.hits() != 1 {
		t.Errorf("GitHub was asked %d times, want once", e.gh.hits())
	}
	noGHSecrets(t, "foreign host", false, out, errOut)
	nothingSaved(t)

	// A lookalike of the official host is refused as before (3B's rule), not just warned about.
	e = newGHEnv(t)
	outside = recordOutsideRequests(t)
	code, out, errOut = runGH(t, "login", "--github-actions", "--trust", ghTrust, "--api-url", "https://evil.agentrunt"+dottedI+"me.io")
	if code != 1 || !strings.Contains(errOut, "plain ASCII host name") || out != "" || len(outside()) != 0 || e.gh.hits() != 0 {
		t.Errorf("lookalike: exit %d, %d requests, GitHub %d\n%s\n%s", code, len(outside()), e.gh.hits(), out, errOut)
	}
}

func TestGitHubActionsReadmeSaysWhereTheKeyStaysAndWhichHostIsShown(t *testing.T) {
	text := flat(readme(t))
	for _, want := range []string{
		"On a self-hosted runner that keeps its home folder between jobs the key stays in `config.json` until it expires",
		"`--export-env`", "ephemeral", "`API host: <host>`", "not an `agentruntime.io` host", "`issued_by_host`", "is not made current",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
	isolate(t)
	_, help, _ := run(t, "", "login", "--help")
	help = flat(help)
	for _, want := range []string{"prints API host: <host>", "warns when it is not an agentruntime.io host"} {
		if !strings.Contains(help, want) {
			t.Errorf("login --help lacks %q", want)
		}
	}
}

// loopbackOnly records every request and lets only those to this machine through (the fake GitHub and the fake API
// are on it); everything else is refused without connecting, so a test can see what would have been dialled.
type loopbackOnly struct {
	*network
	next http.RoundTripper
}

func (l loopbackOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	l.network.record(req)
	if req.URL.Hostname() == "127.0.0.1" {
		return l.next.RoundTrip(req)
	}
	return nil, errors.New("recorded: no network in tests")
}

func recordOutsideRequests(t *testing.T) func() []seenRequest {
	t.Helper()
	n := &network{}
	orig := http.DefaultTransport
	http.DefaultTransport = loopbackOnly{n, orig}
	t.Cleanup(func() { http.DefaultTransport = orig })
	return func() []seenRequest {
		var out []seenRequest
		for _, r := range n.requests() {
			if !strings.HasPrefix(r.Host, "127.0.0.1") {
				out = append(out, r)
			}
		}
		return out
	}
}
