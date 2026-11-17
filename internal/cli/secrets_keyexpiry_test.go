package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

// A short-lived key reports its end in the X-Key-Expires header of the fetch and check answers. The CLI says so on
// standard error when under ten minutes are left, and says nothing otherwise.

var clockNow = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

func atClock(app *App) { app.now = func() time.Time { return clockNow } }

// expiryServer answers fetch and check for one reference and sends X-Key-Expires when header is not empty.
func expiryServer(t *testing.T, header string) *fakeBFF {
	t.Helper()
	f := newFakeBFF(t)
	f.override = func(r bffReq) (int, string, map[string]string) {
		h := map[string]string{}
		if header != "" {
			h["X-Key-Expires"] = header
		}
		if r.Check {
			return 200, `{"items":[{"ref":"workspace/live/stripe#API_KEY","resolves":true}]}`, h
		}
		return 200, `{"values":{"workspace/live/stripe#API_KEY":"` + fakeKey + `"}}`, h
	}
	return f
}

func at(d time.Duration) string { return clockNow.Add(d).Format(time.RFC3339) }

func TestKeyExpiryNoteWordsAndThreshold(t *testing.T) {
	cases := []struct {
		name, header, want string // want "" means no note at all
	}{
		{"seconds left", at(30 * time.Second), "this key expires in less than a minute"},
		{"one minute", at(70 * time.Second), "this key expires in 1 minute"},
		{"five minutes", at(5*time.Minute + 30*time.Second), "this key expires in 5 minutes"},
		{"just under ten", at(9*time.Minute + 59*time.Second), "this key expires in 9 minutes"},
		{"already past (a slow clock)", at(-1 * time.Minute), "this key expires in less than a minute"},
		{"exactly ten", at(10 * time.Minute), ""},
		{"eleven", at(11 * time.Minute), ""},
		{"two hours", at(2 * time.Hour), ""},
		{"no header", "", ""},
		{"unreadable header", "tomorrow", ""},
		{"a number", "1795000000", ""},
	}
	for _, c := range cases {
		f := expiryServer(t, c.header)
		isolate(t)
		code, out, errOut := runApp(t, false, atClock, "--pat", testToken, "secrets", "check", "--api-url", f.URL, "workspace/live/stripe#API_KEY")
		if code != 0 || out != "workspace/live/stripe#API_KEY: ok\n" {
			t.Errorf("%s: code=%d out=%q err=%q", c.name, code, out, errOut)
			continue
		}
		if c.want == "" {
			if errOut != "" {
				t.Errorf("%s: nothing should be said, got %q", c.name, errOut)
			}
			continue
		}
		if errOut != "note: "+c.want+"\n" {
			t.Errorf("%s: stderr %q, want %q", c.name, errOut, "note: "+c.want+"\n")
		}
	}
}

// Every command that calls the fetch route says it, on standard error only, and its own output is unchanged.
func TestKeyExpiryNoteFromCheckGetRunAndRender(t *testing.T) {
	const note = "note: this key expires in 5 minutes\n"
	header := at(5*time.Minute + 30*time.Second)

	// check (check mode is included)
	f := expiryServer(t, header)
	isolate(t)
	if code, out, errOut := runApp(t, false, atClock, "--pat", testToken, "secrets", "check", "--api-url", f.URL, "--json", "workspace/live/stripe#API_KEY"); code != 0 || errOut != note {
		t.Errorf("check: code=%d err=%q", code, errOut)
	} else {
		mustJSON(t, "check --json", out) // the note is on stderr: standard output stays valid JSON
	}

	// get --print, on a terminal
	if code, out, errOut := runApp(t, true, atClock, "--pat", testToken, "secrets", "get", "--api-url", f.URL, "--print", "workspace/live/stripe#API_KEY"); code != 0 || out != fakeKey+"\n" || errOut != note {
		t.Errorf("get: code=%d out=%q err=%q", code, out, errOut)
	}

	// run: the note comes before the command starts, and the command's own output is not touched
	withHelper(t)
	args := append([]string{"--pat", testToken, "secrets", "run", "--api-url", f.URL, "--env", "K=workspace/live/stripe#API_KEY", "--"}, helper("exit", "0")...)
	if code, out, errOut := runApp(t, false, atClock, args...); code != 0 || out != "" || errOut != note {
		t.Errorf("run: code=%d out=%q err=%q", code, out, errOut)
	}

	// render
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", `k = {{ secret "workspace/live/stripe#API_KEY" }}`+"\n")
	out := filepath.Join(dir, "out.conf")
	isolate(t)
	if code, stdout, errOut := runApp(t, false, atClock, "--pat", testToken, "secrets", "render", "--api-url", f.URL, tpl, "--output", out); code != 0 || errOut != note {
		t.Errorf("render: code=%d out=%q err=%q", code, stdout, errOut)
	}
	if got := mustRead(t, out); got != "k = "+fakeKey+"\n" {
		t.Errorf("file %q", got)
	}
}

func TestKeyExpiryNoteIsNotPrintedWhenTheCallFails(t *testing.T) {
	f := newFakeBFF(t)
	f.override = func(bffReq) (int, string, map[string]string) {
		return 404, `{"error":"not_found","message":"No such secret for this key."}`, map[string]string{"X-Key-Expires": at(time.Minute)}
	}
	isolate(t)
	code, _, errOut := runApp(t, false, atClock, "--pat", testToken, "secrets", "check", "--api-url", f.URL, "my/x#y")
	if code != 1 || strings.Contains(errOut, "expires") || !strings.Contains(errOut, "not_found") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

// ---- the 401 wording for a stored expiry -------------------------------------------------------

// saveProfile writes a profile with the test key and an expiry, and returns nothing: the CLI reads it back.
func saveProfile(t *testing.T, expiresAt string) {
	t.Helper()
	isolate(t)
	f := &config.File{Current: "default", Profiles: map[string]*config.Profile{
		"default": {URL: "https://mcp.example.test/mcp", Token: testToken, ExpiresAt: expiresAt},
	}}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
}

func fetchWith401(t *testing.T) *fakeBFF {
	t.Helper()
	f := newFakeBFF(t)
	f.override = func(bffReq) (int, string, map[string]string) { return 401, ``, nil }
	return f
}

const expiredSentence = "your short-lived key expired; sign in again"

func TestAnExpiredStoredKeyGetsItsOwnSentenceOn401(t *testing.T) {
	f := fetchWith401(t)
	saveProfile(t, at(-time.Second))
	for _, sub := range [][]string{
		{"check", "my/x#y"},
		{"get", "--print", "my/x#y"},
	} {
		args := append([]string{"secrets", sub[0], "--api-url", f.URL}, sub[1:]...)
		code, out, errOut := runApp(t, true, atClock, args...)
		if code != ExitError || out != "" || !strings.Contains(errOut, expiredSentence) {
			t.Errorf("%v: code=%d out=%q err=%q", sub, code, out, errOut)
		}
		if strings.Contains(errOut, "agentruntime login") || strings.Contains(errOut, "HTTP 401") {
			t.Errorf("%v: the generic 401 sentence replaced the specific one: %q", sub, errOut)
		}
	}
	// It is the same for the other API commands, and for hand-over and render.
	v := newVaultAPI(t)
	v.answer("GET /v1/vault/secret/versions", 401, nil, ``)
	if code, _, errOut := runApp(t, true, atClock, "secrets", "history", "--api-url", v.URL, "live/stripe"); code != ExitError || !strings.Contains(errOut, expiredSentence) {
		t.Errorf("history: code=%d err=%q", code, errOut)
	}
	v.answer("POST /v1/secrets/handover", 401, nil, ``)
	if code, _, errOut := runApp(t, true, atClock, "secrets", "handover", "--api-url", v.URL, "my/x#y"); code != ExitError || !strings.Contains(errOut, expiredSentence) {
		t.Errorf("handover: code=%d err=%q", code, errOut)
	}
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", `{{ secret "my/x#y" }}`)
	if code, _, errOut := runApp(t, false, atClock, "secrets", "render", "--api-url", f.URL, tpl, "--output", filepath.Join(dir, "o")); code != ExitError || !strings.Contains(errOut, expiredSentence) {
		t.Errorf("render: code=%d err=%q", code, errOut)
	}
}

func TestA401KeepsTheOldWordingWhenTheStoredKeyHasNotExpired(t *testing.T) {
	f := fetchWith401(t)
	for name, expiresAt := range map[string]string{
		"expiry in the future": at(time.Hour),
		"no stored expiry":     "",
		"unreadable expiry":    "soon",
	} {
		saveProfile(t, expiresAt)
		code, _, errOut := runApp(t, false, atClock, "secrets", "check", "--api-url", f.URL, "my/x#y")
		if code != ExitError || strings.Contains(errOut, expiredSentence) || !strings.Contains(errOut, "HTTP 401") || !strings.Contains(errOut, "agentruntime login") {
			t.Errorf("%s: code=%d err=%q", name, code, errOut)
		}
	}
}

// The stored expiry belongs to the profile's key. A key from a flag or the environment is another key, so a 401
// for it is not explained by that expiry.
func TestTheStoredExpiryOnlyExplainsTheProfilesOwnKey(t *testing.T) {
	f := fetchWith401(t)
	saveProfile(t, at(-time.Hour))

	code, _, errOut := runApp(t, false, atClock, "--pat", testToken, "secrets", "check", "--api-url", f.URL, "my/x#y")
	if code != ExitError || strings.Contains(errOut, expiredSentence) || !strings.Contains(errOut, "HTTP 401") {
		t.Errorf("--pat: code=%d err=%q", code, errOut)
	}
	t.Setenv("AGENTRUNTIME_PAT", testToken)
	code, _, errOut = runApp(t, false, atClock, "secrets", "check", "--api-url", f.URL, "my/x#y")
	if code != ExitError || strings.Contains(errOut, expiredSentence) || !strings.Contains(errOut, "HTTP 401") {
		t.Errorf("AGENTRUNTIME_PAT: code=%d err=%q", code, errOut)
	}
}

func TestAnExpiredStoredKeyOnlyChangesTheWordingOfA401(t *testing.T) {
	f := newFakeBFF(t)
	f.override = func(bffReq) (int, string, map[string]string) {
		return 404, `{"error":"not_found","message":"No such secret for this key."}`, nil
	}
	saveProfile(t, at(-time.Hour))
	code, _, errOut := runApp(t, false, atClock, "secrets", "check", "--api-url", f.URL, "my/x#y")
	if code != ExitError || strings.Contains(errOut, expiredSentence) || !strings.Contains(errOut, "not_found") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

// The moment of expiry counts as expired; one second before does not.
func TestTheStoredExpiryIsInclusive(t *testing.T) {
	f := fetchWith401(t)
	saveProfile(t, at(0))
	if code, _, errOut := runApp(t, false, atClock, "secrets", "check", "--api-url", f.URL, "my/x#y"); code != 1 || !strings.Contains(errOut, expiredSentence) {
		t.Errorf("at the moment: code=%d err=%q", code, errOut)
	}
	saveProfile(t, at(time.Second))
	if code, _, errOut := runApp(t, false, atClock, "secrets", "check", "--api-url", f.URL, "my/x#y"); code != 1 || strings.Contains(errOut, expiredSentence) {
		t.Errorf("one second before: code=%d err=%q", code, errOut)
	}
}

// A key saved or removed by `login` and `logout` takes its expiry with it, so an old expiry never explains a 401 for
// a different key.
func TestLoginAndLogoutDropTheStoredExpiry(t *testing.T) {
	read := func() *config.Profile {
		t.Helper()
		b, err := os.ReadFile(os.Getenv("AGENTRUNTIME_CONFIG"))
		if err != nil {
			t.Fatal(err)
		}
		f, err := config.Load()
		if err != nil || f.Profiles["default"] == nil {
			t.Fatalf("config %s err %v", b, err)
		}
		return f.Profiles["default"]
	}
	saveProfile(t, at(-time.Hour))
	if code, out, errOut := runApp(t, false, nil, "login", "--no-verify", "--token", "pat_a_new_long_lived_key"); code != 0 {
		t.Fatalf("login: %d %s %s", code, out, errOut)
	}
	if p := read(); p.Token != "pat_a_new_long_lived_key" || p.ExpiresAt != "" {
		t.Errorf("after login: %+v", p)
	}
	saveProfile(t, at(time.Hour))
	if code, _, errOut := runApp(t, false, nil, "logout"); code != 0 {
		t.Fatalf("logout: %d %s", code, errOut)
	}
	if p := read(); p.Token != "" || p.ExpiresAt != "" {
		t.Errorf("after logout: %+v", p)
	}
}

// The README says what the commands do, including what they leave behind.
func TestReadmeDescribesHandoverRenderAndShortLivedKeys(t *testing.T) {
	text := flat(readme(t))
	lower := strings.ToLower(text)
	for _, want := range []string{
		"## Hand over a secret once", "one-time access key", "exactly once", "must name its room", "never guesses",
		"printed only when standard output is a terminal", "refuses with exit code 2 and makes nothing", "never writes the token to a file",
		"with or without `--json`", "Short-lived access", "handover_not_for_ai_clients",
		"**only that one field** of the secret", "the **whole secret**, every field in it", "usage lines carry the reference exactly as you gave it",
		"## Render a config file", "Go `text/template`", "Every reference is a quoted string written out in the template",
		"at most 20 different references", "nothing is written", "never overwritten", "**`--replace`**", "renamed over it",
		"**on Windows it is not**", "stays on disk", "`secrets run --secret-file` is the command that removes its file",
		"A name that is not in the secret is an **error**", "`--output -`", "refuses with exit code 2, before anything is fetched",
		"## Short-lived keys", "X-Key-Expires", "this key expires in 7 minutes", "your short-lived key expired; sign in again",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
	for _, bad := range []string{"token_withheld", "leaves the token out", "makes the key but"} {
		if strings.Contains(text, bad) {
			t.Errorf("README still describes the removed --json behaviour: %q", bad)
		}
	}
	// The README of a public repository names no private host or address.
	if strings.Contains(lower, ".internal") {
		t.Error("README names a private (.internal) host")
	}
	if m := privateAddress.FindString(text); m != "" {
		t.Errorf("README names a private network address: %q", m)
	}
	// What the template limits are, in the README as in the help.
	for _, want := range []string{
		"A template runs after the fetch, when a one-use key is already spent, so it is held to limits", "calls itself (directly or through other templates",
		"calls a template that is not defined in the file", "more than 50 deep", "more than 100 deep in a row", "a number above 1000000 inside `{{ }}`",
		"a verb that does not end in a letter", "all the text they build at 16 MiB", "refuse a map of fields as an argument",
		"the whole run at 10 seconds", "These limits are not a promise about the memory or the time of every possible template",
		"A loop that builds no text runs until the 10 seconds are up", "a loop split across templates", "keeps using a processor until the command exits",
		"A fixed sentence and a line number", "a masker cannot take out a value of one or two characters",
	} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
			t.Errorf("README lacks %q", want)
		}
	}
}

// privateAddress matches an address on a private network (10/8, 172.16/12, 192.168/16).
var privateAddress = regexp.MustCompile(`\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b`)
