package cli

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"testing"
)

// Every key below is fake.
const (
	handoverToken  = "pat_FAKE-one_time-key0123456789abcdefghijklmnopqrstuv"
	handoverRef    = "workspace/live/stripe#API_KEY"
	handoverRoute  = "POST /v1/secrets/handover"
	handoverAnswer = `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"workspace/live/stripe#API_KEY","uses":1}`
)

// runApp runs the CLI like run does, with the test seams a test may set: whether standard output is a terminal and
// what time it is. The test access key is given with --pat.
func runApp(t *testing.T, tty bool, tweak func(*App), args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	app := NewApp(strings.NewReader(""), &out, &errb)
	app.isTTYOut = func() bool { return tty }
	if tweak != nil {
		tweak(app)
	}
	code := app.Run(append([]string{"--no-color"}, args...))
	return code, out.String(), errb.String()
}

func handoverAPI(t *testing.T) *vaultAPI {
	t.Helper()
	isolate(t)
	v := newVaultAPI(t)
	v.answer(handoverRoute, http.StatusCreated, nil, handoverAnswer)
	return v
}

// handoverAnswerFor is the answer of a server that does what it was asked: a key for exactly the reference it got.
func handoverAnswerFor(ref string) string {
	return `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"` + ref + `","uses":1}`
}

// runHandover runs the command. Unless a test set its own answer, the fake server answers with a key for the
// reference in the command line, as a correct server does.
func runHandover(t *testing.T, v *vaultAPI, tty bool, args ...string) (int, string, string) {
	t.Helper()
	v.mu.Lock()
	isDefault := v.answers[handoverRoute].Body == handoverAnswer
	v.mu.Unlock()
	if isDefault && len(args) > 0 {
		v.answer(handoverRoute, http.StatusCreated, nil, handoverAnswerFor(strings.TrimPrefix(strings.TrimSpace(args[0]), "secret:")))
	}
	return runApp(t, tty, nil, append([]string{"--pat", testToken, "secrets", "handover", "--api-url", v.URL}, args...)...)
}

func TestHandoverPrintsTheKeyOnceOnATerminalWithTheTwoUsageLines(t *testing.T) {
	v := handoverAPI(t)
	code, out, errOut := runHandover(t, v, true, handoverRef, "--ttl", "30m")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	c := v.last()
	if c.Method != http.MethodPost || c.Path != "/v1/secrets/handover" || c.Auth != "Bearer "+testToken || c.Query != "" {
		t.Fatalf("request %+v", c)
	}
	if len(c.Body) != 2 || c.Body["ref"] != handoverRef || c.Body["ttl_seconds"] != float64(1800) {
		t.Fatalf("body %v: want exactly the ref and 1800 seconds", c.Body)
	}
	if v.count() != 1 {
		t.Fatalf("%d calls, want 1", v.count())
	}
	// The key is printed exactly once, on a line of its own.
	if n := strings.Count(out, handoverToken); n != 1 {
		t.Fatalf("the token appears %d times, want once:\n%s", n, out)
	}
	if !strings.Contains("\n"+out, "\n"+handoverToken+"\n") {
		t.Errorf("the token is not on a line of its own:\n%s", out)
	}
	for _, want := range []string{
		"One-time key for " + handoverRef, "It works once, then it stops", "valid for 30m", "2026-11-16T12:00:00Z",
		"Anyone who has it can read this value once. Do not paste it into an AI tool.",
		// The two usage lines carry a placeholder, not the key again.
		"AGENTRUNTIME_PAT=<token> agentruntime secrets get 'workspace/live/stripe#API_KEY' --print",
		`curl -sS -X POST ` + v.URL + `/v1/secrets/fetch -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"refs":["workspace/live/stripe#API_KEY"]}'`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "<token>"); n != 3 {
		t.Errorf("want <token> in the intro line and the two usage lines (3), found %d:\n%s", n, out)
	}
}

func TestHandoverDefaultsToOneHourAndTakesTheWholeSecret(t *testing.T) {
	v := handoverAPI(t)
	if code, out, errOut := runHandover(t, v, true, "my/deploy"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if c := v.last(); c.Body["ref"] != "my/deploy" || c.Body["ttl_seconds"] != float64(3600) {
		t.Fatalf("body %v", c.Body)
	}
	// A secret: prefix is not sent, and the vault spelling of the command works too.
	isolate(t)
	v.answer(handoverRoute, http.StatusCreated, nil, handoverAnswerFor("my/deploy#TOKEN"))
	code, _, _ := runApp(t, true, nil, "--pat", testToken, "vault", "handover", "--api-url", v.URL, "secret:my/deploy#TOKEN")
	if code != 0 || v.last().Body["ref"] != "my/deploy#TOKEN" {
		t.Fatalf("vault alias: code %d body %v", code, v.last().Body)
	}
}

// Redirected or piped, nothing is made and nothing is printed, with or without --json: a coding agent's shell is
// never a terminal, and a key whose token cannot be shown to anyone would be one nobody can use.
func TestHandoverRefusesWhenStdoutIsNotATerminalAndMakesNothing(t *testing.T) {
	for _, extra := range [][]string{nil, {"--json"}, {"--ttl", "15m", "--json"}, {"--json", "--ttl", "15m"}} {
		v := handoverAPI(t)
		code, out, errOut := runHandover(t, v, false, append([]string{handoverRef}, extra...)...)
		if code != ExitUsage {
			t.Errorf("%v: exit %d, want 2", extra, code)
		}
		if !strings.Contains(errOut, "refusing to make a one-time key") || !strings.Contains(errOut, "not a terminal") {
			t.Errorf("%v: message: %q", extra, errOut)
		}
		if out != "" {
			t.Errorf("%v: stdout must stay empty (no JSON either): %q", extra, out)
		}
		if v.count() != 0 {
			t.Errorf("%v: a refused hand-over must not call the API: it would make a key nobody can use", extra)
		}
		if strings.Contains(out+errOut, "pat_") {
			t.Errorf("%v: a token leaked", extra)
		}
	}
}

func TestHandoverJSONOnATerminalCarriesTheToken(t *testing.T) {
	v := handoverAPI(t)
	code, out, errOut := runHandover(t, v, true, handoverRef, "--json")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	m := mustJSON(t, "handover --json", out)
	if m["token"] != handoverToken || m["ref"] != handoverRef || m["expires_at"] != "2026-11-16T12:00:00Z" || m["uses"] != float64(1) {
		t.Fatalf("json %v", m)
	}
	if len(m) != 4 {
		t.Errorf("json %v: want exactly ref, expires_at, uses and token", m)
	}
	if strings.Count(out, handoverToken) != 1 {
		t.Errorf("the token must appear once in the JSON:\n%s", out)
	}
}

// --json does not change that: with no terminal the command refuses with a plain message and makes no call, so no
// one-use key is left behind that nobody can use. The message says it holds with --json too.
func TestHandoverJSONWithoutATerminalRefusesAndMakesNothing(t *testing.T) {
	v := handoverAPI(t)
	code, out, errOut := runHandover(t, v, false, handoverRef, "--json")
	if code != ExitUsage || out != "" {
		t.Fatalf("exit %d, stdout %q: want exit 2 and nothing on standard output", code, out)
	}
	for _, want := range []string{"refusing to make a one-time key", "not a terminal", "holds with --json too", "Run this in a terminal"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q: %s", want, errOut)
		}
	}
	if strings.Contains(errOut, "token_withheld") || strings.Contains(errOut, "revoke") {
		t.Errorf("there is no key to revoke: %s", errOut)
	}
	if v.count() != 0 {
		t.Errorf("%d calls, want none", v.count())
	}
}

// The token is never written to a file: not in the working folder, not in the CLI's own config.
func TestHandoverNeverWritesTheTokenToAFile(t *testing.T) {
	v := handoverAPI(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	for _, tty := range []bool{true, false} {
		runHandover(t, v, tty, handoverRef)
		runHandover(t, v, tty, handoverRef, "--json")
	}
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Errorf("the working folder has files now: %v", entries)
	}
	if cfg := os.Getenv("AGENTRUNTIME_CONFIG"); cfg != "" {
		if b, err := os.ReadFile(cfg); err == nil && strings.Contains(string(b), "pat_FAKE-one_time") {
			t.Error("the token was saved in the CLI config")
		}
	}
}

func TestHandoverNeedsTheRoomAndAValidReferenceBeforeAnyCall(t *testing.T) {
	v := handoverAPI(t)
	for name, ref := range map[string]string{
		"short name":    "live/stripe",
		"short + field": "live/stripe#API_KEY",
		"room only":     "workspace",
		"shared":        "shared/x#y",
		"traversal":     "workspace/a/../b#c",
		"wildcard":      "workspace/live/*",
		"nothing after": "workspace/live/stripe#",
		"backslash":     `workspace\live\stripe`,
		"empty":         "",
	} {
		code, out, errOut := runHandover(t, v, true, ref)
		if code != ExitUsage || out != "" || errOut == "" {
			t.Errorf("%s: code=%d out=%q err=%q", name, code, out, errOut)
		}
		if len(ref) > 12 && strings.Contains(errOut, ref) {
			t.Errorf("%s: the error repeats the reference: %q", name, errOut)
		}
	}
	if v.count() != 0 {
		t.Errorf("%d calls for references that are wrong on their face", v.count())
	}
	// The error for a short name says what to write.
	_, _, errOut := runHandover(t, v, true, "live/stripe")
	if !strings.Contains(errOut, "needs the room") || !strings.Contains(errOut, "never guesses") {
		t.Errorf("short name message: %q", errOut)
	}
}

func TestHandoverTTLBounds(t *testing.T) {
	good := map[string]float64{
		"1m": 60, "60s": 60, "90s": 90, "15m": 900, "1h": 3600, "24h": 86400, "1d": 86400, "1h30m": 5400, "1440m": 86400, "86400s": 86400,
		"1H": 3600, " 2h ": 7200,
	}
	for in, want := range good {
		v := handoverAPI(t)
		code, out, errOut := runHandover(t, v, true, "my/x#y", "--ttl", in)
		if code != 0 {
			t.Errorf("--ttl %q: exit %d\n%s\n%s", in, code, out, errOut)
			continue
		}
		if got := v.last().Body["ttl_seconds"]; got != want {
			t.Errorf("--ttl %q sent %v, want %v", in, got, want)
		}
	}
	for _, in := range []string{"", "0", "0s", "59s", "30s", "1500ms", "1.5s", "25h", "1441m", "2d", "86401s", "-5m", "abc", "1h1x", "5", "99999999h", "1w"} {
		v := handoverAPI(t)
		code, out, errOut := runHandover(t, v, true, "my/x#y", "--ttl", in)
		if code != ExitUsage || out != "" || !strings.Contains(errOut, "--ttl must be from 1m to 24h") {
			t.Errorf("--ttl %q: code=%d out=%q err=%q", in, code, out, errOut)
		}
		if v.count() != 0 {
			t.Errorf("--ttl %q: the API was called", in)
		}
	}
}

func TestHandoverServerErrorCodes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header map[string]string
		body   string
		want   []string
	}{
		{"handover_not_for_ai_clients", 403, nil, `{"error":"handover_not_for_ai_clients","message":"AI clients cannot."}`, []string{"AI clients cannot.", "(handover_not_for_ai_clients)"}},
		{"not_found", 404, nil, `{"error":"not_found","message":"No such secret for this key."}`, []string{"No such secret for this key.", "(not_found)"}},
		{"fetch_disabled", 403, nil, `{"error":"fetch_disabled","message":"Fetch is off."}`, []string{"Fetch is off.", "(fetch_disabled)"}},
		{"view_disabled", 403, nil, `{"error":"view_disabled","message":"Viewing is off."}`, []string{"Viewing is off.", "(view_disabled)"}},
		{"missing_scope", 403, nil, `{"error":"missing_scope"}`, []string{"secrets:fetch", "(missing_scope)"}},
		{"bad_ref", 400, nil, `{"error":"bad_ref","message":"Not valid."}`, []string{"Not valid.", "(bad_ref)"}},
		{"issuance_invalid", 400, nil, `{"message":"issuance_invalid"}`, []string{"could not make a one-time key", "(issuance_invalid)"}},
		{"issuance_expiry_out_of_bounds", 400, nil, `{"message":"issuance_expiry_out_of_bounds"}`, []string{"between 1 minute and 24 hours", "(issuance_expiry_out_of_bounds)"}},
		{"rate_limited", 429, map[string]string{"Retry-After": "21"}, `{"error":"rate_limited","message":"Slow down."}`, []string{"Slow down.", "(rate_limited)", "21 seconds"}},
		{"audit_failed", 503, nil, `{"error":"audit_failed","message":"Not recorded."}`, []string{"Not recorded.", "(audit_failed)"}},
		{"401", 401, nil, ``, []string{"HTTP 401", "agentruntime login"}},
		{"old server", 404, nil, ``, []string{"does not offer one-time hand-over"}},
	}
	for _, c := range cases {
		v := handoverAPI(t)
		v.answer(handoverRoute, c.status, c.header, c.body)
		code, out, errOut := runHandover(t, v, true, handoverRef)
		if code != ExitError {
			t.Errorf("%s: exit %d, want 1", c.name, code)
		}
		for _, w := range c.want {
			if !strings.Contains(errOut, w) {
				t.Errorf("%s: stderr lacks %q:\n%s", c.name, w, errOut)
			}
		}
		if out != "" {
			t.Errorf("%s: stdout must stay empty, got %q", c.name, out)
		}
		if v.count() != 1 {
			t.Errorf("%s: %d calls, want 1 (no retry)", c.name, v.count())
		}
	}
}

func TestHandoverRefusesAnAnswerWithoutAUsableKey(t *testing.T) {
	for name, body := range map[string]string{
		"no token":       `{"expires_at":"2026-11-16T12:00:00Z","ref":"my/x","uses":1}`,
		"not a key":      `{"token":"hello world","expires_at":"2026-11-16T12:00:00Z","uses":1}`,
		"terminal codes": `{"token":"pat_abc\u001b]52;c;ZmFrZQ==\u0007","uses":1}`,
		"not json":       `<html>oops</html>`,
	} {
		v := handoverAPI(t)
		v.answer(handoverRoute, http.StatusCreated, nil, body)
		for _, extra := range [][]string{nil, {"--json"}} {
			code, out, errOut := runHandover(t, v, true, append([]string{handoverRef}, extra...)...)
			if code != ExitError || !strings.Contains(errOut, "unexpected answer") {
				t.Errorf("%s %v: code=%d err=%q", name, extra, code, errOut)
			}
			if out != "" || strings.Contains(out+errOut, "\x1b") || strings.Contains(errOut, "pat_abc") {
				t.Errorf("%s %v: printed something it should not: out=%q err=%q", name, extra, out, errOut)
			}
		}
	}
}

func TestHandoverNeedsALoginAndASafeAddress(t *testing.T) {
	v := handoverAPI(t)
	code, _, errOut := runApp(t, true, nil, "secrets", "handover", "--api-url", v.URL, handoverRef)
	if code != 1 || !strings.Contains(errOut, "agentruntime login") {
		t.Errorf("not logged in: code=%d err=%q", code, errOut)
	}
	code, _, errOut = runApp(t, true, nil, "--pat", testToken, "secrets", "handover", "--api-url", "http://203.0.113.9:8080", handoverRef)
	if code != 1 || !strings.Contains(errOut, "plain http") {
		t.Errorf("plain http: code=%d err=%q", code, errOut)
	}
	if v.count() != 0 {
		t.Error("nothing may be sent")
	}
}

func TestHandoverHelpSaysWhatItDoes(t *testing.T) {
	isolate(t)
	_, out, _ := run(t, "", "secrets", "handover", "--help")
	out = flat(out)
	for _, want := range []string{
		"exactly what you name, exactly once", "1 minute to 24 hours", "never paste it into an AI tool", "only when standard output is a terminal",
		"exit code 2", "with or without --json", "never writes the token to a file", "must name its room", "written to the workspace's audit log",
		"the key can fetch only that one field of the secret, nothing else", "the key can fetch the whole secret: every field in it",
		"with the same REF you gave here",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("handover --help lacks %q", want)
		}
	}
	_, out, _ = run(t, "", "secrets", "--help")
	for _, want := range []string{"handover", "render"} {
		if !strings.Contains(out, want) {
			t.Errorf("secrets --help does not list %q", want)
		}
	}
}

// The server enforces what the key can fetch: with #FIELD only that field, without it the whole secret. The output
// says which of the two the token gives, and both usage lines carry the reference exactly as it was sent.
func TestHandoverSaysWhichOfTheTwoTheKeyGivesAndRepeatsTheReference(t *testing.T) {
	cases := []struct {
		name, ref       string
		wantScope       string
		forbidScope     string
		wantGet, wantCU string
	}{
		{
			"one field", "workspace/live/stripe#API_KEY",
			"It can fetch only the field API_KEY of that secret, and nothing else (not its other fields).", "WHOLE",
			"agentruntime secrets get 'workspace/live/stripe#API_KEY' --print", `-d '{"refs":["workspace/live/stripe#API_KEY"]}'`,
		},
		{
			"whole secret", "workspace/live/stripe",
			"It can fetch the WHOLE secret (every field in it), and nothing else.", "only the field",
			"agentruntime secrets get workspace/live/stripe --print", `-d '{"refs":["workspace/live/stripe"]}'`,
		},
		{
			"my room, one field, secret: prefix typed", "secret:my/deploy#TOKEN",
			"It can fetch only the field TOKEN of that secret, and nothing else (not its other fields).", "WHOLE",
			"agentruntime secrets get 'my/deploy#TOKEN' --print", `-d '{"refs":["my/deploy#TOKEN"]}'`,
		},
	}
	for _, c := range cases {
		v := handoverAPI(t)
		code, out, errOut := runHandover(t, v, true, c.ref)
		if code != 0 || errOut != "" {
			t.Fatalf("%s: exit %d\n%s\n%s", c.name, code, out, errOut)
		}
		if !strings.Contains(out, c.wantScope) {
			t.Errorf("%s: output does not say what the key gives (%q):\n%s", c.name, c.wantScope, out)
		}
		if strings.Contains(out, c.forbidScope) {
			t.Errorf("%s: output says the wrong thing (%q):\n%s", c.name, c.forbidScope, out)
		}
		lines := strings.Split(out, "\n")
		var get, curl string
		for _, l := range lines {
			switch {
			case strings.Contains(l, "AGENTRUNTIME_PAT=<token>"):
				get = l
			case strings.Contains(l, "curl -sS -X POST"):
				curl = l
			}
		}
		if !strings.Contains(get, c.wantGet) {
			t.Errorf("%s: the `get` line is %q, want it to carry %q", c.name, get, c.wantGet)
		}
		if !strings.Contains(curl, c.wantCU) {
			t.Errorf("%s: the curl line is %q, want it to carry %q", c.name, curl, c.wantCU)
		}
		// What was sent to the server is the same reference the lines name.
		sent, _ := v.last().Body["ref"].(string)
		if sent == "" || !strings.Contains(get, sent) || !strings.Contains(curl, sent) {
			t.Errorf("%s: sent %q, but the usage lines name something else:\n%s\n%s", c.name, sent, get, curl)
		}
	}
}

// The output tells the person what the key can fetch and that it works once, from what they typed. That is only true
// if the server made that key, so an answer for another reference, or for a key that can be used more than once, is
// refused before the token is shown (the key exists by then: the message says where to revoke it).
func TestHandoverRefusesAnAnswerThatDoesNotMatchTheRequest(t *testing.T) {
	cases := map[string]string{
		"another reference":      `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"workspace/live/OTHER#API_KEY","uses":1}`,
		"the whole secret":       `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"workspace/live/stripe","uses":1}`,
		"another field":          `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"workspace/live/stripe#WEBHOOK","uses":1}`,
		"another room":           `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"my/live/stripe#API_KEY","uses":1}`,
		"a different case":       `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"Workspace/live/stripe#API_KEY","uses":1}`,
		"no reference at all":    `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","uses":1}`,
		"an empty reference":     `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"","uses":1}`,
		"a reference with codes": `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"x\u001b]52;c;ZmFrZQ==\u0007","uses":1}`,
		"a very long reference":  `{"token":"` + handoverToken + `","expires_at":"2026-11-16T12:00:00Z","ref":"` + strings.Repeat("a", 5000) + `","uses":1}`,
	}
	for name, body := range cases {
		for _, extra := range [][]string{nil, {"--json"}} {
			v := handoverAPI(t)
			v.answer(handoverRoute, http.StatusCreated, nil, body)
			code, out, errOut := runHandover(t, v, true, append([]string{handoverRef}, extra...)...)
			if code != ExitError || out != "" {
				t.Errorf("%s %v: code=%d stdout=%q: want exit 1 and nothing on standard output", name, extra, code, out)
			}
			if strings.Contains(out+errOut, handoverToken) || strings.Contains(out+errOut, "pat_") {
				t.Errorf("%s %v: the token was printed:\n%s%s", name, extra, out, errOut)
			}
			for _, want := range []string{"not for the reference you asked for", "(" + handoverRef + ")", "Its token was not printed", "nothing was shared", "Short-lived access"} {
				if !strings.Contains(errOut, want) {
					t.Errorf("%s %v: stderr lacks %q:\n%s", name, extra, want, errOut)
				}
			}
			if strings.Contains(errOut, "\x1b") || strings.Contains(errOut, "\x07") || len(errOut) > 1200 {
				t.Errorf("%s %v: server text was not made safe or short (%d bytes): %q", name, extra, len(errOut), errOut)
			}
		}
	}
}

func TestHandoverRefusesAKeyThatCanBeUsedMoreThanOnce(t *testing.T) {
	for name, uses := range map[string]string{"five uses": `"uses":5`, "zero": `"uses":0`, "no uses field": `"x":1`, "negative": `"uses":-1`} {
		v := handoverAPI(t)
		v.answer(handoverRoute, http.StatusCreated, nil, `{"token":"`+handoverToken+`","expires_at":"2026-11-16T12:00:00Z","ref":"`+handoverRef+`",`+uses+`}`)
		code, out, errOut := runHandover(t, v, true, handoverRef)
		if code != ExitError || out != "" || !strings.Contains(errOut, "not once as a hand-over must be") || !strings.Contains(errOut, "Its token was not printed") {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", name, code, out, errOut)
		}
		if strings.Contains(out+errOut, "pat_") {
			t.Errorf("%s: the token was printed", name)
		}
	}
}

// An answer that matches is printed, whatever spelling the person typed: the comparison is with what was SENT (the
// reference without a secret: prefix), which is what a correct server stores.
func TestHandoverAcceptsTheAnswerForWhatWasSent(t *testing.T) {
	for _, typed := range []string{"workspace/live/stripe#API_KEY", "secret:workspace/live/stripe#API_KEY", "  workspace/live/stripe#API_KEY  ", "my/deploy", "project/x/y#Z"} {
		v := handoverAPI(t)
		code, out, errOut := runHandover(t, v, true, typed)
		if code != 0 || !strings.Contains(out, handoverToken) || errOut != "" {
			t.Errorf("%q: code=%d out=%q err=%q", typed, code, out, errOut)
		}
	}
}
