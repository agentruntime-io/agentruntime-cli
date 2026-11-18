package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

// Every code, key and name below is fake.
const (
	devCode = "FAKE-device_code-0123456789abcdefghijklmnopqrstuvwxyz"
	devKey  = "pat_FAKE-device_key-0123456789abcdefghijklmnopqrstuvw"
	devUser = "BCDF-2345"
)

type devAnswer struct {
	status int
	header map[string]string
	body   string
}

func ok(body string) devAnswer { return devAnswer{200, nil, body} }

func pending() devAnswer { return devAnswer{400, nil, `{"error":"authorization_pending"}`} }
func slowDown() devAnswer {
	return devAnswer{400, nil, `{"error":"slow_down","message":"Polling too fast."}`}
}
func denied() devAnswer  { return devAnswer{400, nil, `{"error":"access_denied"}`} }
func expired() devAnswer { return devAnswer{400, nil, `{"error":"expired_token"}`} }

// codeBody is the answer to a code request.
func codeBody(verify, complete string, expiresIn, interval int) string {
	c := ""
	if complete != "" {
		c = `,"verification_uri_complete":"` + complete + `"`
	}
	return fmt.Sprintf(`{"device_code":%q,"user_code":%q,"verification_uri":%q%s,"expires_in":%d,"interval":%d}`,
		devCode, devUser, verify, c, expiresIn, interval)
}

func goodCode() devAnswer {
	return ok(codeBody("https://console.example.test/device", "https://console.example.test/device?code="+devUser, 600, 5))
}

// grantBody is the answer to the poll that follows an approval.
func grantBody(scopes, refs string) string {
	return `{"token":"` + devKey + `","expires_at":"` + clockNow.Add(time.Hour).Format(time.RFC3339) +
		`","tenant_id":"tenant-1","scopes":` + scopes + `,"refs":` + refs + `}`
}

func goodGrant() devAnswer { return ok(grantBody(`["secrets:fetch"]`, `["workspace/live/*"]`)) }

// deviceAPI stands in for the two public device routes and records every request.
type deviceAPI struct {
	*httptest.Server
	mu      sync.Mutex
	starts  []map[string]any
	headers []http.Header
	polls   []string // the raw bodies of the polls
	paths   []string
	// start and poll decide the answers; n counts from 1.
	start  func(n int) devAnswer
	poll   func(n int) devAnswer
	onPoll func(n int) // runs before the answer of poll n is sent
}

func newDeviceAPI(t *testing.T) *deviceAPI {
	t.Helper()
	d := &deviceAPI{
		start: func(int) devAnswer { return goodCode() },
		poll:  func(int) devAnswer { return pending() },
	}
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		d.headers = append(d.headers, r.Header.Clone())
		d.paths = append(d.paths, r.Method+" "+r.URL.Path)
		var ans devAnswer
		switch r.URL.Path {
		case "/v1/auth/device/code":
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			d.starts = append(d.starts, body)
			ans = d.start(len(d.starts))
		case "/v1/auth/device/token":
			d.polls = append(d.polls, string(raw))
			n := len(d.polls)
			hook := d.onPoll
			d.mu.Unlock()
			if hook != nil {
				hook(n)
			}
			d.mu.Lock()
			ans = d.poll(n)
		default:
			ans = devAnswer{404, nil, ``}
		}
		d.mu.Unlock()
		if ans.status == -1 { // drop the connection without answering
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		for k, v := range ans.header {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ans.status)
		_, _ = w.Write([]byte(ans.body))
	}))
	t.Cleanup(d.Close)
	return d
}

// pollScript answers the polls in order and repeats the last answer.
func pollScript(answers ...devAnswer) func(int) devAnswer {
	return func(n int) devAnswer {
		if n > len(answers) {
			n = len(answers)
		}
		return answers[n-1]
	}
}

func (d *deviceAPI) hits() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.paths)
}

func (d *deviceAPI) pollCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.polls)
}

// devEnv is the clock, the waiting and the browser of one run, so a test takes no real time.
type devEnv struct {
	mu      sync.Mutex
	now     time.Time
	sleeps  []time.Duration
	opened  []string
	sigs    chan os.Signal
	ctxSeen []context.Context // the context of each wait
	openErr error             // what the browser opener returns

	// From the blockAt-th wait on, the wait does not return until its context ends. With signalOnBlock it also sends
	// Ctrl-C first; without, only a deadline can end it. Zero means never block.
	blockAt       int
	signalOnBlock bool
}

func newDevEnv() *devEnv { return &devEnv{now: clockNow, sigs: make(chan os.Signal, 4)} }

func (e *devEnv) tweak(a *App) {
	a.now = func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
	a.signalSource = e.sigs
	a.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		e.mu.Lock()
		e.ctxSeen = append(e.ctxSeen, ctx)
		n := len(e.ctxSeen)
		e.mu.Unlock()
		if e.blockAt > 0 && n >= e.blockAt {
			if e.signalOnBlock {
				e.sigs <- syscall.SIGINT
			}
			<-ctx.Done()
			return ctx.Err()
		}
		e.mu.Lock()
		e.sleeps = append(e.sleeps, d)
		e.now = e.now.Add(d)
		e.mu.Unlock()
		return nil
	}
	a.openURL = func(u string) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.opened = append(e.opened, u)
		return e.openErr
	}
}

func (e *devEnv) slept() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]time.Duration(nil), e.sleeps...)
}

// notSavedNote is what every run against the fake prints: the fake API address is not the one the profile derives.
const notSavedNote = "note: the API address you gave is not saved. Pass --api-url (or set AGENTRUNTIME_API_URL) on later commands that need it.\n"

// deviceArgs is `login --device` against the fake, asking for one folder.
func deviceArgs(d *deviceAPI, extra ...string) []string {
	return append([]string{"login", "--device", "--api-url", d.URL, "--ref", "workspace/live/*", "--device-name", "test-laptop"}, extra...)
}

// runDevice runs the CLI against the fake with the run's own clock and browser.
func runDevice(t *testing.T, e *devEnv, args ...string) (int, string, string) {
	t.Helper()
	return runApp(t, false, e.tweak, args...)
}

func configPath() string { return os.Getenv("AGENTRUNTIME_CONFIG") }

// savedProfile reads the config back.
func savedProfile(t *testing.T, name string) *config.Profile {
	t.Helper()
	f, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	return f.Profiles[name]
}

// writeConfig saves profiles as the CLI would.
func writeConfig(t *testing.T, current string, profiles map[string]*config.Profile) {
	t.Helper()
	if err := (&config.File{Current: current, Profiles: profiles}).Save(); err != nil {
		t.Fatal(err)
	}
}

// noSecrets fails when the device code or the key is in any output. Nothing the CLI prints may hold either.
func noSecrets(t *testing.T, what string, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, s := range []string{devCode, devKey, strings.TrimPrefix(devKey, "pat_")} {
			if strings.Contains(o, s) {
				t.Errorf("%s: a secret (%.8s…) appears in the output:\n%s", what, s, o)
			}
		}
	}
}

// noTerminalCodes fails when an output holds a byte a terminal would act on.
func noTerminalCodes(t *testing.T, what string, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, r := range o {
			if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Errorf("%s: control character %U in the output:\n%q", what, r, o)
				return
			}
		}
	}
}

func nothingSaved(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(configPath()); err == nil {
		t.Errorf("a config file was written:\n%s", mustRead(t, configPath()))
	}
	if _, err := os.Stat(configPath() + ".tmp"); err == nil {
		t.Error("a temp config file is left behind")
	}
}

// ---- the whole flow -------------------------------------------------------------------------------------------

func TestDeviceLoginPendingSlowDownThenSuccessSavesTheKeyWithItsExpiry(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(pending(), pending(), slowDown(), pending(), goodGrant())
	e := newDevEnv()
	code, out, errOut := runDevice(t, e, deviceArgs(d)...)
	if code != 0 || errOut != notSavedNote {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}

	// The wait before each poll is the server's interval; a slow_down adds five seconds from then on.
	want := []time.Duration{5 * time.Second, 5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}
	if got := e.slept(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("waits %v, want %v", got, want)
	}
	if d.pollCount() != 5 {
		t.Errorf("%d polls, want 5", d.pollCount())
	}

	// What the person sees.
	for _, want := range []string{
		"https://console.example.test/device", "code: " + devUser, "https://console.example.test/device?code=" + devUser,
		"This asks for: fetching workspace/live/*, for up to 1h", "Device: test-laptop",
		"Approve it only if you started this from your own terminal just now.", "The code works for 10m",
		"signed in until ", "; fetch only", "Scopes: secrets:fetch", "Secrets it may fetch: workspace/live/*",
		`Saved to profile "default" in ` + configPath(),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !regexp.MustCompile(`signed in until \d{4}-\d\d-\d\d \d\d:\d\d \S+ \(in 59 minutes\); fetch only`).MatchString(out) {
		t.Errorf("the sign-in line is not in the expected form:\n%s", out)
	}
	noSecrets(t, "login --device", out, errOut)

	// What is saved: the key and its expiry, in the field the rest of the CLI reads.
	p := savedProfile(t, "default")
	if p == nil || p.Token != devKey || p.ExpiresAt != clockNow.Add(time.Hour).Format(time.RFC3339) {
		t.Fatalf("profile %+v", p)
	}
	f, _ := config.Load()
	if f.Current != "" {
		t.Errorf("the sign-in changed the current profile to %q; it must leave it alone", f.Current)
	}
	if r := f.Resolve(config.Overrides{}); r.Token != devKey || !r.TokenExpiresAt.Equal(clockNow.Add(time.Hour)) {
		t.Errorf("the saved key does not resolve with its expiry: %+v", r)
	}
	// The key is in the config file and nowhere else, and the expiry is stored under the field name batch 3A reads.
	raw := mustRead(t, configPath())
	if n := strings.Count(raw, devKey); n != 1 {
		t.Errorf("the config holds the key %d times", n)
	}
	if !strings.Contains(raw, `"expires_at": "`+clockNow.Add(time.Hour).Format(time.RFC3339)+`"`) {
		t.Errorf("the config file has no expires_at:\n%s", strings.ReplaceAll(raw, devKey, "<key>"))
	}
	if _, err := os.Stat(configPath() + ".tmp"); err == nil {
		t.Error("temp file left behind")
	}
}

func TestDeviceLoginSendsOnlyWhatItShouldAndNeverAnAuthorizationHeader(t *testing.T) {
	isolate(t)
	// A saved short-lived key, and a key in the environment: the pre-sign-in calls must carry neither.
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-old-saved-key-123", ExpiresAt: clockNow.Add(-time.Hour).Format(time.RFC3339)}})
	t.Setenv("AGENTRUNTIME_PAT", "pat_FAKE-env-key-0123456789")
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	e := newDevEnv()
	code, out, errOut := runDevice(t, e, deviceArgs(d, "--ttl", "90m", "--scope", "vault:read")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	want := `{"allow_all":false,"client":"agentruntime-cli","device_name":"test-laptop","refs":["workspace/live/*"],"scopes":["secrets:fetch","vault:read"],"ttl_seconds":5400}`
	got, _ := json.Marshal(d.starts[0])
	if string(got) != want {
		t.Errorf("code request %s\nwant         %s", got, want)
	}
	if len(d.polls) != 1 || d.polls[0] != `{"device_code":"`+devCode+`"}` {
		t.Errorf("poll bodies %v: want exactly the device code", d.polls)
	}
	for i, h := range d.headers {
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" || strings.Contains(fmt.Sprint(h), "pat_FAKE") {
			t.Errorf("request %d carried credentials: %v", i, h)
		}
		if h.Get("Content-Type") != "application/json" {
			t.Errorf("request %d content type %q", i, h.Get("Content-Type"))
		}
	}
	if d.paths[0] != "POST /v1/auth/device/code" || d.paths[1] != "POST /v1/auth/device/token" {
		t.Errorf("routes %v", d.paths)
	}
	// The environment key still overrides the saved one, and the person is told.
	if !strings.Contains(errOut, "AGENTRUNTIME_PAT is set in your environment and overrides the saved key") {
		t.Errorf("no note about the environment key: %q", errOut)
	}
	noSecrets(t, "login --device", out, errOut)
	if strings.Contains(out+errOut, "pat_FAKE-env") || strings.Contains(out+errOut, "pat_FAKE-old") {
		t.Error("another key was printed")
	}
}

func TestDeviceLoginAllSecretsWithListingAnotherProfile(t *testing.T) {
	isolate(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-normal-pat-1234", URL: "https://mcp.example.test/mcp"}})
	d := newDeviceAPI(t)
	d.poll = pollScript(ok(`{"token":"` + devKey + `","expires_at":"` + clockNow.Add(time.Hour).Format(time.RFC3339) + `","scopes":["secrets:fetch","vault:read"],"allow_all":true}`))
	e := newDevEnv()
	code, out, errOut := runDevice(t, e, "login", "--device", "--api-url", d.URL, "--all", "--scope", "vault:read", "--ttl", "8h", "--profile", "ci", "--device-name", "ci box")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	got, _ := json.Marshal(d.starts[0])
	if want := `{"allow_all":true,"client":"agentruntime-cli","device_name":"ci box","scopes":["secrets:fetch","vault:read"],"ttl_seconds":28800}`; string(got) != want {
		t.Errorf("code request %s\nwant         %s", got, want)
	}
	for _, want := range []string{"This asks for: fetching every secret you may view, and listing secret names, for up to 8h", "; fetch and list names only", "Secrets it may fetch: every secret you may view", `Profile "ci" is not your current profile (default): use --profile ci, or set AGENTRUNTIME_PROFILE=ci, to use this key.`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// The other profile is untouched, and the current profile stays as it was (here the default one): a fetch-only key
	// must not become the key whoami and workflows use. The person is told how to use it.
	f, _ := config.Load()
	if f.Current != "default" || f.Profiles["default"].Token != "pat_FAKE-normal-pat-1234" || f.Profiles["default"].ExpiresAt != "" || f.Profiles["ci"].Token != devKey {
		t.Errorf("config %+v / %+v", f.Profiles["default"], f.Profiles["ci"])
	}
}

func TestDeviceLoginSaysWhatWasApprovedWhenTheApproverNarrowedIt(t *testing.T) {
	cases := []struct {
		name, grant, want string
	}{
		{"fewer secrets", grantBody(`["secrets:fetch"]`, `["workspace/live/stripe"]`), "Secrets it may fetch: workspace/live/stripe"},
		{"no secrets", grantBody(`["secrets:fetch"]`, `[]`), "Secrets it may fetch: none listed (it fetches nothing)"},
		{"names only", grantBody(`["vault:read"]`, `["my/*"]`), "list names only (it cannot fetch values)"},
		{"no scopes", grantBody(`[]`, `["my/*"]`), "it carries no scope the CLI uses"},
		{"a scope this CLI does not know", grantBody(`["secrets:fetch","tenant:admin"]`, `["my/*"]`), "scopes this CLI does not know"},
		{"many secrets", grantBody(`["secrets:fetch"]`, `["my/1","my/2","my/3","my/4","my/5","my/6","my/7"]`), "my/1, my/2, my/3, my/4, my/5 and 2 more"},
	}
	for _, c := range cases {
		isolate(t)
		d := newDeviceAPI(t)
		d.poll = pollScript(ok(c.grant))
		code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
		if code != 0 || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d, want %q in:\n%s\n%s", c.name, code, c.want, out, errOut)
		}
		if c.name == "a scope this CLI does not know" && strings.Contains(out, "; fetch only") {
			t.Errorf("%s: said 'fetch only' for a key with another scope:\n%s", c.name, out)
		}
		noSecrets(t, c.name, out, errOut)
	}
}

func TestDeviceLoginDefaultTTLAndDefaultDeviceName(t *testing.T) {
	isolate(t)
	hostnameFn = func() (string, error) { return "My\x1b[2J  Laptop\u200b" + strings.Repeat("x", 100), nil }
	t.Cleanup(func() { hostnameFn = os.Hostname })
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	code, out, errOut := runApp(t, false, newDevEnv().tweak, "login", "--device", "--api-url", d.URL, "--ref", "my/*")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if d.starts[0]["ttl_seconds"] != float64(3600) {
		t.Errorf("default ttl %v", d.starts[0]["ttl_seconds"])
	}
	name, _ := d.starts[0]["device_name"].(string)
	if !strings.HasPrefix(name, "My[2J Laptop") || len([]rune(name)) != 64 || strings.ContainsAny(name, "\x1b\u200b") {
		t.Errorf("device name %q: control characters must go, the rest is cut to 64 characters", name)
	}
	noTerminalCodes(t, "default device name", out, errOut)

	// No usable machine name: a plain default.
	isolate(t)
	hostnameFn = func() (string, error) { return "", fmt.Errorf("no hostname") }
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runApp(t, false, newDevEnv().tweak, "login", "--device", "--api-url", d.URL, "--ref", "my/*"); code != 0 || d.starts[0]["device_name"] != "AgentRuntime CLI" {
		t.Errorf("exit %d name %v\n%s\n%s", code, d.starts[0]["device_name"], out, errOut)
	}
}

// ---- the ways it ends -----------------------------------------------------------------------------------------

func TestDeviceLoginDeniedSavesNothing(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(pending(), denied())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || !strings.Contains(errOut, "the sign-in was denied in the Console. Nothing was saved") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if strings.Contains(out, "signed in") {
		t.Errorf("said it signed in:\n%s", out)
	}
	if d.pollCount() != 2 {
		t.Errorf("%d polls after a denial, want 2", d.pollCount())
	}
	noSecrets(t, "denied", out, errOut)
	nothingSaved(t)
}

func TestDeviceLoginExpiredCodeSavesNothing(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(pending(), expired())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || !strings.Contains(errOut, "expired (or was already used) before it was approved. Nothing was saved. Run `agentruntime login --device` again") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	noSecrets(t, "expired", out, errOut)
	nothingSaved(t)
}

func TestDeviceLoginStopsWhenTheCodesLifetimeEnds(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.start = func(int) devAnswer { return ok(codeBody("https://console.example.test/device", "", 60, 5)) }
	e := newDevEnv()
	code, out, errOut := runDevice(t, e, deviceArgs(d)...)
	if code != 1 || !strings.Contains(errOut, "expired (or was already used) before it was approved") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// 60 seconds at one poll every 5 seconds: the 12th poll is the last.
	if d.pollCount() != 12 {
		t.Errorf("%d polls, want 12", d.pollCount())
	}
	if strings.Contains(out, "which has the code in it") {
		t.Errorf("a missing complete address must not leave a dangling line:\n%s", out)
	}
	nothingSaved(t)
}

func TestDeviceKeyIsDeliveredOnceSoTheFirstGrantEndsTheLoop(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant(), expired(), expired())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 0 || d.pollCount() != 1 {
		t.Fatalf("exit %d after %d polls (want 1)\n%s\n%s", code, d.pollCount(), out, errOut)
	}
	if savedProfile(t, "default").Token != devKey {
		t.Error("the key was not saved")
	}
}

// A poll whose answer is lost on the way: the server may already have handed the key over, and every later poll is
// "expired". The CLI must not claim success, and must not save anything.
func TestDeviceLoginALostAnswerLeavesNothingSaved(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(devAnswer{status: -1}, expired())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || d.pollCount() != 2 || !strings.Contains(errOut, "expired (or was already used)") {
		t.Fatalf("exit %d after %d polls\n%s\n%s", code, d.pollCount(), out, errOut)
	}
	noSecrets(t, "lost answer", out, errOut)
	nothingSaved(t)
}

func TestDeviceLoginRetriesTransientFailuresAndGivesUpAfterFiveInARow(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(devAnswer{503, nil, ``}, devAnswer{500, nil, `oops`}, pending(), devAnswer{503, nil, ``}, goodGrant())
	e := newDevEnv()
	if code, out, errOut := runDevice(t, e, deviceArgs(d)...); code != 0 || d.pollCount() != 5 {
		t.Fatalf("exit %d after %d polls\n%s\n%s", code, d.pollCount(), out, errOut)
	}
	// The counter restarts after a good answer: failures spread out never add up to five in a row.

	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(devAnswer{503, nil, ``})
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || d.pollCount() != 6 || !strings.Contains(errOut, "could not check for the approval (6 tries in a row failed") || !strings.Contains(errOut, "Nothing was saved") {
		t.Fatalf("exit %d after %d polls\n%s\n%s", code, d.pollCount(), out, errOut)
	}
	noSecrets(t, "gave up", out, errOut)
	nothingSaved(t)
}

func TestDeviceLoginBacksOffOnTooManyRequestsAndHonoursRetryAfter(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(devAnswer{429, map[string]string{"Retry-After": "20"}, `{"error":"rate_limited"}`}, devAnswer{429, nil, ``}, goodGrant())
	e := newDevEnv()
	if code, out, errOut := runDevice(t, e, deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// 5 s, then Retry-After 20 s, then 20+5 s.
	want := []time.Duration{5 * time.Second, 20 * time.Second, 25 * time.Second}
	if got := e.slept(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("waits %v, want %v", got, want)
	}
}

func TestDeviceLoginUnknownRefusalIsNotRetried(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(devAnswer{403, nil, `{"error":"device_login_disabled","message":"Device sign-in is off."}`})
	code, _, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || d.pollCount() != 1 || !strings.Contains(errOut, "the sign-in failed: Device sign-in is off. (device_login_disabled)") {
		t.Fatalf("exit %d after %d polls\n%s", code, d.pollCount(), errOut)
	}
	nothingSaved(t)
}

func TestDeviceLoginCtrlCSaysCancelledAndSavesNothing(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(pending())
	e := newDevEnv()
	e.blockAt, e.signalOnBlock = 3, true // the third wait gets Ctrl-C and ends with its context
	code, out, errOut := runDevice(t, e, deviceArgs(d)...)
	if code != 130 || !strings.Contains(errOut, "cancelled. Nothing was saved. The code stops working by itself in a few minutes; do not approve it") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if d.pollCount() != 2 {
		t.Errorf("%d polls, want 2 (none after the signal)", d.pollCount())
	}
	noSecrets(t, "ctrl-c", out, errOut)
	nothingSaved(t)
}

func TestDeviceLoginCtrlCWhileStarting(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	e := newDevEnv()
	e.sigs <- syscall.SIGINT // already pending when the command starts
	d.start = func(int) devAnswer {
		time.Sleep(200 * time.Millisecond) // long enough for the signal to cancel the request first
		return goodCode()
	}
	code, out, errOut := runDevice(t, e, deviceArgs(d)...)
	if code != 130 || !strings.Contains(errOut, "cancelled. Nothing was saved") || d.pollCount() != 0 {
		t.Fatalf("exit %d after %d polls\n%s\n%s", code, d.pollCount(), out, errOut)
	}
	nothingSaved(t)
}

func TestDeviceLoginDefaultTimeoutDoesNotCutTheWaitButAnExplicitOneDoes(t *testing.T) {
	// The default --timeout is 6 minutes and the code lives 10: the wait must not carry the default deadline.
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	e := newDevEnv()
	if code, out, errOut := runDevice(t, e, deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if _, has := e.ctxSeen[0].Deadline(); has {
		t.Error("the default --timeout was applied to the wait for the approval")
	}

	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	e = newDevEnv()
	if code, out, errOut := runDevice(t, e, deviceArgs(d, "--timeout", "1h")...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if dl, has := e.ctxSeen[0].Deadline(); !has || time.Until(dl) < 50*time.Minute || time.Until(dl) > time.Hour {
		t.Errorf("an explicit --timeout 1h was not applied: %v %v", dl, has)
	}

	// An explicit timeout that passes before the approval ends the wait with a plain message.
	isolate(t)
	d = newDeviceAPI(t)
	e = newDevEnv()
	e.blockAt = 2 // no signal: only the deadline can end the second wait
	code, out, errOut := runDevice(t, e, deviceArgs(d, "--timeout", "100ms")...)
	if code != 1 || !strings.Contains(errOut, "gave up waiting: --timeout 100ms passed before the code was approved. Nothing was saved") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	nothingSaved(t)
}

// ---- start failures -------------------------------------------------------------------------------------------

func TestDeviceLoginStartErrors(t *testing.T) {
	cases := []struct {
		name string
		ans  devAnswer
		want string
	}{
		{"rate limited", devAnswer{429, map[string]string{"Retry-After": "30"}, `{"error":"rate_limited"}`}, "could not start the sign-in: Too many sign-in attempts from this network. Wait a minute and try again. (rate_limited)"},
		{"not offered", devAnswer{404, nil, `<html>not found</html>`}, "does not offer device sign-in"},
		{"invalid", devAnswer{400, nil, `{"error":"invalid_scope","message":"No such scope."}`}, "No such scope."},
		{"down", devAnswer{503, nil, ``}, "HTTP 503"},
	}
	for _, c := range cases {
		isolate(t)
		d := newDeviceAPI(t)
		d.start = func(int) devAnswer { return c.ans }
		code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
		if code != 1 || !strings.Contains(errOut, c.want) || d.pollCount() != 0 || strings.Contains(out, "To sign in") {
			t.Errorf("%s: exit %d polls %d\nstdout: %s\nstderr: %s", c.name, code, d.pollCount(), out, errOut)
		}
		nothingSaved(t)
	}
}

func TestDeviceLoginUnusableStartAnswers(t *testing.T) {
	good := func(user, verify string) string {
		b, _ := json.Marshal(map[string]any{"device_code": devCode, "user_code": user, "verification_uri": verify, "expires_in": 600, "interval": 5})
		return string(b)
	}
	cases := []struct{ name, body, want string }{
		{"not json", `<html>maintenance</html>`, "unexpected answer from the server"},
		{"empty", ``, "unexpected answer from the server"},
		{"no device code", `{"user_code":"BCDF-2345","verification_uri":"https://c.example.test/d"}`, "no usable device code"},
		{"escape in the user code", good("AB\x1b]0;pwned\x07CD", "https://c.example.test/d"), "no usable user code"},
		{"only an escape in the user code", good("ABCD\x1bEF", "https://c.example.test/d"), "no usable user code"},
		{"newline in the user code", good("ABCD\nEFGH", "https://c.example.test/d"), "no usable user code"},
		{"javascript address", good(devUser, "javascript:alert(1)"), "the sign-in address is not usable"},
		{"file address", good(devUser, "file:///etc/passwd"), "the sign-in address is not usable"},
		{"ftp address", good(devUser, "ftp://c.example.test/d"), "the sign-in address is not usable"},
		{"address with a user name", good(devUser, "https://admin:pw@c.example.test/d"), "the sign-in address is not usable"},
		{"address with a space", good(devUser, "https://c.example.test/a b"), "the sign-in address is not usable"},
		{"address with a line break", good(devUser, "https://c.example.test/a\nb"), "the sign-in address is not usable"},
		{"address with an escape", good(devUser, "https://c.example.test/\x1b[2J"), "the sign-in address is not usable"},
		{"non-ASCII address", good(devUser, "https://c\u00e9.example.test/d"), "the sign-in address is not usable"},
		{"no host", good(devUser, "https:///d"), "the sign-in address is not usable"},
	}
	for _, c := range cases {
		isolate(t)
		d := newDeviceAPI(t)
		d.start = func(int) devAnswer { return ok(c.body) }
		code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
		if code != 1 || !strings.Contains(errOut, c.want) || d.pollCount() != 0 {
			t.Errorf("%s: exit %d polls %d\nstdout: %s\nstderr: %s", c.name, code, d.pollCount(), out, errOut)
		}
		noTerminalCodes(t, c.name, out, errOut)
		noSecrets(t, c.name, out, errOut)
		if strings.Contains(out+errOut, "pwned") || strings.Contains(out+errOut, "admin:pw") || strings.Contains(out+errOut, "maintenance") {
			t.Errorf("%s: text from the server was shown:\n%s\n%s", c.name, out, errOut)
		}
		nothingSaved(t)
	}
}

func TestDeviceLoginLeavesOutAnUnusableCompleteAddress(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.start = func(int) devAnswer {
		return ok(codeBody("https://console.example.test/device", "javascript:alert(1)", 600, 5))
	}
	d.poll = pollScript(goodGrant())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 0 || strings.Contains(out, "javascript") || strings.Contains(out, "which has the code in it") || !strings.Contains(out, "code: "+devUser) {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestDeviceLoginUnusableGrants(t *testing.T) {
	cases := []struct{ name, body string }{
		{"not json", `<html>`},
		{"no token", `{"expires_at":"2026-11-16T11:00:00Z","scopes":["secrets:fetch"]}`},
		{"not a key", `{"token":"NOTAKEY-secretish-12345","expires_at":"2026-11-16T11:00:00Z"}`},
		{"key with an escape", `{"token":"pat_ab\u001b]0;pwned\u0007cd","expires_at":"2026-11-16T11:00:00Z"}`},
		{"no expiry", `{"token":"` + devKey + `","scopes":["secrets:fetch"]}`},
		{"unreadable expiry", `{"token":"` + devKey + `","expires_at":"soon"}`},
	}
	for _, c := range cases {
		isolate(t)
		d := newDeviceAPI(t)
		d.poll = pollScript(ok(c.body), expired())
		code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
		if code != 1 || !strings.Contains(errOut, "the sign-in failed: unexpected answer from the server") {
			t.Errorf("%s: exit %d\n%s\n%s", c.name, code, out, errOut)
		}
		if d.pollCount() != 1 {
			t.Errorf("%s: an unreadable answer was retried (%d polls)", c.name, d.pollCount())
		}
		noSecrets(t, c.name, out, errOut)
		noTerminalCodes(t, c.name, out, errOut)
		for _, leak := range []string{"NOTAKEY", "pwned"} {
			if strings.Contains(out+errOut, leak) {
				t.Errorf("%s: %q from the server was shown", c.name, leak)
			}
		}
		nothingSaved(t)
	}
}

// ---- redirects and plain http ---------------------------------------------------------------------------------

func TestDeviceLoginNeverFollowsARedirect(t *testing.T) {
	var landed int
	var mu sync.Mutex
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); landed++; mu.Unlock() }))
	defer other.Close()

	// At the code request.
	isolate(t)
	d := newDeviceAPI(t)
	d.start = func(int) devAnswer {
		return devAnswer{307, map[string]string{"Location": other.URL + "/v1/auth/device/code"}, ``}
	}
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || !strings.Contains(errOut, "answered with a redirect (HTTP 307)") || d.pollCount() != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if strings.Contains(errOut, other.URL) {
		t.Errorf("the redirect target was printed: %s", errOut)
	}
	nothingSaved(t)

	// At the poll, which carries the device code.
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = func(int) devAnswer {
		return devAnswer{302, map[string]string{"Location": other.URL + "/v1/auth/device/token"}, ``}
	}
	code, out, errOut = runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || !strings.Contains(errOut, "redirect (HTTP 302)") || d.pollCount() != 1 {
		t.Fatalf("exit %d after %d polls\n%s\n%s", code, d.pollCount(), out, errOut)
	}
	noSecrets(t, "redirect", out, errOut)
	nothingSaved(t)

	mu.Lock()
	defer mu.Unlock()
	if landed != 0 {
		t.Errorf("the redirect target received %d request(s)", landed)
	}
}

func TestDeviceLoginRefusesPlainHTTPBeforeAnyRequest(t *testing.T) {
	d := newDeviceAPI(t)
	port := strings.TrimPrefix(d.URL, "http://127.0.0.1")
	for _, base := range []string{"http://127.0.0.2" + port, "http://localhost.example.test" + port, "http://foo.localhost" + port, "http://api.example.test"} {
		isolate(t)
		code, out, errOut := runDevice(t, newDevEnv(), "login", "--device", "--api-url", base, "--ref", "my/*")
		if code != 1 || !strings.Contains(errOut, "refusing to sign in over plain http") {
			t.Errorf("%s: exit %d\n%s\n%s", base, code, out, errOut)
		}
		if out != "" {
			t.Errorf("%s: something was printed before the refusal:\n%s", base, out)
		}
		nothingSaved(t)
	}
	// An address derived from the MCP address is held to the same rule, and so is one from the environment.
	isolate(t)
	if code, _, errOut := runDevice(t, newDevEnv(), "login", "--device", "--url", "http://mcp.example.test/mcp", "--ref", "my/*"); code != 1 || !strings.Contains(errOut, "plain http") {
		t.Errorf("derived address: exit %d\n%s", code, errOut)
	}
	isolate(t)
	t.Setenv("AGENTRUNTIME_API_URL", "http://api.example.test")
	if code, _, errOut := runDevice(t, newDevEnv(), "login", "--device", "--ref", "my/*"); code != 1 || !strings.Contains(errOut, "plain http") {
		t.Errorf("environment address: exit %d\n%s", code, errOut)
	}
	if d.hits() != 0 {
		t.Errorf("the server received %d request(s)", d.hits())
	}
	// The exact loopback hosts are fine over http (every other test in this file relies on it).
	isolate(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 {
		t.Errorf("loopback http: exit %d\n%s\n%s", code, out, errOut)
	}
}

// ---- inputs -----------------------------------------------------------------------------------------------------

func TestDeviceLoginRefusesBadInputsBeforeAnyRequest(t *testing.T) {
	long := "workspace/" + strings.Repeat("a", 250)
	var many []string
	for i := 0; i < 101; i++ {
		many = append(many, "--ref", fmt.Sprintf("my/s%d", i))
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"nothing to fetch", []string{}, "say which secrets the key may fetch"},
		{"all and ref", []string{"--all", "--ref", "my/*"}, "--all and --ref cannot be combined"},
		{"unknown scope", []string{"--ref", "my/*", "--scope", "admin"}, "--scope accepts secrets:fetch and vault:read only"},
		{"scope that widens", []string{"--ref", "my/*", "--scope", "vault:read,tenant:admin"}, "--scope accepts"},
		{"ttl under a minute", []string{"--ref", "my/*", "--ttl", "59s"}, "--ttl must be from 1m to 8h"},
		{"ttl over 8h", []string{"--ref", "my/*", "--ttl", "8h1s"}, "--ttl must be from 1m to 8h"},
		{"ttl in days", []string{"--ref", "my/*", "--ttl", "1d"}, "--ttl must be from 1m to 8h"},
		{"ttl zero", []string{"--ref", "my/*", "--ttl", "0"}, "--ttl must be from 1m to 8h"},
		{"ttl negative", []string{"--ref", "my/*", "--ttl", "-5m"}, "--ttl must be from 1m to 8h"},
		{"ttl words", []string{"--ref", "my/*", "--ttl", "soon"}, "--ttl must be from 1m to 8h"},
		{"ttl fraction of a second", []string{"--ref", "my/*", "--ttl", "90500ms"}, "--ttl must be from 1m to 8h"},
		{"short name", []string{"--ref", "live/stripe"}, "--ref #1: start with the room"},
		{"shared room", []string{"--ref", "shared/x"}, "shared secrets cannot be fetched yet"},
		{"star in the middle", []string{"--ref", "workspace/*/x"}, "'*' may only be the whole last part"},
		{"star inside a name", []string{"--ref", "workspace/li*"}, "'*' may only be the whole last part"},
		{"double star", []string{"--ref", "workspace/**"}, "'*' may only be the whole last part"},
		{"empty folder", []string{"--ref", "workspace/live//x"}, "a folder name is empty"},
		{"leading slash", []string{"--ref", "/workspace/x"}, "a folder name is empty"},
		{"trailing slash", []string{"--ref", "workspace/x/"}, "a folder name is empty"},
		{"dot dot", []string{"--ref", "workspace/../x"}, "'.' and '..' are not allowed"},
		{"a field", []string{"--ref", "workspace/live/stripe#KEY"}, "not fields"},
		{"comma", []string{"--ref", "workspace/a,workspace/b"}, "give --ref once for each secret"},
		{"room alone", []string{"--ref", "workspace"}, "name something after the room"},
		{"backslash", []string{"--ref", `my\x`}, "use '/' between folders"},
		{"control character", []string{"--ref", "workspace/a\x01b"}, "control or invisible characters"},
		{"zero width character", []string{"--ref", "workspace/a\u200bb"}, "control or invisible characters"},
		{"line separator", []string{"--ref", "workspace/a\u2028b"}, "control or invisible characters"},
		{"empty ref", []string{"--ref", " "}, "--ref #1: it is empty"},
		{"too long", []string{"--ref", long + "/bbbbbbbbbb"}, "longer than 256 characters"},
		{"second ref bad", []string{"--ref", "my/*", "--ref", "nope"}, "--ref #2: start with the room"},
		{"101 refs", many, "at most 100 different --ref values (got 101)"},
	}
	for _, c := range cases {
		isolate(t)
		d := newDeviceAPI(t)
		args := append([]string{"login", "--device", "--api-url", d.URL}, c.args...)
		code, out, errOut := runDevice(t, newDevEnv(), args...)
		if code != 2 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: exit %d, want 2 and %q\nstdout: %s\nstderr: %s", c.name, code, c.want, out, errOut)
		}
		if d.hits() != 0 || out != "" {
			t.Errorf("%s: %d request(s) made, stdout %q", c.name, d.hits(), out)
		}
		nothingSaved(t)
	}
}

func TestDeviceLoginRefErrorsNeverEchoTheText(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	for _, bad := range []string{"FAKEPASTEDVALUE-abcdef123456", "workspace/FAKEPASTEDVALUE#x", "workspace/FAKEPASTEDVALUE/**", "shared/FAKEPASTEDVALUE", "workspace/FAKEPASTEDVALUE,x"} {
		_, out, errOut := runDevice(t, newDevEnv(), "login", "--device", "--api-url", d.URL, "--ref", bad)
		if strings.Contains(out+errOut, "FAKEPASTEDVALUE") {
			t.Errorf("%q: the error repeats what was typed:\n%s", bad, errOut)
		}
	}
}

func TestDeviceLoginAcceptsTheRefFormsTheServerAccepts(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	args := []string{"login", "--device", "--api-url", d.URL, "--device-name", "n",
		"--ref", "workspace/live/*", "--ref", "workspace/*", "--ref", "my/*", "--ref", "project/ci/deploy", "--ref", "workspace/with space/x",
		"--ref", "secret:workspace/live/stripe", "--ref", "workspace/live/stripe", "--ref", " my/*  ", "--ref", "workspace/a.b/c-d_e"}
	if code, out, errOut := runDevice(t, newDevEnv(), args...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	got := fmt.Sprint(d.starts[0]["refs"])
	// The prefix is removed, a repeat is sent once, and the order is the order given.
	if want := "[workspace/live/* workspace/* my/* project/ci/deploy workspace/with space/x workspace/live/stripe workspace/a.b/c-d_e]"; got != want {
		t.Errorf("refs sent %s\nwant      %s", got, want)
	}

	// A hundred different refs are fine.
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	args = []string{"login", "--device", "--api-url", d.URL}
	for i := 0; i < 100; i++ {
		args = append(args, "--ref", fmt.Sprintf("my/s%d", i))
	}
	if code, out, errOut := runDevice(t, newDevEnv(), args...); code != 0 || len(d.starts[0]["refs"].([]any)) != 100 {
		t.Fatalf("100 refs: exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestDeviceFlagsNeedDeviceAndDeviceTakesNoPastedKey(t *testing.T) {
	for _, flag := range [][]string{{"--ref", "my/*"}, {"--all"}, {"--ttl", "1h"}, {"--scope", "vault:read"}, {"--open"}, {"--device-name", "x"}, {"--api-url", "https://api.example.test"}, {"--replace"}} {
		isolate(t)
		code, _, errOut := run(t, "", append([]string{"login", "--token", testToken, "--no-verify"}, flag...)...)
		if code != 2 || !strings.Contains(errOut, flag[0]+" only works with --device") {
			t.Errorf("%v: exit %d\n%s", flag, code, errOut)
		}
		nothingSaved(t)
	}
	for _, other := range []string{"--token", "--with-token", "--no-verify"} {
		isolate(t)
		args := []string{"login", "--device", "--ref", "my/*", other}
		if other == "--token" {
			args = append(args, testToken)
		}
		code, _, errOut := run(t, "", args...)
		if code != 2 || !strings.Contains(errOut, "--device cannot be combined with --token, --with-token or --no-verify") {
			t.Errorf("%s: exit %d\n%s", other, code, errOut)
		}
		nothingSaved(t)
	}
}

// ---- the profile ---------------------------------------------------------------------------------------------------

func TestDeviceLoginDoesNotReplaceAKeyThatDoesNotExpireUnlessAsked(t *testing.T) {
	forever := func() map[string]*config.Profile {
		return map[string]*config.Profile{"default": {Token: "pat_FAKE-long-lived-1234567890", URL: "https://mcp.example.test/mcp"}}
	}
	// Refused before anything is sent.
	isolate(t)
	writeConfig(t, "default", forever())
	d := newDeviceAPI(t)
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 2 || d.hits() != 0 || out != "" ||
		!strings.Contains(errOut, `profile "default" already holds an access key that does not expire`) || !strings.Contains(errOut, "--profile NAME") || !strings.Contains(errOut, "--replace") {
		t.Fatalf("exit %d hits %d\n%s\n%s", code, d.hits(), out, errOut)
	}
	if savedProfile(t, "default").Token != "pat_FAKE-long-lived-1234567890" {
		t.Error("the key was replaced although it was refused")
	}
	noSecrets(t, "refused", out, errOut)
	if strings.Contains(out+errOut, "pat_FAKE-long") {
		t.Error("the existing key was printed")
	}

	// An unreadable expiry is treated as a key that does not expire.
	isolate(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-long-lived-1234567890", ExpiresAt: "garbage"}})
	if code, _, _ := runDevice(t, newDevEnv(), deviceArgs(newDeviceAPI(t))...); code != 2 {
		t.Errorf("an unreadable stored expiry: exit %d, want 2", code)
	}

	// --replace does it; the URL stays.
	isolate(t)
	writeConfig(t, "default", forever())
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d, "--replace")...); code != 0 {
		t.Fatalf("--replace: exit %d\n%s\n%s", code, out, errOut)
	}
	if p := savedProfile(t, "default"); p.Token != devKey || p.URL != "https://mcp.example.test/mcp" || p.ExpiresAt == "" {
		t.Errorf("profile after --replace: %+v", p)
	}

	// Another profile keeps both.
	isolate(t)
	writeConfig(t, "default", forever())
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d, "--profile", "fetch-only")...); code != 0 {
		t.Fatalf("--profile: exit %d\n%s\n%s", code, out, errOut)
	}
	if savedProfile(t, "default").Token != "pat_FAKE-long-lived-1234567890" || savedProfile(t, "fetch-only").Token != devKey {
		t.Error("a second profile did not keep both keys")
	}

	// A key from an earlier sign-in (it has an expiry, even a past one) is renewed without --replace.
	for _, exp := range []time.Duration{-time.Hour, 30 * time.Minute} {
		isolate(t)
		writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-short-lived-123456", ExpiresAt: clockNow.Add(exp).Format(time.RFC3339)}})
		d = newDeviceAPI(t)
		d.poll = pollScript(goodGrant())
		if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 || savedProfile(t, "default").Token != devKey {
			t.Errorf("renewing a short-lived key (%v): exit %d\n%s\n%s", exp, code, out, errOut)
		}
	}
}

func TestDeviceLoginSetsTheMCPURLOnlyWhenAsked(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 || savedProfile(t, "default").URL != config.DefaultURL {
		t.Fatalf("new profile: exit %d url %q\n%s\n%s", code, savedProfile(t, "default").URL, out, errOut)
	}
	isolate(t)
	d = newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d, "--url", "https://mcp.example.test/mcp")...); code != 0 || savedProfile(t, "default").URL != "https://mcp.example.test/mcp" {
		t.Fatalf("--url: exit %d\n%s\n%s", code, out, errOut)
	} else if !strings.Contains(errOut, "the API address you gave is not saved") {
		t.Errorf("--api-url was given and the person was not told it is not saved:\n%s", errOut)
	}
}

func TestProfileListShowsNoPartOfAShortLivedKey(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	e := newDevEnv()
	if code, out, errOut := runDevice(t, e, deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	writeConfigAdd(t, "pasted", &config.Profile{Token: "pat_FAKE-normal-pat-1234567890"})

	code, out, errOut := runApp(t, false, e.tweak, "profile", "list")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "short-lived key (until ") {
		t.Errorf("a short-lived key is not described:\n%s", out)
	}
	// Not one character of the key: not the old shortened form either.
	for _, frag := range []string{devKey, "pat_FA", "…", "uvw"} {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "short-lived") && strings.Contains(line, frag) {
				t.Errorf("the short-lived key's row shows %q:\n%s", frag, line)
			}
		}
	}
	// A key that does not expire is shown shortened, as before.
	if !strings.Contains(out, "pat_FA…7890") {
		t.Errorf("a normal key is no longer shown shortened:\n%s", out)
	}

	// After it ends.
	e.now = e.now.Add(2 * time.Hour)
	if _, out, _ := runApp(t, false, e.tweak, "profile", "list"); !strings.Contains(out, "short-lived key (expired)") {
		t.Errorf("an ended key is not shown as expired:\n%s", out)
	}

	// JSON: the expiry, never the key.
	code, out, _ = run(t, "", "profile", "list", "--json")
	if code != 0 || strings.Contains(out, devKey) || strings.Contains(out, "pat_FA") || !strings.Contains(out, `"expires_at": "`+clockNow.Add(time.Hour).Format(time.RFC3339)+`"`) {
		t.Errorf("profile list --json:\n%s", out)
	}
}

func writeConfigAdd(t *testing.T, name string, p *config.Profile) {
	t.Helper()
	f, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	f.Profiles[name] = p
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
}

// No other command shows the saved key either.
func TestNoCommandPrintsTheSavedShortLivedKey(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, args := range [][]string{{"profile", "list"}, {"profile", "list", "--json"}, {"profile", "path"}, {"profile", "use", "default"}, {"logout"}, {"version"}} {
		code, out, errOut := run(t, "", args...)
		noSecrets(t, strings.Join(args, " "), out, errOut)
		if code != 0 {
			t.Errorf("%v: exit %d\n%s", args, code, errOut)
		}
	}
	// logout removes the key and its expiry together.
	if p := savedProfile(t, "default"); p.Token != "" || p.ExpiresAt != "" {
		t.Errorf("logout left %+v", p)
	}
}

func TestSavedKeyIsUsedByTheFetchCommandsAndItsExpiryIsRemembered(t *testing.T) {
	// After a device sign-in the key is the profile's key: a 401 once its stored expiry has passed says so.
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	e := newDevEnv()
	if code, out, errOut := runDevice(t, e, deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	api := newVaultAPI(t) // answers 401 for any key but the test key
	e.now = clockNow.Add(2 * time.Hour)
	code, _, errOut := runApp(t, false, e.tweak, "--allow-other-host", "secrets", "check", "--api-url", api.URL, "workspace/live/stripe#API_KEY")
	if code != 1 || !strings.Contains(errOut, "your short-lived key expired; sign in again") {
		t.Errorf("exit %d\n%s", code, errOut)
	}
	if got := api.all(); len(got) != 1 || got[0].Auth != "Bearer "+devKey {
		t.Errorf("the saved key was not the one used: %+v", got)
	}
}

// ---- saving fails -----------------------------------------------------------------------------------------------------

func TestDeviceLoginSaveFailureKeepsTheOldConfigAndNeverPrintsTheKey(t *testing.T) {
	isolate(t)
	writeConfig(t, "other", map[string]*config.Profile{"other": {Token: "pat_FAKE-other-123456789", URL: "https://mcp.example.test/mcp"}})
	before := mustRead(t, configPath())
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	// After the preflight and before the key arrives, the folder becomes unwritable for this file: its temp name is a
	// folder with something in it.
	d.onPoll = func(int) { _ = os.MkdirAll(filepath.Join(configPath()+".tmp", "keep"), 0o700) }
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d, "--profile", "new")...)
	if code != 1 || !strings.Contains(errOut, "the sign-in was approved, but the key could not be saved") ||
		!strings.Contains(errOut, "It cannot be shown again") || !strings.Contains(errOut, "Short-lived access") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	noSecrets(t, "save failure", out, errOut)
	if strings.Contains(out, "signed in") {
		t.Errorf("claimed success:\n%s", out)
	}
	if after := mustRead(t, configPath()); after != before {
		t.Errorf("the old config changed:\n%s", after)
	}
}

func TestDeviceLoginFindsAnUnwritableConfigFolderBeforeAskingAnyone(t *testing.T) {
	isolate(t)
	blocker := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTRUNTIME_CONFIG", filepath.Join(blocker, "sub", "config.json"))
	d := newDeviceAPI(t)
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	// Windows reads a missing path as "no config yet", so the preflight finds the problem; Unix already fails when it
	// reads the config. Either way nothing is sent and nothing is shown.
	want := "cannot write the config folder"
	if runtime.GOOS != "windows" {
		want = "not a directory"
	}
	if code != 1 || !strings.Contains(errOut, want) || d.hits() != 0 || out != "" {
		t.Fatalf("exit %d hits %d\n%s\n%s", code, d.hits(), out, errOut)
	}
	if runtime.GOOS == "windows" && !strings.Contains(errOut, "nothing was started") {
		t.Errorf("the preflight did not say it started nothing:\n%s", errOut)
	}
}

// ---- the browser ----------------------------------------------------------------------------------------------------

func TestDeviceLoginOpensABrowserOnlyWithOpenAndOnlyForAnHTTPSAddressOnTheAPIsDomain(t *testing.T) {
	// The fake API is at 127.0.0.1, so the sign-in address must be https on 127.0.0.1 to be on its domain.
	inFamily := func(d *deviceAPI) devAnswer {
		host := strings.TrimPrefix(d.URL, "http://")
		return ok(codeBody("https://"+host+"/device", "https://"+host+"/device?code="+devUser, 600, 5))
	}
	cases := []struct {
		name     string
		args     []string
		answer   func(d *deviceAPI) devAnswer
		openErr  error
		wantOpen int // how many times the opener runs
		wantNote string
	}{
		{"no --open", nil, inFamily, nil, 0, ""},
		{"--open, https on the API's host", []string{"--open"}, inFamily, nil, 1, ""},
		{"--open, another domain", []string{"--open"}, func(*deviceAPI) devAnswer { return goodCode() }, nil, 0, "not opening a browser: the address is not a plain https address on the API's own domain"},
		{"--open, plain http on the API's host", []string{"--open"}, func(d *deviceAPI) devAnswer {
			host := strings.TrimPrefix(d.URL, "http://")
			return ok(codeBody("http://"+host+"/device", "http://"+host+"/device?code="+devUser, 600, 5))
		}, nil, 0, "not opening a browser"},
		{"--open, the opener fails", []string{"--open"}, inFamily, fmt.Errorf("no browser"), 1, "could not open a browser. Open the address yourself."},
	}
	for _, c := range cases {
		isolate(t)
		d := newDeviceAPI(t)
		d.start = func(int) devAnswer { return c.answer(d) }
		d.poll = pollScript(goodGrant())
		e := newDevEnv()
		e.openErr = c.openErr
		code, out, errOut := runDevice(t, e, deviceArgs(d, c.args...)...)
		errOut = strings.ReplaceAll(errOut, notSavedNote, "")
		if code != 0 {
			t.Errorf("%s: exit %d\n%s\n%s", c.name, code, out, errOut)
			continue
		}
		if len(e.opened) != c.wantOpen {
			t.Errorf("%s: the browser was opened %d time(s), want %d: %v", c.name, len(e.opened), c.wantOpen, e.opened)
		}
		if c.wantOpen > 0 && !strings.HasSuffix(e.opened[0], "/device?code="+devUser) {
			t.Errorf("%s: opened %q, want the address with the code in it", c.name, e.opened[0])
		}
		if c.wantNote != "" && !strings.Contains(errOut, c.wantNote) {
			t.Errorf("%s: no note %q in\n%s", c.name, c.wantNote, errOut)
		}
		if c.wantNote == "" && errOut != "" {
			t.Errorf("%s: unexpected stderr %q", c.name, errOut)
		}
		// The sign-in goes on either way, and the address is always on the screen.
		if !strings.Contains(out, "code: "+devUser) || savedProfile(t, "default").Token != devKey {
			t.Errorf("%s: the sign-in did not complete or the code was not shown:\n%s", c.name, out)
		}
	}
}

func TestDeviceLoginNotesAnAddressOutsideTheAPIsDomain(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t) // answers console.example.test; the API is at 127.0.0.1
	d.poll = pollScript(goodGrant())
	code, out, _ := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 0 || !strings.Contains(out, "note: this address is not on the same domain as the API (127.0.0.1). Check it is the Console you expect before you sign in there.") {
		t.Errorf("exit %d\n%s", code, out)
	}
	// On the API's own host there is no such note.
	isolate(t)
	d = newDeviceAPI(t)
	host := strings.TrimPrefix(d.URL, "http://")
	d.start = func(int) devAnswer { return ok(codeBody("http://"+host+"/device", "", 600, 5)) }
	d.poll = pollScript(goodGrant())
	if _, out, _ := runDevice(t, newDevEnv(), deviceArgs(d)...); strings.Contains(out, "not on the same domain") {
		t.Errorf("a note for the API's own host:\n%s", out)
	}
}

func TestAPIFamily(t *testing.T) {
	cases := []struct {
		api, host string
		want      bool
	}{
		{"api.agentruntime.io", "console.agentruntime.io", true},
		{"api.agentruntime.io", "agentruntime.io", true},
		{"api.agentruntime.io", "api.agentruntime.io", true},
		{"API.AgentRuntime.IO", "Console.AgentRuntime.io", true},
		{"api.agentruntime.io", "a.b.agentruntime.io", true},
		{"api.agentruntime.io", "evilagentruntime.io", false},
		{"api.agentruntime.io", "agentruntime.io.evil.test", false},
		{"api.agentruntime.io", "agentruntime.io.", false},
		{"api.agentruntime.io", "io", false},
		{"api.agentruntime.io", "example.test", false},
		{"api.staging.example.com", "console.staging.example.com", true},
		{"api.staging.example.com", "console.example.com", false},
		{"agentruntime.example.com", "console.agentruntime.example.com", true},
		{"agentruntime.example.com", "example.com", false},
		{"api.localhost", "console.localhost", false}, // "localhost" alone is not a domain to trust
		{"localhost", "localhost", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1", "127.0.0.2", false},
		{"127.0.0.1", "evil.127.0.0.1", false},
		{"::1", "::1", true},
	}
	for _, c := range cases {
		if got := inAPIFamily(c.api, c.host); got != c.want {
			t.Errorf("inAPIFamily(%q, %q) = %v, want %v", c.api, c.host, got, c.want)
		}
	}
}

func TestMayOpenAndTheOpenerRefuseAnythingButHTTPS(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://console.agentruntime.io/device?code=BCDF-2345": true,
		"https://agentruntime.io/device":                        true,
		"http://console.agentruntime.io/device":                 false,
		"https://console.example.test/device":                   false,
		"https://evilagentruntime.io/device":                    false,
	} {
		u, err := parseVerificationURL(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := mayOpen("api.agentruntime.io", u); got != want {
			t.Errorf("mayOpen(%s) = %v, want %v", raw, got, want)
		}
	}
	if mayOpen("api.agentruntime.io", nil) {
		t.Error("mayOpen(nil)")
	}
	// The opener re-checks, so no caller can hand it a path, an option or a script. These return before anything
	// starts, and nothing is started here whatever the check says: the launcher is replaced by a recorder.
	launched := recordLaunches(t)
	for _, bad := range []string{"", "file:///etc/passwd", "http://console.agentruntime.io/d", "javascript:alert(1)", "-https://x", "ftp://x", "https://x/a b", "https://x/\n--help", "https://x/\x1b", "/usr/bin/true", "calc.exe", "https://x/é"} {
		if err := openInBrowser(bad); err == nil {
			t.Errorf("openInBrowser(%q) accepted it", bad)
		}
	}
	if len(*launched) != 0 {
		t.Errorf("an opener was started for a bad address: %v", *launched)
	}
}

func TestVerificationURLRules(t *testing.T) {
	for _, ok := range []string{"https://console.example.test/device", "http://localhost:5173/device?code=AB-12", "https://c.example.test/d?code=BCDF-2345&x=%20y"} {
		if _, err := parseVerificationURL(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "console.example.test/device", "//c.example.test/d", "javascript:alert(1)", "data:text/html,x", "mailto:a@b.test", "https://u:p@c.example.test/", "https://@c.example.test/", "https:///x", "https://c.example.test/a b", "https://c.example.test/\t", "https://c\u00e9.example.test/", "https://c.example.test/\u202e"} {
		if _, err := parseVerificationURL(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// ---- output hygiene, help and README -----------------------------------------------------------------------------------

func TestDeviceLoginWithJSONFlagStillPrintsNoKey(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d, "--json")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	noSecrets(t, "--json", out, errOut)
}

func TestLoginHelpAndReadmeDescribeTheDeviceSignIn(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "login", "--help")
	help = flat(help)
	text := flat(readme(t))
	for _, want := range []string{
		"--device", "--ref", "--ttl", "--scope", "--open", "--device-name", "--all", "--replace", "1 minute to 8 hours",
		"never prints the key", "never opens a browser unless you pass --open", "only an https address on the API's own domain",
		"Approve a code only if you started it from your own terminal just now", "Ctrl-C cancels, and nothing is saved",
		"short-lived access key", "Short-lived access", "refuses when the profile holds a key that does not expire",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("login --help lacks %q", want)
		}
	}
	for _, want := range []string{
		"## Sign in with a code", "agentruntime login --device", "fetch only", "`expires_at`", "never prints the key", "`--open`",
		"Approve a code only if you started it from your own terminal just now", "`--replace`", "`--all`", "`slow_down`", "exactly once",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
}

// A host with an empty label is never in the API's family, whatever the suffix test would say about it.
func TestAPIFamilyRefusesAnEmptyLabel(t *testing.T) {
	for _, c := range []struct{ api, host string }{
		{"api.agentruntime.io", ".agentruntime.io"}, {"api.agentruntime.io", "a..agentruntime.io"}, {"api.agentruntime.io", "..agentruntime.io"},
		{"api.agentruntime.io", "console..agentruntime.io"}, {".agentruntime.io", "console.agentruntime.io"}, {"api..agentruntime.io", "api..agentruntime.io"},
		{".agentruntime.io", ".agentruntime.io"},
	} {
		if inAPIFamily(c.api, c.host) {
			t.Errorf("inAPIFamily(%q, %q) = true", c.api, c.host)
		}
	}
}
