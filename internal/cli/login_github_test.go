package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

// Every token, key and id below is fake.
const (
	ghJWT      = "eyJhbGciOiJSUzI1NiJ9.eyJGQUtFLWNhbmFyeSI6IkNBTkFSWS1PSURDLUpXVCJ9.FAKE-signature_0123456789"
	ghJWTMid   = "eyJGQUtFLWNhbmFyeSI6IkNBTkFSWS1PSURDLUpXVCJ9"
	ghReqToken = "FAKE-request_token-CANARY-0123456789abcdef"
	ghKey      = "pat_FAKE-workload_key-0123456789abcdefghijklmnopqrstu"
	ghTrust    = "11111111-2222-4333-8444-555555555555"
	ghSrvText  = "SERVER-TEXT-CANARY-do-not-print"
	ghDefAud   = "https://api.agentruntime.io/workload"
)

// ---- the two fake servers ------------------------------------------------------------------------------------------

type ghAnswer struct {
	status int
	header map[string]string
	body   string
}

func ghOK(body string) ghAnswer { return ghAnswer{200, nil, body} }

// fakeGitHub stands in for the identity-token endpoint of GitHub Actions.
type fakeGitHub struct {
	*httptest.Server
	mu    sync.Mutex
	calls []*http.Request
	reply func(n int) ghAnswer
	block <-chan struct{} // when set, a request waits for it (or for its own context)
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{reply: func(int) ghAnswer { return ghOK(`{"count":1,"value":"` + ghJWT + `"}`) }}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.calls = append(g.calls, r.Clone(context.Background()))
		n := len(g.calls)
		ans := g.reply(n)
		block := g.block
		g.mu.Unlock()
		if block != nil {
			select {
			case <-block:
			case <-r.Context().Done():
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
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGitHub) hits() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

// workloadAPI stands in for the public exchange route.
type workloadAPI struct {
	*httptest.Server
	mu      sync.Mutex
	headers []http.Header
	paths   []string
	raw     []string
	bodies  []map[string]any
	answer  func(n int) ghAnswer
	onCall  func(n int) // runs before the answer of call n is sent
}

func exchangeBody(scopes string) string {
	return `{"token":"` + ghKey + `","expires_at":"` + clockNow.Add(15*time.Minute).Format(time.RFC3339) +
		`","scopes":` + scopes + `,"trust":"` + ghTrust + `"}`
}

func newWorkloadAPI(t *testing.T) *workloadAPI {
	t.Helper()
	w := &workloadAPI{answer: func(int) ghAnswer { return ghOK(exchangeBody(`["secrets:fetch"]`)) }}
	w.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.headers = append(w.headers, r.Header.Clone())
		w.paths = append(w.paths, r.Method+" "+r.URL.Path)
		w.raw = append(w.raw, string(raw))
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		w.bodies = append(w.bodies, body)
		n := len(w.paths)
		hook := w.onCall
		w.mu.Unlock()
		if hook != nil {
			hook(n)
		}
		w.mu.Lock()
		ans := w.answer(n)
		w.mu.Unlock()
		for k, v := range ans.header {
			rw.Header().Set(k, v)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(ans.status)
		_, _ = rw.Write([]byte(ans.body))
	}))
	t.Cleanup(w.Close)
	return w
}

func (w *workloadAPI) hits() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.paths)
}

// ghEnv is one test's world: a fake GitHub, a fake API, and the environment of a job that has id-token: write.
type ghEnv struct {
	gh  *fakeGitHub
	api *workloadAPI
}

func newGHEnv(t *testing.T) *ghEnv {
	t.Helper()
	isolate(t)
	e := &ghEnv{gh: newFakeGitHub(t), api: newWorkloadAPI(t)}
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", e.gh.URL+"/_apis/idtoken?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", ghReqToken)
	t.Setenv("GITHUB_ENV", "")
	t.Setenv("AGENTRUNTIME_WORKLOAD_AUDIENCE", "")
	// No test can reach a real host: whatever a (mutated) command does without --api-url goes to the fake API.
	t.Setenv("AGENTRUNTIME_API_URL", e.api.URL)
	return e
}

// args is `login --github-actions` against the fake API.
func (e *ghEnv) args(extra ...string) []string {
	return append([]string{"login", "--github-actions", "--trust", ghTrust, "--api-url", e.api.URL}, extra...)
}

func (e *ghEnv) hits() int { return e.gh.hits() + e.api.hits() }

// apiHostLine is the line the command prints on standard error before it asks GitHub for anything.
func (e *ghEnv) apiHostLine() string {
	return "API host: " + strings.TrimPrefix(e.api.URL, "http://") + "\n"
}

func fixedClock(a *App) { a.now = func() time.Time { return clockNow } }

func runGH(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return runApp(t, false, fixedClock, args...)
}

// useEnvFile makes GITHUB_ENV name a file with the given content, as the runner does for each step.
func useEnvFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "set_env_0001")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_ENV", p)
	return p
}

// noGHSecrets fails when an output holds the identity token, the request token or a server's free text, or the key.
// With allowMask, the one line "::add-mask::<key>" is allowed in the output given first (standard output); the key
// may not appear anywhere else.
func noGHSecrets(t *testing.T, what string, allowMask bool, stdout, stderr string) {
	t.Helper()
	if allowMask {
		stdout = strings.Replace(stdout, "::add-mask::"+ghKey+"\n", "", 1)
	}
	for _, o := range []string{stdout, stderr} {
		for _, s := range []string{ghJWT, ghJWTMid, ghReqToken, ghSrvText, ghKey, strings.TrimPrefix(ghKey, "pat_")} {
			if strings.Contains(o, s) {
				t.Errorf("%s: a secret (%.10s…) appears in the output:\n%s", what, s, o)
			}
		}
	}
}

// ---- the whole flow --------------------------------------------------------------------------------------------------

func TestGitHubActionsLoginSavesTheKeyWithItsExpiry(t *testing.T) {
	e := newGHEnv(t)
	code, out, errOut := runGH(t, e.args()...)
	if code != 0 || errOut != e.apiHostLine()+notSavedNote {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	for _, want := range []string{"signed in for this job until ", "(in 15 minutes); fetch only", "Scopes: secrets:fetch", `Saved to profile "default" in ` + configPath()} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !regexp.MustCompile(`signed in for this job until \d{4}-\d\d-\d\d \d\d:\d\d \S+ \(in 15 minutes\); fetch only`).MatchString(out) {
		t.Errorf("the sign-in line is not in the expected form:\n%s", out)
	}
	noGHSecrets(t, "login --github-actions", false, out, errOut)

	p := savedProfile(t, "default")
	if p == nil || p.Token != ghKey || p.ExpiresAt != clockNow.Add(15*time.Minute).Format(time.RFC3339) {
		t.Fatalf("profile %+v", p)
	}
	f, _ := config.Load()
	if f.Current != "" {
		t.Errorf("the sign-in changed the current profile to %q; it must leave it alone", f.Current)
	}
	if r := f.Resolve(config.Overrides{}); r.Token != ghKey || !r.TokenExpiresAt.Equal(clockNow.Add(15*time.Minute)) {
		t.Errorf("the saved key does not resolve with its expiry: %+v", r)
	}
	// The expiry is stored under the field name the rest of the CLI reads.
	if raw := mustRead(t, configPath()); !strings.Contains(raw, `"expires_at": "`+clockNow.Add(15*time.Minute).Format(time.RFC3339)+`"`) {
		t.Errorf("the config file has no expires_at:\n%s", raw)
	}
	if e.gh.hits() != 1 || e.api.hits() != 1 {
		t.Errorf("GitHub %d requests, API %d: want one each", e.gh.hits(), e.api.hits())
	}
}

func TestGitHubActionsLoginAsksGitHubAndTheAPIAsTheyExpect(t *testing.T) {
	e := newGHEnv(t)
	// Keys the process holds must not reach either server.
	t.Setenv("AGENTRUNTIME_PAT", "pat_FAKE-environment-key-0123456789")
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-old-signed-in-key", ExpiresAt: clockNow.Add(-time.Hour).Format(time.RFC3339)}})
	code, out, errOut := runGH(t, e.args("--pat", "pat_FAKE-flag-key-0123456789")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}

	g := e.gh.calls[0]
	if g.Method != http.MethodGet || g.URL.Path != "/_apis/idtoken" {
		t.Errorf("GitHub got %s %s", g.Method, g.URL.Path)
	}
	if got := g.Header.Get("Authorization"); got != "Bearer "+ghReqToken {
		t.Errorf("GitHub got Authorization %q", got)
	}
	if got := g.Header.Get("Accept"); got != "application/json; api-version=2.0" {
		t.Errorf("GitHub got Accept %q", got)
	}
	q := g.URL.Query()
	if len(q) != 2 || q.Get("api-version") != "2.0" || q.Get("audience") != ghDefAud {
		t.Errorf("GitHub got the query %v", q)
	}

	if e.api.paths[0] != "POST /v1/auth/workload/exchange" {
		t.Errorf("API got %s", e.api.paths[0])
	}
	b := e.api.bodies[0]
	if len(b) != 3 || b["provider"] != "github" || b["trust"] != ghTrust || b["token"] != ghJWT {
		t.Errorf("API body %v: want exactly provider, trust and the identity token", b)
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Vault-Token"} {
		if v := e.api.headers[0].Get(h); v != "" {
			t.Errorf("the exchange carries %s: %q", h, v)
		}
	}
	// The request token goes to GitHub and nowhere else; the identity token to the API and nowhere else.
	if strings.Contains(e.api.raw[0], ghReqToken) || strings.Contains(fmt.Sprint(e.api.headers[0]), ghReqToken) {
		t.Error("the request token reached the API")
	}
	for _, c := range e.gh.calls {
		if strings.Contains(c.URL.String(), ghJWT) {
			t.Error("the identity token reached GitHub")
		}
	}
	noGHSecrets(t, "login", false, out, errOut)
}

func TestGitHubActionsLoginUsesTheAPIAddressFromTheEnvironment(t *testing.T) {
	e := newGHEnv(t) // AGENTRUNTIME_API_URL names the fake API
	code, out, errOut := runGH(t, "login", "--github-actions", "--trust", ghTrust)
	if code != 0 || errOut != e.apiHostLine() || e.api.hits() != 1 {
		t.Fatalf("exit %d, %d API requests\nstdout: %s\nstderr: %s", code, e.api.hits(), out, errOut)
	}
	if p := savedProfile(t, "default"); p == nil || p.Token != ghKey {
		t.Errorf("profile %+v", p)
	}
}

func TestGitHubActionsLoginAudience(t *testing.T) {
	audienceSeen := func(e *ghEnv) []string { return e.gh.calls[0].URL.Query()["audience"] }
	t.Run("the default", func(t *testing.T) {
		e := newGHEnv(t)
		if code, out, errOut := runGH(t, e.args()...); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
		}
		if got := audienceSeen(e); len(got) != 1 || got[0] != ghDefAud {
			t.Errorf("audience %q", got)
		}
	})
	t.Run("the flag", func(t *testing.T) {
		e := newGHEnv(t)
		if code, out, errOut := runGH(t, e.args("--audience", "https://api.example.test/workload")...); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
		}
		if got := audienceSeen(e); len(got) != 1 || got[0] != "https://api.example.test/workload" {
			t.Errorf("audience %q", got)
		}
	})
	t.Run("the environment", func(t *testing.T) {
		e := newGHEnv(t)
		t.Setenv("AGENTRUNTIME_WORKLOAD_AUDIENCE", "https://env.example.test/workload")
		if code, out, errOut := runGH(t, e.args()...); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
		}
		if got := audienceSeen(e); len(got) != 1 || got[0] != "https://env.example.test/workload" {
			t.Errorf("audience %q", got)
		}
	})
	t.Run("the flag beats the environment", func(t *testing.T) {
		e := newGHEnv(t)
		t.Setenv("AGENTRUNTIME_WORKLOAD_AUDIENCE", "https://env.example.test/workload")
		if code, out, errOut := runGH(t, e.args("--audience", "https://flag.example.test/workload")...); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
		}
		if got := audienceSeen(e); len(got) != 1 || got[0] != "https://flag.example.test/workload" {
			t.Errorf("audience %q", got)
		}
	})
	t.Run("it is one query parameter whatever it holds", func(t *testing.T) {
		e := newGHEnv(t)
		aud := "https://x.example.test/w?a=b&audience=other&api-version=9#frag%20x"
		if code, out, errOut := runGH(t, e.args("--audience", aud)...); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
		}
		q := e.gh.calls[0].URL.Query()
		if got := q["audience"]; len(got) != 1 || got[0] != aud || len(q) != 2 || q.Get("api-version") != "2.0" {
			t.Errorf("query %v", q)
		}
	})
	t.Run("a bad audience is a usage error and sends nothing", func(t *testing.T) {
		for _, bad := range []string{"", " ", "a b", "a\tb", "a\nb", "caf\u00e9", strings.Repeat("a", 257)} {
			e := newGHEnv(t)
			code, out, errOut := runGH(t, e.args("--audience", bad)...)
			if code != 2 || e.hits() != 0 || out != "" || !strings.Contains(errOut, "--audience") {
				t.Errorf("--audience %q: exit %d hits %d\n%s\n%s", bad, code, e.hits(), out, errOut)
			}
			if bad != "" && strings.TrimSpace(bad) != "" && strings.Contains(errOut, bad) {
				t.Errorf("--audience %q: the error repeats it:\n%s", bad, errOut)
			}
		}
		e := newGHEnv(t)
		t.Setenv("AGENTRUNTIME_WORKLOAD_AUDIENCE", "a b")
		code, _, errOut := runGH(t, e.args()...)
		if code != 2 || e.hits() != 0 || !strings.Contains(errOut, "AGENTRUNTIME_WORKLOAD_AUDIENCE") {
			t.Errorf("a bad audience in the environment: exit %d hits %d\n%s", code, e.hits(), errOut)
		}
	})
}

// ---- --export-env ------------------------------------------------------------------------------------------------------

func TestGitHubActionsExportEnvAppendsTheKeyAndMasksItFirst(t *testing.T) {
	cases := []struct {
		name    string
		content string // what GITHUB_ENV holds before; "<none>" for a file that does not exist yet
		want    string
	}{
		{"an empty file", "", "AGENTRUNTIME_PAT=" + ghKey + "\n"},
		{"a file with lines", "FOO=bar\nBAZ=1\n", "FOO=bar\nBAZ=1\nAGENTRUNTIME_PAT=" + ghKey + "\n"},
		{"a last line without its newline", "FOO=bar", "FOO=bar\nAGENTRUNTIME_PAT=" + ghKey + "\n"},
		{"a file that does not exist yet", "<none>", "AGENTRUNTIME_PAT=" + ghKey + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGHEnv(t)
			path := filepath.Join(t.TempDir(), "set_env_0001")
			if tc.content != "<none>" {
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("GITHUB_ENV", path)
			code, out, errOut := runGH(t, e.args("--export-env")...)
			if code != 0 || errOut != e.apiHostLine()+notSavedNote {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
			}
			if got := mustRead(t, path); got != tc.want {
				t.Errorf("GITHUB_ENV holds %q, want %q", got, tc.want)
			}
			// The mask is the first thing printed, and the only line that holds the key.
			if !strings.HasPrefix(out, "::add-mask::"+ghKey+"\n") {
				t.Errorf("the first output is not the mask line:\n%s", out)
			}
			if strings.Count(out, ghKey) != 1 {
				t.Errorf("the key appears %d times in the output:\n%s", strings.Count(out, ghKey), out)
			}
			for _, want := range []string{"AGENTRUNTIME_PAT is set for the next steps of this job until ", "(in 15 minutes); fetch only", "Scopes: secrets:fetch", "The current step does not see it"} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			noGHSecrets(t, "--export-env", true, out, errOut)
			if exists(configPath()) {
				t.Errorf("--export-env wrote the config:\n%s", mustRead(t, configPath()))
			}
		})
	}
}

// orderWriter is standard output that looks at the GITHUB_ENV file at the moment the mask line arrives.
type orderWriter struct {
	buf        bytes.Buffer
	envFile    string
	sawMask    bool
	fileAtMask string
	lineNo     int
}

func (w *orderWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("::add-mask::")) && !w.sawMask {
		w.sawMask = true
		w.lineNo = bytes.Count(w.buf.Bytes(), []byte("\n"))
		b, _ := os.ReadFile(w.envFile)
		w.fileAtMask = string(b)
	}
	return w.buf.Write(p)
}

func TestGitHubActionsExportEnvMasksTheKeyBeforeTheFileHoldsIt(t *testing.T) {
	e := newGHEnv(t)
	path := useEnvFile(t, "FOO=bar\n")
	ow := &orderWriter{envFile: path}
	var errb bytes.Buffer
	app := NewApp(strings.NewReader(""), ow, &errb)
	app.isTTYOut = func() bool { return false }
	fixedClock(app)
	if code := app.Run(append([]string{"--no-color"}, e.args("--export-env")...)); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, ow.buf.String(), errb.String())
	}
	if !ow.sawMask {
		t.Fatal("no mask line was printed")
	}
	if strings.Contains(ow.fileAtMask, ghKey) {
		t.Errorf("the key was in GITHUB_ENV before the mask line was printed:\n%s", ow.fileAtMask)
	}
	if ow.lineNo != 0 {
		t.Errorf("%d lines were printed before the mask line", ow.lineNo)
	}
	if !strings.Contains(mustRead(t, path), "AGENTRUNTIME_PAT="+ghKey+"\n") {
		t.Error("the key is not in GITHUB_ENV")
	}
}

func TestGitHubActionsExportEnvLeavesTheProfileAlone(t *testing.T) {
	e := newGHEnv(t)
	// A key that does not expire in the profile: --export-env does not touch the profile, so it is not in the way.
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-long-lived-1234567890", URL: "https://mcp.example.test/mcp"}})
	before := mustRead(t, configPath())
	path := useEnvFile(t, "")
	code, out, errOut := runGH(t, e.args("--export-env")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if after := mustRead(t, configPath()); after != before {
		t.Errorf("the config changed:\n%s", after)
	}
	if !strings.Contains(mustRead(t, path), ghKey) {
		t.Error("the key is not in GITHUB_ENV")
	}
}

func TestGitHubActionsExportEnvRefusalsHappenBeforeAnythingIsRequested(t *testing.T) {
	notAFile := func(t *testing.T) string { return t.TempDir() } // a folder
	cases := []struct {
		name string
		set  func(t *testing.T) string // the value of GITHUB_ENV
		want string
	}{
		{"GITHUB_ENV unset", func(*testing.T) string { return "" }, "GITHUB_ENV is not set"},
		{"GITHUB_ENV blank", func(*testing.T) string { return "   " }, "GITHUB_ENV is not set"},
		{"a folder", notAFile, "does not name a regular file"},
		{"a folder that does not exist", func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope", "set_env") }, "folder of the file named by GITHUB_ENV does not exist"},
		{"a link", func(t *testing.T) string {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("cannot make a symbolic link here: %v", err)
			}
			return link
		}, "does not name a regular file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGHEnv(t)
			t.Setenv("GITHUB_ENV", tc.set(t))
			code, out, errOut := runGH(t, e.args("--export-env")...)
			if code != 1 || e.hits() != 0 || out != "" {
				t.Fatalf("exit %d, %d requests, stdout %q\n%s", code, e.hits(), out, errOut)
			}
			if !strings.Contains(errOut, tc.want) || !strings.Contains(errOut, "Nothing was requested") {
				t.Errorf("stderr lacks %q:\n%s", tc.want, errOut)
			}
			noGHSecrets(t, tc.name, false, out, errOut)
		})
	}
}

// The file is opened, then checked as opened: in between, or just before, something else may take its place. What
// is written must be the file the path names, a link is never followed, and a file that did not exist is created only
// if nothing appeared at its path.
func TestGitHubActionsExportEnvWritesOnlyToTheFileThatWasChecked(t *testing.T) {
	t.Cleanup(func() { envRaceHook = nil })
	t.Run("a link swapped in just before the open", func(t *testing.T) {
		e := newGHEnv(t)
		path := useEnvFile(t, "FOO=bar\n")
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var skip string
		envRaceHook = func(stage string) {
			if stage != "before-open" {
				return
			}
			_ = os.Remove(path)
			if err := os.Symlink(victim, path); err != nil {
				skip = "cannot make a symbolic link here: " + err.Error()
			}
		}
		code, out, errOut := runGH(t, e.args("--export-env")...)
		if skip != "" {
			t.Skip(skip)
		}
		if got := mustRead(t, victim); got != "untouched\n" {
			t.Errorf("the key was written through the link: %q", got)
		}
		if code != 1 || !strings.Contains(errOut, "the key could not be written") {
			t.Errorf("exit %d\n%s\n%s", code, out, errOut)
		}
		noGHSecrets(t, "link before the open", true, out, errOut)
	})
	t.Run("another file put in its place just after the open", func(t *testing.T) {
		e := newGHEnv(t)
		path := useEnvFile(t, "FOO=bar\n")
		var skip string
		envRaceHook = func(stage string) {
			if stage != "after-open" {
				return
			}
			if err := os.Rename(path, path+".moved"); err != nil {
				skip = "cannot move an open file here: " + err.Error()
				return
			}
			_ = os.WriteFile(path, []byte("OTHER=file\n"), 0o600)
		}
		code, out, errOut := runGH(t, e.args("--export-env")...)
		if skip != "" {
			t.Skip(skip)
		}
		if code != 1 || !strings.Contains(errOut, "the key could not be written") {
			t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
		}
		for _, p := range []string{path, path + ".moved"} {
			if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), ghKey) {
				t.Errorf("the key was written to %s", filepath.Base(p))
			}
		}
		noGHSecrets(t, "swapped file", true, out, errOut)
	})
	t.Run("a link appears where the file was to be created", func(t *testing.T) {
		e := newGHEnv(t)
		dir := t.TempDir()
		path := filepath.Join(dir, "set_env_0001")
		victim := filepath.Join(dir, "victim") // does not exist: a followed link would create it
		t.Setenv("GITHUB_ENV", path)
		var skip string
		envRaceHook = func(stage string) {
			if stage != "before-open" {
				return
			}
			if err := os.Symlink(victim, path); err != nil {
				skip = "cannot make a symbolic link here: " + err.Error()
			}
		}
		code, out, errOut := runGH(t, e.args("--export-env")...)
		if skip != "" {
			t.Skip(skip)
		}
		if exists(victim) {
			t.Errorf("the link was followed: %s was created", filepath.Base(victim))
		}
		if code != 1 {
			t.Errorf("exit %d\n%s\n%s", code, out, errOut)
		}
		noGHSecrets(t, "link at the new file", true, out, errOut)
	})
}

func TestGitHubActionsExportEnvWhenTheFileCannotBeWrittenAfterTheKeyWasMade(t *testing.T) {
	e := newGHEnv(t)
	path := useEnvFile(t, "FOO=bar\n")
	// After the checks and before the key arrives, the file is replaced by a folder.
	e.api.onCall = func(int) { _ = os.Remove(path); _ = os.Mkdir(path, 0o700) }
	code, out, errOut := runGH(t, e.args("--export-env")...)
	if code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{"the sign-in worked, but the key could not be written to the file named by GITHUB_ENV", "It cannot be shown again", "stops working by itself at", "Short-lived access"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	if strings.Contains(out, "AGENTRUNTIME_PAT is set") {
		t.Errorf("claimed success:\n%s", out)
	}
	noGHSecrets(t, "write failure", true, out, errOut)
}

// ---- the job's environment -------------------------------------------------------------------------------------------

func TestGitHubActionsLoginNeedsThePermissionToAskForAnIdentityToken(t *testing.T) {
	cases := []struct {
		name        string
		url, token  string
		wantMissing string
	}{
		{"both missing", "", "", "ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN"},
		{"the address missing", "", ghReqToken, "Not set: ACTIONS_ID_TOKEN_REQUEST_URL"},
		{"the request token missing", "SET", "", "Not set: ACTIONS_ID_TOKEN_REQUEST_TOKEN"},
		{"both blank", "  ", "  ", "ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGHEnv(t)
			u := tc.url
			if u == "SET" {
				u = e.gh.URL + "/x"
			}
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", u)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", tc.token)
			code, out, errOut := runGH(t, e.args()...)
			if code != 1 || e.hits() != 0 || out != "" {
				t.Fatalf("exit %d, %d requests\n%s\n%s", code, e.hits(), out, errOut)
			}
			for _, want := range []string{"the job needs permissions: id-token: write", tc.wantMissing} {
				if !strings.Contains(errOut, want) {
					t.Errorf("stderr lacks %q:\n%s", want, errOut)
				}
			}
			noGHSecrets(t, tc.name, false, out, errOut)
			nothingSaved(t)
		})
	}
}

func TestGitHubActionsLoginRefusesAnAddressThatIsNotGitHubsAndSendsNothing(t *testing.T) {
	bad := []string{
		"http://github.com/x", "http://pipelines.actions.githubusercontent.com/x", "https://evil.example.test/idtoken?api-version=2.0",
		"https://github.com.evil.example.test/x", "https://evilgithub.com/x", "https://notactions.githubusercontent.com/x",
		"https://actions.githubusercontent.com.evil.example.test/x", "https://user:pw@github.com/x", "https://github.com@evil.example.test/x",
		"https://github.com:8443/x", "https://github.com./x", "https://github.com/x#frag", "ftp://github.com/x", "github.com/x", "/x", "not a url",
		"http://127.0.0.2:9/x", "http://localhost.evil.example.test/x", "https://api.github.com/x",
		"https://G\u0130THUB.COM/x", "https://github.com/x\ny",
		// percent-encoded lookalikes: url.Parse decodes them, and a Unicode case mapping would turn them into plain letters
		"https://g%C4%B0thub.com/x", "https://actions.g%C4%B0thubusercontent.com/x", "https://action%C5%BF.githubusercontent.com/x",
		"https://github%E2%84%AA.com/x", "https://%EF%BD%87ithub.com/x", "https://g%25C4%25B0thub.com/x", "https://%67ithub.com/x",
	}
	for _, u := range bad {
		e := newGHEnv(t)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", u)
		code, out, errOut := runGH(t, e.args()...)
		if code != 1 || e.hits() != 0 || out != "" {
			t.Errorf("%q: exit %d, %d requests, stdout %q\n%s", u, code, e.hits(), out, errOut)
			continue
		}
		if !strings.Contains(errOut, "will send the job's request token to") || !strings.Contains(errOut, "Nothing was sent") {
			t.Errorf("%q: stderr:\n%s", u, errOut)
		}
		// Nothing of the address, and no part of the request token, is repeated.
		if (strings.TrimSpace(u) != "" && len(u) > 4 && strings.Contains(errOut, u)) || strings.Contains(errOut, ghReqToken) {
			t.Errorf("%q: the error repeats the address or the token:\n%s", u, errOut)
		}
		nothingSaved(t)
	}
}

func TestGitHubActionsLoginRefusesARequestTokenThatIsNotPlainText(t *testing.T) {
	for _, tok := range []string{"a b", "a\nb", "caf\u00e9", strings.Repeat("a", 9000)} {
		e := newGHEnv(t)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", tok)
		code, out, errOut := runGH(t, e.args()...)
		if code != 1 || e.hits() != 0 || out != "" || !strings.Contains(errOut, "request token is not in a usable form") {
			t.Errorf("%.12q: exit %d, %d requests\n%s\n%s", tok, code, e.hits(), out, errOut)
		}
		if strings.TrimSpace(tok) != "" && len(tok) < 100 && strings.Contains(errOut, tok) {
			t.Errorf("%.12q: the error repeats the request token", tok)
		}
	}
}

// ---- redirects and plain http ---------------------------------------------------------------------------------------------

func TestGitHubActionsLoginFollowsNoRedirect(t *testing.T) {
	t.Run("from GitHub", func(t *testing.T) {
		e := newGHEnv(t)
		target := newWorkloadAPI(t) // anything that counts what reaches it
		e.gh.reply = func(int) ghAnswer {
			return ghAnswer{302, map[string]string{"Location": target.URL + "/stolen"}, ``}
		}
		code, out, errOut := runGH(t, e.args()...)
		if code != 1 || target.hits() != 0 || e.api.hits() != 0 {
			t.Fatalf("exit %d, target %d, API %d\n%s\n%s", code, target.hits(), e.api.hits(), out, errOut)
		}
		if !strings.Contains(errOut, "redirect (HTTP 302)") || !strings.Contains(errOut, "Nothing was saved") {
			t.Errorf("stderr:\n%s", errOut)
		}
		if strings.Contains(errOut, target.URL) {
			t.Errorf("the redirect target is printed:\n%s", errOut)
		}
		noGHSecrets(t, "redirect from GitHub", false, out, errOut)
		nothingSaved(t)
	})
	for _, mode := range []string{"profile", "export-env"} {
		t.Run("from the API, "+mode, func(t *testing.T) {
			e := newGHEnv(t)
			target := newWorkloadAPI(t)
			e.api.answer = func(int) ghAnswer {
				return ghAnswer{307, map[string]string{"Location": target.URL + "/v1/auth/workload/exchange"}, ``}
			}
			args := e.args()
			if mode == "export-env" {
				useEnvFile(t, "")
				args = e.args("--export-env")
			}
			code, out, errOut := runGH(t, args...)
			if code != 1 || target.hits() != 0 {
				t.Fatalf("exit %d, target %d\n%s\n%s", code, target.hits(), out, errOut)
			}
			if !strings.Contains(errOut, "redirect (HTTP 307)") {
				t.Errorf("stderr:\n%s", errOut)
			}
			noGHSecrets(t, "redirect from the API", false, out, errOut)
			nothingSaved(t)
		})
	}
}

func TestGitHubActionsLoginRefusesPlainHTTPToTheAPIBeforeAskingGitHub(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{"--api-url", []string{"login", "--github-actions", "--trust", ghTrust, "--api-url", "http://api.example.test"}, nil},
		{"--api-url on a look-alike of loopback", []string{"login", "--github-actions", "--trust", ghTrust, "--api-url", "http://127.0.0.2:8080"}, nil},
		{"the environment", []string{"login", "--github-actions", "--trust", ghTrust}, map[string]string{"AGENTRUNTIME_API_URL": "http://api.example.test"}},
		{"derived from --url", []string{"login", "--github-actions", "--trust", ghTrust, "--url", "http://mcp.example.test/mcp"}, map[string]string{"AGENTRUNTIME_API_URL": ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGHEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			code, out, errOut := runGH(t, tc.args...)
			if code != 1 || e.hits() != 0 || out != "" || !strings.Contains(errOut, "plain http") || !strings.Contains(errOut, "identity token") {
				t.Fatalf("exit %d, %d requests\n%s\n%s", code, e.hits(), out, errOut)
			}
			nothingSaved(t)
		})
	}
}

// ---- what the server answers -----------------------------------------------------------------------------------------------

func TestGitHubActionsLogin401PrintsTheFixedSentenceAndTheHintsWithoutNamingACause(t *testing.T) {
	for _, mode := range []string{"profile", "export-env"} {
		t.Run(mode, func(t *testing.T) {
			e := newGHEnv(t)
			e.api.answer = func(int) ghAnswer {
				return ghAnswer{401, nil, `{"error":"invalid_workload_token","message":"` + ghSrvText + ` the branch is main"}`}
			}
			args := e.args()
			var path string
			if mode == "export-env" {
				path = useEnvFile(t, "FOO=bar\n")
				args = e.args("--export-env")
			}
			code, out, errOut := runGH(t, args...)
			if code != 1 || out != "" {
				t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
			}
			for _, want := range []string{
				"The server did not accept this job's identity token for that CI trust.", "The server does not say why.",
				"branch or in an environment the trust accepts", "not a pull request", "the audience", "--audience", "the trust id is the right one",
				"turned on", "each one works once", "Nothing was saved.",
			} {
				if !strings.Contains(errOut, want) {
					t.Errorf("stderr lacks %q:\n%s", want, errOut)
				}
			}
			// The list does not say which one it is, and the server's own words are not shown.
			for _, claim := range []string{"because", "the reason is", "the branch is main", "your branch", "your audience is wrong", "pull request was detected"} {
				if strings.Contains(errOut, claim) {
					t.Errorf("stderr claims a cause (%q):\n%s", claim, errOut)
				}
			}
			noGHSecrets(t, "401", false, out, errOut)
			nothingSaved(t)
			if mode == "export-env" && mustRead(t, path) != "FOO=bar\n" {
				t.Errorf("GITHUB_ENV changed: %q", mustRead(t, path))
			}
		})
	}
}

func TestGitHubActionsLoginOtherRefusalsAreFixedSentences(t *testing.T) {
	cases := []struct {
		name   string
		answer ghAnswer
		want   string
	}{
		{"400", ghAnswer{400, nil, `{"error":"invalid_request","message":"` + ghSrvText + `"}`}, "did not accept the sign-in request (HTTP 400). Check --trust."},
		{"403", ghAnswer{403, nil, `{"message":"` + ghSrvText + `"}`}, "The server refused the request (HTTP 403)."},
		{"401 with another code", ghAnswer{401, nil, `{"error":"unauthorized","message":"` + ghSrvText + `"}`}, "The server refused the request (HTTP 401)."},
		{"404", ghAnswer{404, nil, `<html>` + ghSrvText + `</html>`}, "does not offer CI sign-in at this address (HTTP 404)"},
		{"405", ghAnswer{405, nil, ``}, "does not offer CI sign-in at this address (HTTP 405)"},
		{"429", ghAnswer{429, map[string]string{"Retry-After": "42"}, `{"message":"` + ghSrvText + `"}`}, "Too many sign-in attempts (HTTP 429). Wait a minute and try again. Try again in 42 seconds."},
		{"500", ghAnswer{500, nil, `{"message":"` + ghSrvText + `"}`}, "could not do this right now (HTTP 500)"},
		{"503", ghAnswer{503, nil, ``}, "could not do this right now (HTTP 503)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGHEnv(t)
			e.api.answer = func(int) ghAnswer { return tc.answer }
			code, out, errOut := runGH(t, e.args()...)
			if code != 1 || out != "" || !strings.Contains(errOut, tc.want) || !strings.Contains(errOut, "Nothing was saved.") {
				t.Fatalf("exit %d\n%s\n%s\nwant %q", code, out, errOut, tc.want)
			}
			if strings.Contains(errOut, "does not say why") {
				t.Errorf("the hints for a refused identity token are shown for %s:\n%s", tc.name, errOut)
			}
			noGHSecrets(t, tc.name, false, out, errOut)
			nothingSaved(t)
		})
	}
}

func TestGitHubActionsLoginNeverUsesAnAnswerItCannotRead(t *testing.T) {
	huge := `{"token":"` + ghKey + `","expires_at":"` + clockNow.Add(15*time.Minute).Format(time.RFC3339) + `","pad":"` + strings.Repeat("x", 70*1024) + `"}`
	exp := clockNow.Add(15 * time.Minute).Format(time.RFC3339)
	bodies := map[string]string{
		"not json":                  "<html>" + ghSrvText + "</html>",
		"empty":                     "",
		"an array":                  "[]",
		"no token":                  `{"expires_at":"` + exp + `"}`,
		"a text that is not a key":  `{"token":"not-a-key-` + ghSrvText + `","expires_at":"` + exp + `"}`,
		"a key with a newline":      `{"token":"pat_abc\nEVIL=1","expires_at":"` + exp + `"}`,
		"a key with a space":        `{"token":"pat_abc def","expires_at":"` + exp + `"}`,
		"a key with an escape code": `{"token":"pat_abc\u001b[31m","expires_at":"` + exp + `"}`,
		"a key that is too long":    `{"token":"pat_` + strings.Repeat("a", 300) + `","expires_at":"` + exp + `"}`,
		"a number as the key":       `{"token":12345,"expires_at":"` + exp + `"}`,
		"no expiry":                 `{"token":"` + ghKey + `"}`,
		"an unreadable expiry":      `{"token":"` + ghKey + `","expires_at":"` + ghSrvText + `"}`,
		"a key for another trust":   `{"token":"` + ghKey + `","expires_at":"` + exp + `","trust":"99999999-2222-4333-8444-555555555555"}`,
		"text as the trust":         `{"token":"` + ghKey + `","expires_at":"` + exp + `","trust":"` + ghSrvText + `"}`,
		"a huge answer":             huge,
	}
	for name, body := range bodies {
		for _, mode := range []string{"profile", "export-env"} {
			t.Run(name+" "+mode, func(t *testing.T) {
				e := newGHEnv(t)
				e.api.answer = func(int) ghAnswer { return ghOK(body) }
				args := e.args()
				var path string
				if mode == "export-env" {
					path = useEnvFile(t, "FOO=bar\n")
					args = e.args("--export-env")
				}
				code, out, errOut := runGH(t, args...)
				if code != 1 || out != "" {
					t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
				}
				if !strings.Contains(errOut, "Nothing was saved") && !strings.Contains(errOut, "nothing was used") {
					t.Errorf("stderr does not say that nothing was saved:\n%s", errOut)
				}
				if strings.Contains(errOut, "EVIL") || strings.Contains(errOut, "\x1b") {
					t.Errorf("the answer is repeated:\n%s", errOut)
				}
				noGHSecrets(t, name, false, out, errOut)
				nothingSaved(t)
				if mode == "export-env" && mustRead(t, path) != "FOO=bar\n" {
					t.Errorf("GITHUB_ENV changed: %q", mustRead(t, path))
				}
			})
		}
	}
}

func TestGitHubActionsLoginWhenGitHubDoesNotGiveATokenTheAPIIsNeverCalled(t *testing.T) {
	cases := map[string]ghAnswer{
		"401":                         {401, nil, `{"message":"` + ghSrvText + `"}`},
		"403":                         {403, nil, `{"message":"` + ghSrvText + `"}`},
		"500":                         {500, nil, ``},
		"429":                         {429, nil, ``},
		"not json":                    ghOK("<html>" + ghSrvText + "</html>"),
		"no value":                    ghOK(`{"count":0}`),
		"a value that is not a token": ghOK(`{"value":"` + ghSrvText + `"}`),
		"a value with a newline":      ghOK(`{"value":"aaaaaaaa.bbbbbbbb\nEVIL.cccccccc"}`),
		"a huge answer":               ghOK(`{"value":"` + ghJWT + `","pad":"` + strings.Repeat("x", 70*1024) + `"}`),
	}
	for name, ans := range cases {
		t.Run(name, func(t *testing.T) {
			e := newGHEnv(t)
			e.gh.reply = func(int) ghAnswer { return ans }
			code, out, errOut := runGH(t, e.args()...)
			if code != 1 || out != "" || e.api.hits() != 0 || !strings.Contains(errOut, "Nothing was saved") {
				t.Fatalf("exit %d, API hits %d\n%s\n%s", code, e.api.hits(), out, errOut)
			}
			if strings.Contains(errOut, "EVIL") {
				t.Errorf("the answer is repeated:\n%s", errOut)
			}
			noGHSecrets(t, name, false, out, errOut)
			nothingSaved(t)
		})
	}
}

func TestGitHubActionsLoginStopsAtTheTimeout(t *testing.T) {
	e := newGHEnv(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	e.gh.block = release
	start := time.Now()
	code, out, errOut := runGH(t, e.args("--timeout", "300ms")...)
	if code != 1 || e.api.hits() != 0 || !strings.Contains(errOut, "timed out after 300ms") || !strings.Contains(errOut, "Nothing was saved") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	nothingSaved(t)
}

// ---- the profile -----------------------------------------------------------------------------------------------------------------

func TestGitHubActionsLoginDoesNotReplaceAKeyThatDoesNotExpireUnlessAsked(t *testing.T) {
	forever := func() map[string]*config.Profile {
		return map[string]*config.Profile{"default": {Token: "pat_FAKE-long-lived-1234567890", URL: "https://mcp.example.test/mcp"}}
	}
	// Refused before anything is sent.
	e := newGHEnv(t)
	writeConfig(t, "default", forever())
	code, out, errOut := runGH(t, e.args()...)
	if code != 2 || e.hits() != 0 || out != "" ||
		!strings.Contains(errOut, `profile "default" already holds an access key that does not expire`) || !strings.Contains(errOut, "--profile NAME") ||
		!strings.Contains(errOut, "--replace") || !strings.Contains(errOut, "--export-env") {
		t.Fatalf("exit %d, %d requests\n%s\n%s", code, e.hits(), out, errOut)
	}
	if savedProfile(t, "default").Token != "pat_FAKE-long-lived-1234567890" {
		t.Error("the key was replaced although it was refused")
	}
	if strings.Contains(out+errOut, "pat_FAKE-long") {
		t.Error("the existing key was printed")
	}
	// An unreadable expiry counts as a key that does not expire.
	e = newGHEnv(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-long-lived-1234567890", ExpiresAt: "garbage"}})
	if code, _, _ := runGH(t, e.args()...); code != 2 || e.hits() != 0 {
		t.Errorf("an unreadable stored expiry: exit %d, %d requests", code, e.hits())
	}

	// --replace replaces it.
	e = newGHEnv(t)
	writeConfig(t, "default", forever())
	if code, out, errOut := runGH(t, e.args("--replace")...); code != 0 {
		t.Fatalf("--replace: exit %d\n%s\n%s", code, out, errOut)
	}
	if p := savedProfile(t, "default"); p.Token != ghKey || p.ExpiresAt == "" {
		t.Errorf("--replace: profile %+v", p)
	}

	// --profile keeps both, and leaves the current profile alone.
	e = newGHEnv(t)
	writeConfig(t, "default", forever())
	if code, out, errOut := runGH(t, e.args("--profile", "ci")...); code != 0 {
		t.Fatalf("--profile: exit %d\n%s\n%s", code, out, errOut)
	}
	f, _ := config.Load()
	if f.Profiles["default"].Token != "pat_FAKE-long-lived-1234567890" || f.Profiles["ci"].Token != ghKey || f.Current != "default" {
		t.Errorf("--profile: %+v current %q", f.Profiles, f.Current)
	}

	// A key from an earlier sign-in (it has an expiry) is renewed without asking, and the URL of the profile is kept.
	e = newGHEnv(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: "pat_FAKE-old-signed-in-key", URL: "https://mcp.example.test/mcp", ExpiresAt: clockNow.Add(-time.Hour).Format(time.RFC3339)}})
	if code, out, errOut := runGH(t, e.args()...); code != 0 {
		t.Fatalf("renew: exit %d\n%s\n%s", code, out, errOut)
	}
	if p := savedProfile(t, "default"); p.Token != ghKey || p.URL != "https://mcp.example.test/mcp" {
		t.Errorf("renew: profile %+v", p)
	}
}

func TestGitHubActionsLoginFindsAnUnwritableConfigFolderBeforeSpendingTheIdentityToken(t *testing.T) {
	e := newGHEnv(t)
	blocker := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTRUNTIME_CONFIG", filepath.Join(blocker, "sub", "config.json"))
	code, out, errOut := runGH(t, e.args()...)
	if code != 1 || e.hits() != 0 || out != "" {
		t.Fatalf("exit %d, %d requests\n%s\n%s", code, e.hits(), out, errOut)
	}
}

func TestGitHubActionsLoginSaveFailureKeepsTheOldConfigAndNeverPrintsTheKey(t *testing.T) {
	e := newGHEnv(t)
	writeConfig(t, "other", map[string]*config.Profile{"other": {Token: "pat_FAKE-other-123456789", URL: "https://mcp.example.test/mcp"}})
	before := mustRead(t, configPath())
	// After the checks and before the key arrives, the folder becomes unwritable for this file: its temp name is a
	// folder with something in it.
	e.api.onCall = func(int) { _ = os.MkdirAll(filepath.Join(configPath()+".tmp", "keep"), 0o700) }
	code, out, errOut := runGH(t, e.args("--profile", "new")...)
	if code != 1 || !strings.Contains(errOut, "the sign-in worked, but the key could not be saved") ||
		!strings.Contains(errOut, "It cannot be shown again") || !strings.Contains(errOut, "Short-lived access") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	noGHSecrets(t, "save failure", false, out, errOut)
	if strings.Contains(out, "signed in") {
		t.Errorf("claimed success:\n%s", out)
	}
	if after := mustRead(t, configPath()); after != before {
		t.Errorf("the old config changed:\n%s", after)
	}
}

func TestGitHubActionsLoginNotesAnEnvironmentKeyThatWouldOverrideTheSavedOne(t *testing.T) {
	e := newGHEnv(t)
	t.Setenv("AGENTRUNTIME_PAT", "pat_FAKE-environment-key-0123456789")
	code, out, errOut := runGH(t, e.args()...)
	if code != 0 || !strings.Contains(errOut, "AGENTRUNTIME_PAT is set in your environment and overrides the saved key") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if strings.Contains(out+errOut, "FAKE-environment-key") {
		t.Error("the key from the environment was printed")
	}
}

// ---- usage -----------------------------------------------------------------------------------------------------------------------

func TestGitHubActionsLoginUsageErrorsSendNothing(t *testing.T) {
	pasted := "pat_FAKE-pasted-secret-0123456789"
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no trust", []string{"login", "--github-actions"}, "--trust is required"},
		{"an empty trust", []string{"login", "--github-actions", "--trust", ""}, "--trust is required"},
		{"a trust that is not an id", []string{"login", "--github-actions", "--trust", "my-trust"}, "--trust is not a trust id"},
		{"a pasted secret as the trust", []string{"login", "--github-actions", "--trust", pasted}, "--trust is not a trust id"},
		{"an id with a character added", []string{"login", "--github-actions", "--trust", ghTrust + "0"}, "--trust is not a trust id"},
		{"an id without hyphens", []string{"login", "--github-actions", "--trust", strings.ReplaceAll(ghTrust, "-", "")}, "--trust is not a trust id"},
		{"with --device", []string{"login", "--github-actions", "--device", "--trust", ghTrust}, "--device and --github-actions cannot be combined"},
		{"with --token", []string{"login", "--github-actions", "--trust", ghTrust, "--token", testToken}, "--github-actions cannot be combined with --token, --with-token or --no-verify"},
		{"with --with-token", []string{"login", "--github-actions", "--trust", ghTrust, "--with-token"}, "--github-actions cannot be combined with --token, --with-token or --no-verify"},
		{"with --no-verify", []string{"login", "--github-actions", "--trust", ghTrust, "--no-verify"}, "--github-actions cannot be combined with --token, --with-token or --no-verify"},
		{"--ref", []string{"login", "--github-actions", "--trust", ghTrust, "--ref", "my/*"}, "--ref only works with --device"},
		{"--all", []string{"login", "--github-actions", "--trust", ghTrust, "--all"}, "--all only works with --device"},
		{"--ttl", []string{"login", "--github-actions", "--trust", ghTrust, "--ttl", "1h"}, "--ttl only works with --device"},
		{"--scope", []string{"login", "--github-actions", "--trust", ghTrust, "--scope", "vault:read"}, "--scope only works with --device"},
		{"--open", []string{"login", "--github-actions", "--trust", ghTrust, "--open"}, "--open only works with --device"},
		{"--device-name", []string{"login", "--github-actions", "--trust", ghTrust, "--device-name", "x"}, "--device-name only works with --device"},
		{"--device with --trust", []string{"login", "--device", "--ref", "my/*", "--trust", ghTrust}, "--trust only works with --github-actions"},
		{"--device with --audience", []string{"login", "--device", "--ref", "my/*", "--audience", "x"}, "--audience only works with --github-actions"},
		{"--device with --export-env", []string{"login", "--device", "--ref", "my/*", "--export-env"}, "--export-env only works with --github-actions"},
		{"--trust alone", []string{"login", "--token", testToken, "--no-verify", "--trust", ghTrust}, "--trust only works with --github-actions"},
		{"--audience alone", []string{"login", "--token", testToken, "--no-verify", "--audience", "x"}, "--audience only works with --github-actions"},
		{"--export-env alone", []string{"login", "--token", testToken, "--no-verify", "--export-env"}, "--export-env only works with --github-actions"},
		{"--api-url alone", []string{"login", "--token", testToken, "--no-verify", "--api-url", "https://api.example.test"}, "--api-url only works with --device or --github-actions"},
		{"--replace alone", []string{"login", "--token", testToken, "--no-verify", "--replace"}, "--replace only works with --device or --github-actions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGHEnv(t)
			code, out, errOut := runGH(t, tc.args...)
			if code != 2 || e.hits() != 0 || out != "" || !strings.Contains(errOut, tc.want) {
				t.Fatalf("exit %d, %d requests\n%s\n%s\nwant %q", code, e.hits(), out, errOut, tc.want)
			}
			if strings.Contains(errOut, pasted) || strings.Contains(errOut, "my-trust") {
				t.Errorf("the error repeats what was typed:\n%s", errOut)
			}
			nothingSaved(t)
		})
	}
}

// ---- output hygiene ---------------------------------------------------------------------------------------------------------------

func TestGitHubActionsLoginWithJSONFlagStillPrintsNoKey(t *testing.T) {
	e := newGHEnv(t)
	code, out, errOut := runGH(t, e.args("--json")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	noGHSecrets(t, "--json", false, out, errOut)
	e = newGHEnv(t)
	useEnvFile(t, "")
	code, out, errOut = runGH(t, e.args("--json", "--export-env")...)
	if code != 0 {
		t.Fatalf("--export-env --json: exit %d\n%s\n%s", code, out, errOut)
	}
	noGHSecrets(t, "--export-env --json", true, out, errOut)
}

func TestGitHubActionsLoginPrintsNoTerminalControlCodes(t *testing.T) {
	e := newGHEnv(t)
	path := useEnvFile(t, "")
	code, out, errOut := runGH(t, e.args("--export-env")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	noTerminalCodes(t, "--export-env", out, errOut)
	_ = path
	e = newGHEnv(t)
	e.api.answer = func(int) ghAnswer {
		return ghAnswer{401, nil, `{"error":"invalid_workload_token","message":"\u001b[31mred"}`}
	}
	_, out, errOut = runGH(t, e.args()...)
	noTerminalCodes(t, "401", out, errOut)
}

func TestLoginHelpAndReadmeDescribeTheGitHubActionsSignIn(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "login", "--help")
	help = flat(help)
	text := flat(readme(t))
	for _, want := range []string{
		"--github-actions", "--trust", "--audience", "--export-env", "permissions: id-token: write", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
		"github.com or actions.githubusercontent.com", "never follows a redirect", "::add-mask::<key>", "GITHUB_ENV", "AGENTRUNTIME_WORKLOAD_AUDIENCE",
		"never prints the identity token, the request token or the key", "Short-lived access", "Exit codes: 0 signed in, 1 refused or failed, 2 bad flags, 130 Ctrl-C",
		"https://api.agentruntime.io/workload", "the profile holds a key that does not expire", "--replace",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("login --help lacks %q", want)
		}
	}
	for _, want := range []string{
		"## Sign in from GitHub Actions", "agentruntime login --github-actions", "permissions:", "id-token: write", "`--export-env`", "`::add-mask::`", "`GITHUB_ENV`",
		"`--trust`", "`--audience`", "`AGENTRUNTIME_WORKLOAD_AUDIENCE`", "never prints the identity token", "Each identity token works once", "`expires_at`",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
}

// ---- the ordinary login is as it was ----------------------------------------------------------------------------------------------

func TestGitHubActionsFlagsDoNotChangeAPlainLogin(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, out, errOut := run(t, "", "login", "--token", testToken, "--url", srv.URL)
	if code != 0 || !strings.Contains(out, "Acme Corp") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if p := savedProfile(t, "default"); p.Token != testToken || p.ExpiresAt != "" {
		t.Errorf("profile %+v", p)
	}
}

// A request-token address that only passes as GitHub's under a Unicode case mapping is refused, and nothing is dialled:
// the recording transport replaces the default one, so any request, to any host, would be seen.
func TestGitHubActionsLoginDialsNothingForAnEscapedLookalikeOfGitHub(t *testing.T) {
	for _, u := range []string{
		"https://g%C4%B0thub.com/x", "https://actions.g%C4%B0thubusercontent.com/_apis/idtoken?api-version=2.0",
		"https://pipelines.actions.g%C4%B0thubusercontent.com/x", "https://github%E2%84%AA.com/x", "https://%EF%BD%87ithub.com/x",
		"https://g%25C4%25B0thub.com/x", "HTTPS://G%C4%B0THUB.COM/x",
	} {
		e := newGHEnv(t)
		net := recordNetwork(t)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", u)
		code, out, errOut := runGH(t, e.args()...)
		if code != 1 || !strings.Contains(errOut, "will send the job's request token to") || out != "" {
			t.Errorf("%q: exit %d\n%s\n%s", u, code, out, errOut)
		}
		if reqs := net.requests(); len(reqs) != 0 || e.hits() != 0 {
			t.Errorf("%q: dialled %v, fakes hit %d times", u, reqs, e.hits())
		}
		if strings.Contains(errOut, ghReqToken) {
			t.Errorf("%q: the request token is in the error", u)
		}
		nothingSaved(t)
	}
}

func TestHelpAndReadmeSayHowTheGitHubHostIsChecked(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "login", "--help")
	if !strings.Contains(flat(help), "The host is checked exactly as it will be dialled: plain ASCII letters, digits, dots and hyphens only") {
		t.Errorf("login --help does not say how the GitHub host is checked")
	}
	if !strings.Contains(flat(readme(t)), "The host is checked exactly as it will be dialled: it must be plain ASCII letters, digits, dots and hyphens") {
		t.Errorf("the README does not say how the GitHub host is checked")
	}
}
