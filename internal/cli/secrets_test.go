package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Every value below is fake. Nothing in this file is a real credential.
const (
	fakeKey     = "sk_test_FAKE_0123456789abcdef"
	fakeHook    = "whsec_FAKE_9876543210zyxwvu"
	fakeTok     = "deploytoken_FAKE_1234567"
	fakeSpecial = "p@ss w/rd+&=<ünï>ok!"
	fakeDBPass  = "dbpass_FAKE_value_55"
	fakeAPIKey  = "apikey_FAKE_value_66"
	fakeShort   = "12ab"
)

// bffReq is the body of a fetch call.
type bffReq struct {
	Refs  []string `json:"refs"`
	Check bool     `json:"check"`
}

// fakeBFF stands in for POST /v1/secrets/fetch. By default it answers from
// store, all or nothing, and counts every request.
type fakeBFF struct {
	*httptest.Server
	mu    sync.Mutex
	reqs  []bffReq
	hdrs  []http.Header
	store map[string]map[string]string
	// override, when set, answers instead of the default logic.
	override func(r bffReq) (status int, body string, header map[string]string)
}

func newFakeBFF(t *testing.T) *fakeBFF {
	t.Helper()
	f := &fakeBFF{store: map[string]map[string]string{
		"workspace/live/stripe": {"API_KEY": fakeKey, "WEBHOOK": fakeHook},
		"my/deploy":             {"TOKEN": fakeTok, "HOST": "deploy-host.test"},
		"workspace/app":         {"db_pass": fakeDBPass, "Host": "db.example.test", "API_KEY": fakeAPIKey},
		"workspace/special":     {"P": fakeSpecial},
		"my/pin":                {"PIN": fakeShort},
		"workspace/badnames":    {"api-key": "badname_FAKE_value_1"},
		"workspace/c1":          {"x_y": "collide_FAKE_value_1"},
		"workspace/c2":          {"X_Y": "collide_FAKE_value_2"},
		"workspace/dup":         {"a_b": "dupfield_FAKE_value_1", "A_B": "dupfield_FAKE_value_2"},
		"workspace/nl":          {"TOKEN": fakeNLToken},
		"workspace/pem":         {"KEY": fakePEM},
	}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeBFF) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path != "/v1/secrets/fetch" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req bffReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad_ref","message":"bad body"}`))
		return
	}
	f.reqs = append(f.reqs, req)
	f.hdrs = append(f.hdrs, r.Header.Clone())

	if f.override != nil {
		status, body, hdr := f.override(req)
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
		return
	}

	resolve := func(ref string) (any, bool) {
		base, field, hasField := strings.Cut(ref, "#")
		sec, ok := f.store[base]
		if !ok {
			return nil, false
		}
		if !hasField {
			return sec, true
		}
		v, ok := sec[field]
		return v, ok
	}
	if req.Check {
		items := []map[string]any{}
		for _, ref := range req.Refs {
			_, ok := resolve(ref)
			items = append(items, map[string]any{"ref": ref, "resolves": ok})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
		return
	}
	values := map[string]any{}
	for _, ref := range req.Refs {
		v, ok := resolve(ref)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found","message":"No such secret for this key."}`))
			return
		}
		values[ref] = v
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"values": values})
}

func (f *fakeBFF) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *fakeBFF) last() bffReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		return bffReq{}
	}
	return f.reqs[len(f.reqs)-1]
}

// runSecrets runs `agentruntime secrets <sub> --api-url <fake> ...`.
func runSecrets(t *testing.T, f *fakeBFF, stdin, sub string, args ...string) (int, string, string) {
	t.Helper()
	full := append([]string{"--pat", testToken, "secrets", sub, "--api-url", f.URL}, args...)
	return run(t, stdin, full...)
}

// helper builds a child command line that re-runs this test binary as a helper
// process (see TestHelperProcess).
func helper(args ...string) []string {
	return append([]string{os.Args[0], "-test.run=^TestHelperProcess$", "--"}, args...)
}

func withHelper(t *testing.T) {
	t.Helper()
	isolate(t)
	t.Setenv("AR_HELPER_PROCESS", "1")
}

// TestHelperProcess is not a test: it is the child that `secrets run` starts.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("AR_HELPER_PROCESS") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	switch args[0] {
	case "dump-env": // dump-env OUT NAME...
		var sb strings.Builder
		for _, name := range args[2:] {
			v, ok := os.LookupEnv(name)
			if !ok {
				v = "<unset>"
			}
			fmt.Fprintf(&sb, "%s=%s\n", name, v)
		}
		_ = os.WriteFile(args[1], []byte(sb.String()), 0o600)
	case "print-env": // print-env NAME: the value in several forms, to stdout and stderr
		v := os.Getenv(args[1])
		j, _ := json.Marshal(v)
		fmt.Println("marker-plain-text")
		fmt.Println("raw:", v)
		fmt.Println("b64:", base64.StdEncoding.EncodeToString([]byte(v)))
		fmt.Println("b64raw:", base64.RawURLEncoding.EncodeToString([]byte(v)))
		fmt.Println("urlenc:", url.QueryEscape(v))
		fmt.Println("json:", string(j))
		fmt.Fprintln(os.Stderr, "err raw:", v)
		fmt.Fprintln(os.Stderr, "err json:", string(j))
	case "print-lines": // print-lines NAME...: each value trimmed, then line by line
		for _, n := range args[1:] {
			v := os.Getenv(n)
			fmt.Println(n+" (trimmed):", strings.TrimSpace(v))
			for _, line := range strings.Split(v, "\n") {
				fmt.Println("line:", line)
			}
		}
	case "print-env2": // print-env2 NAME NAME: two values on one line each
		for _, n := range args[1:] {
			fmt.Println(n+":", os.Getenv(n))
		}
	case "exit":
		var n int
		fmt.Sscan(args[1], &n)
		os.Exit(n)
	case "touch":
		_ = os.WriteFile(args[1], []byte("ran"), 0o600)
	case "copy-file": // copy-file SRC DST
		b, err := os.ReadFile(args[1])
		if err != nil {
			_ = os.WriteFile(args[2], []byte("missing"), 0o600)
			break
		}
		_ = os.WriteFile(args[2], b, 0o600)
		if st, err := os.Stat(args[1]); err == nil {
			_ = os.WriteFile(args[2]+".mode", []byte(fmt.Sprintf("%o", st.Mode().Perm())), 0o600)
		}
	case "stdin-to-file":
		b, _ := io.ReadAll(os.Stdin)
		_ = os.WriteFile(args[1], b, 0o600)
	case "wait", "wait-ignore-term": // wait READY: signal readiness, then sleep
		if args[0] == "wait-ignore-term" {
			ignoreTerm()
		}
		_ = os.WriteFile(args[1], []byte("ready"), 0o600)
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

// ---- helpers ------------------------------------------------------------------------

// allFakeValues lists every fake value and the encodings tests look for.
func allFakeValues() []string {
	var out []string
	for _, v := range []string{fakeKey, fakeHook, fakeTok, fakeSpecial, fakeDBPass, fakeAPIKey} {
		out = append(out,
			v,
			base64.StdEncoding.EncodeToString([]byte(v)),
			base64.RawURLEncoding.EncodeToString([]byte(v)),
			url.QueryEscape(v),
		)
	}
	return out
}

// assertNoValue fails when any fake value, or an encoding of one, appears in the outputs.
func assertNoValue(t *testing.T, what string, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, v := range allFakeValues() {
			if strings.Contains(o, v) {
				t.Errorf("%s: a secret value (%q…) appears in the output:\n%s", what, v[:6], o)
			}
		}
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func waitFor(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if exists(path) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
}

// ---- secrets run: environment, exit code, stdin --------------------------------------

func TestSecretsRunEnvValuesReachTheChild(t *testing.T) {
	withHelper(t)
	t.Setenv("STRIPE_KEY", "old-value-from-parent")
	f := newFakeBFF(t)
	dump := filepath.Join(t.TempDir(), "env.txt")

	args := []string{"--env", "STRIPE_KEY=secret:workspace/live/stripe#API_KEY", "--env", "DEPLOY=my/deploy#TOKEN", "--"}
	args = append(args, helper("dump-env", dump, "STRIPE_KEY", "DEPLOY", "AR_HELPER_PROCESS")...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	want := "STRIPE_KEY=" + fakeKey + "\nDEPLOY=" + fakeTok + "\nAR_HELPER_PROCESS=1\n"
	if got := mustRead(t, dump); got != want {
		t.Errorf("child environment:\n%s\nwant:\n%s", got, want)
	}
	if f.count() != 1 {
		t.Fatalf("%d fetch calls, want exactly 1", f.count())
	}
	req := f.last()
	if strings.Join(req.Refs, ",") != "workspace/live/stripe#API_KEY,my/deploy#TOKEN" || req.Check {
		t.Errorf("request = %+v (the secret: prefix must be stripped)", req)
	}
	if h := f.hdrs[0]; h.Get("Authorization") != "Bearer "+testToken || !strings.HasPrefix(h.Get("User-Agent"), "agentruntime-cli/") {
		t.Errorf("headers = %v", h)
	}
	assertNoValue(t, "run", out, errOut)
	if out != "" || errOut != "" {
		t.Errorf("a quiet run should print nothing: stdout %q stderr %q", out, errOut)
	}
}

func TestSecretsRunPassesExitCodeThrough(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	for _, want := range []int{0, 1, 7, 42} {
		args := []string{"--env", "K=workspace/live/stripe#API_KEY", "--"}
		args = append(args, helper("exit", fmt.Sprint(want))...)
		code, out, errOut := runSecrets(t, f, "", "run", args...)
		if code != want {
			t.Errorf("exit code %d, want %d", code, want)
		}
		if strings.Contains(errOut, "error:") {
			t.Errorf("a failing child must not add an error line: %q", errOut)
		}
		assertNoValue(t, "exit", out, errOut)
	}
}

func TestSecretsRunPassesStdinThrough(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dst := filepath.Join(t.TempDir(), "stdin.txt")
	args := []string{"--env", "K=workspace/live/stripe#API_KEY", "--"}
	args = append(args, helper("stdin-to-file", dst)...)
	if code, out, errOut := runSecrets(t, f, "hello\nworld\n", "run", args...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if got := mustRead(t, dst); got != "hello\nworld\n" {
		t.Errorf("stdin arrived as %q", got)
	}
}

func TestSecretsRunCommandNotFoundDoesNotFetch(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	code, _, errOut := runSecrets(t, f, "", "run", "--env", "K=workspace/live/stripe#API_KEY", "--", "no-such-program-agentruntime-test")
	if code != 127 || !strings.Contains(errOut, "cannot run") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if f.count() != 0 {
		t.Error("a program that cannot run must not use up a fetch")
	}
}

// ---- masking ------------------------------------------------------------------------

func TestSecretsRunMasksEveryFormOnStdoutAndStderr(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	for _, ref := range []string{"workspace/live/stripe#API_KEY", "workspace/special#P"} {
		args := []string{"--env", "K=" + ref, "--"}
		args = append(args, helper("print-env", "K")...)
		code, out, errOut := runSecrets(t, f, "", "run", args...)
		if code != 0 {
			t.Fatalf("%s: exit %d\n%s\n%s", ref, code, out, errOut)
		}
		assertNoValue(t, ref, out, errOut)
		// The JSON form of the special value carries <, > and & escapes in Go's encoder.
		for _, forbidden := range []string{"p@ss w", "p%40ss", "\\u003c", "sk_test_FAKE"} {
			if strings.Contains(out+errOut, forbidden) {
				t.Errorf("%s: %q leaked:\n%s\n%s", ref, forbidden, out, errOut)
			}
		}
		for _, line := range []string{"marker-plain-text", "raw: ***", "b64: ***", "b64raw: ***", "urlenc: ***", `json: "***"`} {
			if !strings.Contains(out, line) {
				t.Errorf("%s: stdout lacks %q:\n%s", ref, line, out)
			}
		}
		for _, line := range []string{"err raw: ***", `err json: "***"`} {
			if !strings.Contains(errOut, line) {
				t.Errorf("%s: stderr lacks %q:\n%s", ref, line, errOut)
			}
		}
	}
}

func TestSecretsRunMasksValuesFromEveryRefAndFile(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dir := t.TempDir()
	// A value that is only written to a file is masked too.
	args := []string{
		"--env", "A=workspace/live/stripe#API_KEY", "--env", "B=my/deploy#TOKEN",
		"--secret-file", filepath.Join(dir, "app.env") + "=workspace/live/stripe#API_KEY,WEBHOOK", "--",
	}
	args = append(args, helper("print-env2", "A", "B")...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "A: ***") || !strings.Contains(out, "B: ***") {
		t.Errorf("stdout:\n%s", out)
	}
	assertNoValue(t, "multi", out, errOut)
}

func TestSecretsRunShortValuesAreNotMaskedAndSaidOnce(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	args := []string{"--env", "PIN=my/pin#PIN", "--env", "KEY=workspace/live/stripe#API_KEY", "--env", "PIN2=my/pin#PIN", "--"}
	args = append(args, helper("print-env2", "PIN", "KEY")...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "PIN: "+fakeShort) {
		t.Errorf("the short value is printed unmasked by design:\n%s", out)
	}
	if !strings.Contains(out, "KEY: ***") {
		t.Errorf("the long value must still be masked:\n%s", out)
	}
	if n := strings.Count(errOut, "shorter than 8"); n != 1 {
		t.Errorf("the note must appear once on stderr, got %d:\n%s", n, errOut)
	}
	if strings.Contains(errOut, fakeShort) {
		t.Errorf("the note must not print the value: %s", errOut)
	}
	assertNoValue(t, "short", out, errOut)
}

// ---- the command does not inherit the access key --------------------------------------

func TestSecretsRunDoesNotPassTheAccessKeyUnlessAsked(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag []string
		want string
	}{
		{"default strips it", nil, "AGENTRUNTIME_PAT=<unset>\n"},
		{"--pass-key keeps it", []string{"--pass-key"}, "AGENTRUNTIME_PAT=pat_from_env\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHelper(t)
			t.Setenv("AGENTRUNTIME_PAT", "pat_from_env")
			f := newFakeBFF(t)
			dump := filepath.Join(t.TempDir(), "env.txt")
			args := append([]string{"--env", "HOST=my/deploy#HOST"}, tc.flag...)
			args = append(args, "--")
			args = append(args, helper("dump-env", dump, "AGENTRUNTIME_PAT")...)
			code, out, errOut := runSecrets(t, f, "", "run", args...)
			if code != 0 {
				t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
			}
			if got := mustRead(t, dump); got != tc.want {
				t.Errorf("child environment:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

// ---- --env-from ---------------------------------------------------------------------

func TestSecretsRunEnvFromUppercasesFieldNames(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dump := filepath.Join(t.TempDir(), "env.txt")
	args := []string{"--env-from", "secret:workspace/app#db_pass,Host,API_KEY", "--env", "HOST=my/deploy#HOST", "--"}
	args = append(args, helper("dump-env", dump, "DB_PASS", "HOST", "API_KEY", "db_pass", "Host")...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	want := "DB_PASS=" + fakeDBPass + "\n" +
		"HOST=deploy-host.test\n" + // the explicit --env wins over --env-from's Host
		"API_KEY=" + fakeAPIKey + "\n" +
		"db_pass=<unset>\n" +
		"Host=<unset>\n"
	if runtime.GOOS == "windows" {
		// Windows variable names are case-insensitive: the lower-case probes find the upper-case ones.
		want = strings.Replace(want, "db_pass=<unset>", "db_pass="+fakeDBPass, 1)
		want = strings.Replace(want, "Host=<unset>", "Host=deploy-host.test", 1)
	}
	if got := mustRead(t, dump); got != want {
		t.Errorf("child environment:\n%s\nwant:\n%s", got, want)
	}
	if got := strings.Join(f.last().Refs, ","); got != "my/deploy#HOST,workspace/app#db_pass,workspace/app#Host,workspace/app#API_KEY" {
		t.Errorf("refs = %s (distinct, --env first, one per named field)", got)
	}
	assertNoValue(t, "env-from", out, errOut)
}

// ---- --secret-file ------------------------------------------------------------------

func TestSecretsRunWritesOwnerOnlyFilesAndRemovesThem(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dir := t.TempDir()
	envFile, jsonFile := filepath.Join(dir, "app.env"), filepath.Join(dir, "creds.json")
	copyEnv, copyJSON := filepath.Join(dir, "copy.env"), filepath.Join(dir, "copy.json")

	// The helper copies each file while the command runs, so the test can see it.
	runOne := func(file, ref, copyTo string, childExit int) (int, string, string) {
		args := []string{"--secret-file", file + "=" + ref, "--"}
		if childExit == 0 {
			args = append(args, helper("copy-file", file, copyTo)...)
		} else {
			args = append(args, helper("exit", fmt.Sprint(childExit))...)
		}
		return runSecrets(t, f, "", "run", args...)
	}

	// dotenv: the fields are named
	code, out, errOut := runOne(envFile, "workspace/app#API_KEY,Host,db_pass", copyEnv, 0)
	if code != 0 {
		t.Fatalf("dotenv: exit %d\n%s\n%s", code, out, errOut)
	}
	wantEnv := "API_KEY=" + fakeAPIKey + "\nHost=db.example.test\ndb_pass=" + fakeDBPass + "\n"
	if got := mustRead(t, copyEnv); got != wantEnv {
		t.Errorf("dotenv content:\n%s\nwant:\n%s", got, wantEnv)
	}
	if exists(envFile) {
		t.Error("the dotenv file must be removed when the command ends")
	}
	if runtime.GOOS != "windows" {
		if mode := mustRead(t, copyEnv+".mode"); mode != "600" {
			t.Errorf("file mode %s, want 600", mode)
		}
	}
	assertNoValue(t, "dotenv", out, errOut)

	// JSON
	code, out, errOut = runOne(jsonFile, "my/deploy", copyJSON, 0)
	if code != 0 {
		t.Fatalf("json: exit %d\n%s\n%s", code, out, errOut)
	}
	var back map[string]string
	if err := json.Unmarshal([]byte(mustRead(t, copyJSON)), &back); err != nil || back["TOKEN"] != fakeTok || back["HOST"] != "deploy-host.test" {
		t.Errorf("json content: %v %v", back, err)
	}
	if exists(jsonFile) {
		t.Error("the JSON file must be removed when the command ends")
	}
	assertNoValue(t, "json", out, errOut)

	// The command fails: the file is still removed and the exit code is the command's.
	code, out, errOut = runOne(envFile, "workspace/app#db_pass", "", 3)
	if code != 3 {
		t.Errorf("exit code %d, want 3", code)
	}
	if exists(envFile) {
		t.Error("the file must be removed even when the command fails")
	}
	assertNoValue(t, "failure", out, errOut)
}

func TestSecretsRunRefusesToOverwriteOrMissingFolderBeforeFetching(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dir := t.TempDir()
	existing := filepath.Join(dir, ".env")
	if err := os.WriteFile(existing, []byte("ORIGINAL=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "ran")
	args := append([]string{"--secret-file", existing + "=workspace/app#db_pass", "--"}, helper("touch", marker)...)
	code, _, errOut := runSecrets(t, f, "", "run", args...)
	if code != ExitUsage || !strings.Contains(errOut, "refusing to overwrite") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if got := mustRead(t, existing); got != "ORIGINAL=1\n" {
		t.Errorf("an existing file was changed: %q", got)
	}
	args = append([]string{"--secret-file", filepath.Join(dir, "nope", "a.env") + "=workspace/app#db_pass", "--"}, helper("touch", marker)...)
	code, _, errOut = runSecrets(t, f, "", "run", args...)
	if code != ExitUsage || !strings.Contains(errOut, "folder does not exist") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if f.count() != 0 || exists(marker) {
		t.Errorf("nothing may be fetched or run: fetches=%d", f.count())
	}
}

func TestSecretsRunSignalsRemoveFilesAndSecondSignalKills(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dir := t.TempDir()
	file, ready := filepath.Join(dir, "app.env"), filepath.Join(dir, "ready")

	sigs := make(chan os.Signal, 4)
	var out, errb bytes.Buffer
	app := NewApp(strings.NewReader(""), &out, &errb)
	app.signalSource = sigs
	done := make(chan int, 1)
	args := append([]string{"--no-color", "--pat", testToken, "secrets", "run", "--api-url", f.URL,
		"--secret-file", file + "=workspace/app#db_pass", "--"}, helper("wait-ignore-term", ready)...)
	go func() { done <- app.Run(args) }()

	waitFor(t, ready)
	if !exists(file) {
		t.Fatal("the secret file should exist while the command runs")
	}
	// The command ignores the first signal (forwarded on Unix, a no-op on Windows);
	// the run must still be going. The second signal kills it.
	sigs <- syscall.SIGTERM
	select {
	case code := <-done:
		t.Fatalf("returned after one signal (code %d) although the command ignores it", code)
	case <-time.After(400 * time.Millisecond):
	}
	sigs <- syscall.SIGTERM
	select {
	case code := <-done:
		if code == 0 {
			t.Error("a killed command must not report success")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after the second signal")
	}
	if exists(file) {
		t.Error("the secret file must be removed after a signal")
	}
	assertNoValue(t, "signal", out.String(), errb.String())
}

// ---- failures from the server: each code, all or nothing ------------------------------

func TestSecretsRunServerErrorCodes(t *testing.T) {
	withHelper(t)
	cases := []struct {
		code   string
		status int
		header map[string]string
		body   string
		want   []string
	}{
		{"fetch_key_required", 403, nil, `{"error":"fetch_key_required","message":"Only an access key can fetch."}`, []string{"Only an access key can fetch.", "(fetch_key_required)"}},
		{"missing_scope", 403, nil, `{"error":"missing_scope","message":"The key lacks the scope."}`, []string{"The key lacks the scope.", "(missing_scope)"}},
		{"fetch_disabled", 403, nil, `{"error":"fetch_disabled","message":"Fetch is off."}`, []string{"Fetch is off.", "(fetch_disabled)"}},
		{"view_disabled", 403, nil, `{"error":"view_disabled","message":"Viewing is off."}`, []string{"Viewing is off.", "(view_disabled)"}},
		{"not_found", 404, nil, `{"error":"not_found","message":"No such secret for this key."}`, []string{"No such secret for this key.", "(not_found)"}},
		{"ambiguous_ref", 409, nil, `{"error":"ambiguous_ref","message":"The name is ambiguous.","rooms":["my","workspace"]}`, []string{"The name is ambiguous.", "(ambiguous_ref)", "my, workspace", "my/<name>"}},
		{"uses_exhausted", 403, nil, `{"error":"uses_exhausted","message":"No uses left."}`, []string{"No uses left.", "(uses_exhausted)"}},
		{"rate_limited", 429, map[string]string{"Retry-After": "17"}, `{"error":"rate_limited","message":"Slow down."}`, []string{"Slow down.", "(rate_limited)", "17 seconds"}},
		{"bad_ref", 400, nil, `{"error":"bad_ref","message":"A reference is not valid."}`, []string{"A reference is not valid.", "(bad_ref)"}},
		{"too_large", 413, nil, `{"error":"too_large","message":"Too much."}`, []string{"Too much.", "(too_large)"}},
		{"audit_failed", 503, nil, `{"error":"audit_failed","message":"Not recorded."}`, []string{"Not recorded.", "(audit_failed)"}},
		{"codes without a sentence use the fixed fallback", 403, nil, `{"error":"missing_scope"}`, []string{"secrets:fetch", "(missing_scope)"}},
		{"401 with no body", 401, nil, ``, []string{"HTTP 401", "agentruntime login"}},
	}
	for _, c := range cases {
		f := newFakeBFF(t)
		f.override = func(bffReq) (int, string, map[string]string) { return c.status, c.body, c.header }
		dir := t.TempDir()
		marker, file := filepath.Join(dir, "ran"), filepath.Join(dir, "app.env")
		args := []string{"--env", "K=workspace/live/stripe#API_KEY", "--secret-file", file + "=workspace/app#db_pass", "--"}
		args = append(args, helper("touch", marker)...)
		code, out, errOut := runSecrets(t, f, "", "run", args...)
		if code != ExitError {
			t.Errorf("%s: exit %d, want 1", c.code, code)
		}
		for _, w := range c.want {
			if !strings.Contains(errOut, w) {
				t.Errorf("%s: stderr lacks %q:\n%s", c.code, w, errOut)
			}
		}
		if out != "" {
			t.Errorf("%s: stdout must stay empty, got %q", c.code, out)
		}
		if exists(marker) || exists(file) {
			t.Errorf("%s: no command and no file on a refused fetch", c.code)
		}
		if f.count() != 1 {
			t.Errorf("%s: %d calls, want 1 (no retry)", c.code, f.count())
		}
		assertNoValue(t, c.code, out, errOut)
	}
}

func TestSecretsRunIsAllOrNothing(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dir := t.TempDir()
	marker, file := filepath.Join(dir, "ran"), filepath.Join(dir, "app.env")
	args := []string{
		"--env", "A=workspace/live/stripe#API_KEY", "--env", "B=my/missing#X",
		"--secret-file", file + "=workspace/app#db_pass", "--",
	}
	args = append(args, helper("touch", marker)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 1 || !strings.Contains(errOut, "not_found") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if exists(marker) || exists(file) {
		t.Error("one unresolved reference must stop everything")
	}
	if f.count() != 1 {
		t.Errorf("one call for all refs, got %d", f.count())
	}
	assertNoValue(t, "all or nothing", out, errOut)
}

func TestSecretsRunRefusesAnAnswerThatSkipsARef(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	f.override = func(r bffReq) (int, string, map[string]string) {
		// 200, but only the first ref is answered.
		return 200, fmt.Sprintf(`{"values":{%q:%q}}`, r.Refs[0], fakeKey), nil
	}
	marker := filepath.Join(t.TempDir(), "ran")
	args := []string{"--env", "A=workspace/live/stripe#API_KEY", "--env", "B=my/deploy#TOKEN", "--"}
	args = append(args, helper("touch", marker)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 1 || !strings.Contains(errOut, "did not answer for every reference") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if exists(marker) {
		t.Error("the command must not start on an incomplete answer")
	}
	assertNoValue(t, "incomplete", out, errOut)
}

func TestSecretsRunNeedsALoginAndASafeAddress(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	// No token anywhere.
	// The command is a harmless helper: were it ever started, it must not re-run the whole test binary.
	cmdline := append([]string{"--env", "K=my/a#B", "--"}, helper("exit", "0")...)
	code, _, errOut := run(t, "", append([]string{"secrets", "run", "--api-url", f.URL}, cmdline...)...)
	if code != 1 || !strings.Contains(errOut, "agentruntime login") {
		t.Errorf("not logged in: code=%d err=%q", code, errOut)
	}
	// A plain-http address that is not local would send the key in the clear.
	code, _, errOut = run(t, "", append([]string{"--pat", testToken, "secrets", "run", "--api-url", "http://api.example.invalid"}, cmdline...)...)
	if code != 1 || !strings.Contains(errOut, "plain http") {
		t.Errorf("plain http: code=%d err=%q", code, errOut)
	}
	if f.count() != 0 {
		t.Error("no request may be made")
	}
}

func TestAPIAddressResolution(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dump := filepath.Join(t.TempDir(), "env.txt")
	childArgs := append([]string{"--"}, helper("dump-env", dump, "K")...)

	// The environment variable works when no flag is given.
	t.Setenv("AGENTRUNTIME_API_URL", f.URL)
	args := append([]string{"--pat", testToken, "secrets", "run", "--env", "K=workspace/live/stripe#API_KEY"}, childArgs...)
	if code, out, errOut := run(t, "", args...); code != 0 {
		t.Fatalf("env override: exit %d\n%s\n%s", code, out, errOut)
	}
	if f.count() != 1 {
		t.Errorf("env override: %d calls", f.count())
	}
	// The flag wins over the environment variable.
	t.Setenv("AGENTRUNTIME_API_URL", "http://127.0.0.1:1")
	if code, out, errOut := runSecrets(t, f, "", "run", append([]string{"--env", "K=workspace/live/stripe#API_KEY"}, childArgs...)...); code != 0 {
		t.Fatalf("flag override: exit %d\n%s\n%s", code, out, errOut)
	}
	// With neither, a local MCP address cannot be turned into an API address.
	t.Setenv("AGENTRUNTIME_API_URL", "")
	code, _, errOut := run(t, "", "--pat", testToken, "--url", "http://127.0.0.1:8340/mcp", "secrets", "check", "my/a")
	if code != 1 || !strings.Contains(errOut, "cannot derive the API address") || !strings.Contains(errOut, "--api-url") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

func TestSecretsPlainHTTPOnlyForLocalhost127AndIPv6Loopback(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	for _, addr := range []string{"http://api.localhost:1", "http://foo.localhost", "http://127.0.0.2:1", "http://localhost.example.test:1"} {
		code, _, errOut := run(t, "", "--pat", testToken, "secrets", "check", "--api-url", addr, "my/a")
		if code != ExitError || !strings.Contains(errOut, "plain http") {
			t.Errorf("%s: code=%d err=%q", addr, code, errOut)
		}
	}
	if f.count() != 0 {
		t.Error("no request may be made")
	}
	// The exact hosts are accepted (the fake server is on 127.0.0.1).
	if code, _, errOut := runSecrets(t, f, "", "check", "workspace/app"); code != 0 {
		t.Errorf("127.0.0.1: code=%d err=%q", code, errOut)
	}
}

// ---- secrets run: usage errors ------------------------------------------------------

func TestSecretsRunUsageErrors(t *testing.T) {
	withHelper(t)
	dir := t.TempDir()
	twenty1 := []string{}
	for i := 0; i < 21; i++ {
		twenty1 = append(twenty1, "--env", fmt.Sprintf("V%d=my/s%d#F", i, i))
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no dash", []string{"--env", "A=my/x#Y", "python"}, "put -- before the command"},
		{"no command", []string{"--env", "A=my/x#Y", "--"}, "missing command"},
		{"args before dash", []string{"--env", "A=my/x#Y", "extra", "--", "cmd"}, "unexpected arguments before --"},
		{"nothing to fetch", []string{"--", "cmd"}, "nothing to fetch"},
		{"env without =", []string{"--env", "NOEQUALS", "--", "cmd"}, "--env expects NAME=REF"},
		{"bad env name", []string{"--env", "1X=my/a#b", "--", "cmd"}, "not a valid variable name"},
		{"dup env name", []string{"--env", "A=my/a#b", "--env", "A=my/c#d", "--", "cmd"}, "given twice"},
		{"env with a whole secret", []string{"--env", "A=my/a", "--", "cmd"}, "no #field"},
		{"env-from without names", []string{"--env-from", "my/a", "--", "cmd"}, "name the fields"},
		{"env-from wildcard", []string{"--env-from", "my/a#*", "--", "cmd"}, "'*' is not accepted"},
		{"env-from repeated name", []string{"--env-from", "my/a#b,c,b", "--", "cmd"}, "field 3 repeats field 1"},
		{"env-from name with a dash", []string{"--env-from", "my/a#api-key", "--", "cmd"}, "not a plain ASCII name"},
		{"env-from reserved name", []string{"--env-from", "my/a#agentruntime_pat", "--", "cmd"}, "reserved"},
		{"secret-file bad extension", []string{"--secret-file", filepath.Join(dir, "x.txt") + "=my/a#b", "--", "cmd"}, "cannot tell the file format"},
		{"dotenv file without names", []string{"--secret-file", filepath.Join(dir, "x.env") + "=my/a", "--", "cmd"}, "a dotenv file needs the fields to write"},
		{"dotenv file with a wildcard", []string{"--secret-file", filepath.Join(dir, "x.env") + "=my/a#*", "--", "cmd"}, "a dotenv file needs the fields to write"},
		{"dotenv file key with a dot", []string{"--secret-file", filepath.Join(dir, "x.env") + "=my/a#a.b", "--", "cmd"}, "cannot be a key in a dotenv file"},
		{"dotenv file reserved key", []string{"--secret-file", filepath.Join(dir, "x.env") + "=my/a#AGENTRUNTIME_PAT", "--", "cmd"}, "reserved"},
		{"json file with a wildcard", []string{"--secret-file", filepath.Join(dir, "x.json") + "=my/a#*", "--", "cmd"}, "'*' is not accepted"},
		{"secret-file twice", []string{"--secret-file", filepath.Join(dir, "x.env") + "=my/a#b", "--secret-file", filepath.Join(dir, ".", "x.env") + "=my/b#c", "--", "cmd"}, "given twice"},
		{"secret-file without =", []string{"--secret-file", "x.env", "--", "cmd"}, "PATH=REF"},
		{"too many refs", append(twenty1, "--", "cmd"), "at most 20"},
		{"invalid ref is named by flag, never echoed", []string{"--env", "A=my/FAKEPASTEDVALUE123/../x#F", "--", "cmd"}, "--env A: not a valid secret reference"},
		{"shared room", []string{"--env", "A=shared/x#F", "--", "cmd"}, "shared secrets cannot be fetched yet"},
		{"wildcard in the path", []string{"--env-from", "workspace/live/*#A", "--", "cmd"}, "wildcards"},
	}
	for _, c := range cases {
		f := newFakeBFF(t)
		code, out, errOut := runSecrets(t, f, "", "run", c.args...)
		if code != ExitUsage {
			t.Errorf("%s: exit %d, want 2\n%s", c.name, code, errOut)
		}
		if !strings.Contains(errOut, c.want) {
			t.Errorf("%s: stderr lacks %q:\n%s", c.name, c.want, errOut)
		}
		if strings.Contains(out+errOut, "FAKEPASTEDVALUE123") {
			t.Errorf("%s: a mistyped reference was echoed:\n%s", c.name, errOut)
		}
		if f.count() != 0 {
			t.Errorf("%s: a usage error must not fetch", c.name)
		}
	}
}

// ---- secrets check ------------------------------------------------------------------

func TestSecretsCheck(t *testing.T) {
	isolate(t)
	f := newFakeBFF(t)

	code, out, errOut := runSecrets(t, f, "", "check",
		"secret:workspace/live/stripe#API_KEY", "my/deploy", "my/missing", "workspace/live/stripe#API_KEY")
	if code != 1 {
		t.Errorf("exit %d, want 1 (one reference does not resolve)", code)
	}
	want := "workspace/live/stripe#API_KEY: ok\nmy/deploy: ok\nmy/missing: not available\n"
	if out != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", out, want)
	}
	req := f.last()
	if !req.Check || strings.Join(req.Refs, ",") != "workspace/live/stripe#API_KEY,my/deploy,my/missing" {
		t.Errorf("request = %+v (check:true, prefix stripped, duplicates removed)", req)
	}
	assertNoValue(t, "check", out, errOut)

	code, out, _ = runSecrets(t, f, "", "check", "workspace/live/stripe#API_KEY", "my/deploy")
	if code != 0 || out != "workspace/live/stripe#API_KEY: ok\nmy/deploy: ok\n" {
		t.Errorf("all ok: code=%d out=%q", code, out)
	}
}

func TestSecretsCheckJSONIsValid(t *testing.T) {
	isolate(t)
	f := newFakeBFF(t)
	code, out, _ := runSecrets(t, f, "", "check", "--json", "my/deploy", "my/missing")
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	var got struct {
		Items []struct {
			Ref      string `json:"ref"`
			Resolves bool   `json:"resolves"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", err, out)
	}
	if len(got.Items) != 2 || !got.Items[0].Resolves || got.Items[1].Resolves || got.Items[1].Ref != "my/missing" {
		t.Errorf("items = %+v", got.Items)
	}
	assertNoValue(t, "check json", out)
}

// check takes the same REF#F1,F2 that run does, so the line that is checked is
// the line that is run.
func TestSecretsCheckTakesNamedFields(t *testing.T) {
	isolate(t)
	f := newFakeBFF(t)
	code, out, errOut := runSecrets(t, f, "", "check", "workspace/app#db_pass,API_KEY,no_such_field", "my/deploy#TOKEN")
	if code != 1 {
		t.Errorf("exit %d, want 1 (one field does not resolve)", code)
	}
	want := "workspace/app#db_pass: ok\nworkspace/app#API_KEY: ok\nworkspace/app#no_such_field: not available\nmy/deploy#TOKEN: ok\n"
	if out != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", out, want)
	}
	if got := strings.Join(f.last().Refs, ","); got != "workspace/app#db_pass,workspace/app#API_KEY,workspace/app#no_such_field,my/deploy#TOKEN" || !f.last().Check {
		t.Errorf("request = %+v", f.last())
	}
	assertNoValue(t, "check named", out, errOut)

	before := f.count()
	for name, c := range map[string]struct{ ref, want string }{
		"a wildcard":       {"workspace/app#*", "'*' is not accepted"},
		"an empty name":    {"workspace/app#db_pass,,API_KEY", "field 2 is empty"},
		"a repeated name":  {"workspace/app#db_pass,db_pass", "field 2 repeats field 1"},
		"hash and nothing": {"workspace/app#", "nothing after '#'"},
	} {
		code, _, errOut := runSecrets(t, f, "", "check", c.ref)
		if code != ExitUsage || !strings.Contains(errOut, c.want) || !strings.Contains(errOut, "argument 1") {
			t.Errorf("%s: code=%d err=%q", name, code, errOut)
		}
	}
	if f.count() != before {
		t.Error("usage errors must not call the server")
	}
}

func TestSecretsCheckUsageAndServerErrors(t *testing.T) {
	isolate(t)
	f := newFakeBFF(t)
	code, out, errOut := runSecrets(t, f, "", "check", "my/a", "my/FAKEPASTEDVALUE123/../b")
	if code != ExitUsage || !strings.Contains(errOut, "argument 2") || strings.Contains(out+errOut, "FAKEPASTEDVALUE123") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, fmt.Sprintf("my/s%d", i))
	}
	if code, _, _ := runSecrets(t, f, "", "check", many...); code != ExitUsage {
		t.Errorf("21 refs: exit %d, want 2", code)
	}
	if f.count() != 0 {
		t.Error("usage errors must not call the server")
	}

	f.override = func(bffReq) (int, string, map[string]string) {
		return 403, `{"error":"missing_scope","message":"The key lacks the scope."}`, nil
	}
	code, _, errOut = runSecrets(t, f, "", "check", "my/a")
	if code != 1 || !strings.Contains(errOut, "The key lacks the scope.") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

// ---- secrets get --print ------------------------------------------------------------

func TestSecretsGetRefusesWhenStdoutIsNotATerminal(t *testing.T) {
	isolate(t)
	f := newFakeBFF(t)
	code, out, errOut := runSecrets(t, f, "", "get", "workspace/live/stripe#API_KEY", "--print")
	if code != ExitUsage {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(errOut, "refusing to print a secret value") || !strings.Contains(errOut, "not a terminal") {
		t.Errorf("message: %q", errOut)
	}
	if out != "" {
		t.Errorf("stdout must stay empty: %q", out)
	}
	if f.count() != 0 {
		t.Error("a refused print must not fetch (it would use a key use and write an audit row)")
	}
	assertNoValue(t, "get refused", out, errOut)

	// Same with --json: still refused.
	if code, _, _ := runSecrets(t, f, "", "get", "workspace/live/stripe#API_KEY", "--print", "--json"); code != ExitUsage {
		t.Errorf("--json exit %d, want 2", code)
	}
	// Without --print there is nothing to do.
	code, _, errOut = runSecrets(t, f, "", "get", "workspace/live/stripe#API_KEY")
	if code != ExitUsage || !strings.Contains(errOut, "--print") {
		t.Errorf("no --print: code=%d err=%q", code, errOut)
	}
	if f.count() != 0 {
		t.Error("no fetch without a terminal")
	}
}

func TestSecretsGetPrintsOnATerminal(t *testing.T) {
	isolate(t)
	f := newFakeBFF(t)
	runTTY := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		app := NewApp(strings.NewReader(""), &out, &errb)
		app.isTTYOut = func() bool { return true }
		code := app.Run(append([]string{"--no-color", "--pat", testToken, "secrets", "get", "--api-url", f.URL, "--print"}, args...))
		return code, out.String(), errb.String()
	}

	code, out, errOut := runTTY("secret:workspace/live/stripe#API_KEY")
	if code != 0 || out != fakeKey+"\n" {
		t.Errorf("one field: code=%d out=%q err=%q", code, out, errOut)
	}
	if got := f.last().Refs; len(got) != 1 || got[0] != "workspace/live/stripe#API_KEY" || f.last().Check {
		t.Errorf("request = %+v", f.last())
	}

	code, out, _ = runTTY("my/deploy")
	var whole map[string]string
	if code != 0 || json.Unmarshal([]byte(out), &whole) != nil || whole["TOKEN"] != fakeTok || whole["HOST"] != "deploy-host.test" {
		t.Errorf("whole secret: code=%d out=%q", code, out)
	}

	code, out, _ = runTTY("--json", "workspace/live/stripe#API_KEY")
	var wrapped struct {
		Values map[string]string `json:"values"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &wrapped) != nil || wrapped.Values["workspace/live/stripe#API_KEY"] != fakeKey {
		t.Errorf("--json: code=%d out=%q", code, out)
	}

	// A refused or missing secret prints no value and no reason beyond the server's sentence.
	code, out, errOut = runTTY("my/missing#X")
	if code != 1 || out != "" || !strings.Contains(errOut, "not_found") {
		t.Errorf("not found: code=%d out=%q err=%q", code, out, errOut)
	}
	assertNoValue(t, "get not found", out, errOut)

	// A bad reference is a usage error and does not fetch.
	before := f.count()
	if code, _, _ := runTTY("my/a/../b"); code != ExitUsage || f.count() != before {
		t.Errorf("bad ref: code=%d, fetches %d->%d", code, before, f.count())
	}
}

// A value is text chosen by whoever can write the secret. Printed raw to a
// terminal it could move the cursor, change the title or write to the clipboard
// (OSC 52), so everything a terminal would act on is shown as \xNN instead.
func TestSecretsGetPrintEscapesWhatATerminalWouldActOn(t *testing.T) {
	isolate(t)
	f := newFakeBFF(t)
	f.put("workspace/evil", map[string]string{
		"OSC":   "ok\x1b]52;c;ZmFrZV9jbGlwYm9hcmQ=\x07tail",      // write to the clipboard
		"CSI":   "a\x1b[2J\x1b[Hb",                               // clear the screen, move the cursor
		"CR":    "visible\rhidden-by-overwrite",                  // carriage return
		"C1":    "x\xc2\x9b31my\xc2\x85z\xc2\x9d0;title\xc2\x9c", // the 8-bit forms: CSI, NEL, OSC, ST
		"DEL":   "a\x7fb",
		"NUL":   "a\x00b",
		"KEEP":  "col1\tcol2\nline2 \u00fcn\u00ef \u2713", // tab, newline and ordinary Unicode stay
		"PLAIN": "just_FAKE_text_1",
	})
	runTTY := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		app := NewApp(strings.NewReader(""), &out, &errb)
		app.isTTYOut = func() bool { return true }
		code := app.Run(append([]string{"--no-color", "--pat", testToken, "secrets", "get", "--api-url", f.URL, "--print"}, args...))
		return code, out.String(), errb.String()
	}
	// onlySafe fails the test when the output still holds anything a terminal would act on.
	onlySafe := func(what, s string) {
		t.Helper()
		for _, r := range s {
			if r == '\n' || r == '\t' {
				continue
			}
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				t.Errorf("%s: output holds the control character U+%04X: %q", what, r, s)
			}
		}
	}

	for field, want := range map[string]string{
		"OSC":   `ok\x1b]52;c;ZmFrZV9jbGlwYm9hcmQ=\x07tail`,
		"CSI":   `a\x1b[2J\x1b[Hb`,
		"CR":    `visible\x0dhidden-by-overwrite`,
		"C1":    `x\x9b31my\x85z\x9d0;title\x9c`,
		"DEL":   `a\x7fb`,
		"NUL":   `a\x00b`,
		"KEEP":  "col1\tcol2\nline2 \u00fcn\u00ef \u2713",
		"PLAIN": "just_FAKE_text_1",
	} {
		code, out, errOut := runTTY("workspace/evil#" + field)
		if code != 0 || out != want+"\n" {
			t.Errorf("%s: code=%d\nout=%q\nwant=%q\nerr=%q", field, code, out, want+"\n", errOut)
		}
		onlySafe(field, out)
		if field == "KEEP" || field == "PLAIN" {
			if errOut != "" {
				t.Errorf("%s: nothing was replaced, so no note is expected: %q", field, errOut)
			}
		} else if !strings.Contains(errOut, "control character(s)") || !strings.Contains(errOut, `\xNN`) {
			t.Errorf("%s: a note that something was replaced is expected, got %q", field, errOut)
		}
		if strings.Contains(errOut, "ZmFrZV9") {
			t.Errorf("%s: the note must not repeat the value: %q", field, errOut)
		}
	}

	// The whole secret, as JSON on the terminal, and with --json.
	for name, args := range map[string][]string{"whole": {"workspace/evil"}, "--json": {"--json", "workspace/evil"}} {
		code, out, errOut := runTTY(args...)
		if code != 0 {
			t.Fatalf("%s: code=%d err=%q", name, code, errOut)
		}
		onlySafe(name, out)
		for _, bad := range []string{"\x1b", "\xc2\x9b", "\x7f", "\r"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: output still holds %q", name, bad)
			}
		}
		// What is left is still readable: the OSC payload and the ordinary text are there.
		for _, want := range []string{"ZmFrZV9jbGlwYm9hcmQ=", "just_FAKE_text_1", `\u001b]52`} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q:\n%s", name, want, out)
			}
		}
		// DEL and the 8-bit controls are not escaped by the JSON encoder, so the terminal filter shows them.
		if !strings.Contains(out, `\x7f`) || !strings.Contains(out, `\x9b`) {
			t.Errorf("%s: DEL and C1 should be shown as \\xNN:\n%s", name, out)
		}
		if !strings.Contains(errOut, "control character(s)") {
			t.Errorf("%s: expected the note, got %q", name, errOut)
		}
	}
}

func TestTerminalSafe(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		n    int
	}{
		{"plain text", "plain text", 0},
		{"tab\tand\nnewline", "tab\tand\nnewline", 0},
		{"\x1b[31mred\x1b[0m", `\x1b[31mred\x1b[0m`, 2},
		{"a\rb", `a\x0db`, 1},
		{"a\x7fb\x00c\x08d", `a\x7fb\x00c\x08d`, 3},
		{"\xc2\x80\xc2\x9f", `\x80\x9f`, 2},                   // both ends of the C1 range
		{"\xc2\xa0 and \xc2\xa1", "\xc2\xa0 and \xc2\xa1", 0}, // U+00A0 and above are ordinary
		{"caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x98\x80", "caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x98\x80", 0},
		{"bad \xff\xfe bytes", `bad \xff\xfe bytes`, 2}, // not valid UTF-8
		{"", "", 0},
	} {
		got, n := terminalSafe(c.in)
		if got != c.want || n != c.n {
			t.Errorf("terminalSafe(%q) = %q, %d; want %q, %d", c.in, got, n, c.want, c.n)
		}
	}
}

// ---- vault set / delete / list / read ------------------------------------------------

func TestVaultSetCreateUpdateRemoveKey(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}

	// create
	code, out, errOut := run(t, "", append(base, "secrets", "set", "live/stripe", "-d", "api_key=sk_fake_1", "--create", "--scope", "tenant")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	got := srv.last("vault_secrets_upsert")
	data, _ := got["data"].(map[string]any)
	if got["mode"] != "create" || got["path"] != "live/stripe" || got["scope"] != "tenant" || data["api_key"] != "sk_fake_1" {
		t.Errorf("create request = %v", got)
	}
	if _, has := got["remove_keys"]; has {
		t.Errorf("remove_keys should be absent: %v", got)
	}

	// update: blank keeps, remove-key deletes; the old name `vault` still works
	code, out, errOut = run(t, "", append(base, "vault", "set", "live/stripe", "-d", "api_key=", "-d", "hook=new_fake", "--update", "--remove-key", "old")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	got = srv.last("vault_secrets_upsert")
	data, _ = got["data"].(map[string]any)
	keys, _ := got["remove_keys"].([]any)
	if got["mode"] != "update" || data["api_key"] != "" || data["hook"] != "new_fake" || len(keys) != 1 || keys[0] != "old" {
		t.Errorf("update request = %v", got)
	}

	// update with only a removal
	if code, _, errOut = run(t, "", append(base, "secrets", "set", "live/stripe", "--update", "--remove-key", "old")...); code != 0 {
		t.Fatalf("remove only: exit %d: %s", code, errOut)
	}
	if got = srv.last("vault_secrets_upsert"); got["mode"] != "update" {
		t.Errorf("remove-only request = %v", got)
	}

	// neither flag: whole-object replace, as before (no mode sent)
	if code, _, errOut = run(t, "", append(base, "secrets", "set", "live/stripe", "-d", "k=v")...); code != 0 {
		t.Fatalf("replace: exit %d: %s", code, errOut)
	}
	if got = srv.last("vault_secrets_upsert"); got["mode"] != nil {
		t.Errorf("replace must not send a mode: %v", got)
	}
}

func TestVaultSetUsageErrors(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken, "secrets", "set", "x/y"}
	for name, args := range map[string][]string{
		"create and update":         {"-d", "a=b", "--create", "--update"},
		"remove-key without update": {"-d", "a=b", "--remove-key", "c"},
		"no data":                   {"--create"},
		"empty remove-key":          {"--update", "--remove-key", " "},
		"set and remove same key":   {"-d", "a=b", "--update", "--remove-key", "a"},
	} {
		if code, _, errOut := run(t, "", append(append([]string{}, base...), args...)...); code != ExitUsage {
			t.Errorf("%s: exit %d, want 2 (%s)", name, code, errOut)
		}
	}
	if srv.last("vault_secrets_upsert") != nil {
		t.Error("a usage error must not reach the server")
	}
}

func TestVaultSetHelpNamesTheRooms(t *testing.T) {
	isolate(t)
	code, out, _ := run(t, "", "secrets", "set", "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"--create", "--update", "--remove-key", "user", "project", "tenant", "shared"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
}

func TestVaultSetTakesValuesFromStdinAndFiles(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}

	code, out, errOut := run(t, `{"api_key":"stdin_FAKE_value","hook":"stdin_FAKE_hook"}`,
		append(base, "secrets", "set", "live/stripe", "--data-file", "-", "--create")...)
	if code != 0 {
		t.Fatalf("stdin: exit %d\n%s\n%s", code, out, errOut)
	}
	got := srv.last("vault_secrets_upsert")
	data, _ := got["data"].(map[string]any)
	if got["mode"] != "create" || data["api_key"] != "stdin_FAKE_value" || data["hook"] != "stdin_FAKE_hook" {
		t.Errorf("stdin request = %v", got)
	}

	keyFile := filepath.Join(t.TempDir(), "api_key.txt")
	if err := os.WriteFile(keyFile, []byte("file_FAKE_value\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = run(t, "", append(base, "secrets", "set", "live/stripe", "-d", "api_key=@"+keyFile, "--update")...)
	if code != 0 {
		t.Fatalf("@file: exit %d\n%s\n%s", code, out, errOut)
	}
	got = srv.last("vault_secrets_upsert")
	data, _ = got["data"].(map[string]any)
	if data["api_key"] != "file_FAKE_value" {
		t.Errorf("@file request = %v", got)
	}
}

func TestVaultReadIsGoneAndUnknownWordsFail(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}
	for _, group := range []string{"vault", "secrets"} {
		code, _, errOut := run(t, "", append(base, group, "read", "a/b")...)
		if code != ExitUsage || !strings.Contains(errOut, "removed") {
			t.Errorf("%s read: code=%d err=%q", group, code, errOut)
		}
		code, _, errOut = run(t, "", append(base, group, "bogus")...)
		if code != ExitUsage || !strings.Contains(errOut, "unknown command") {
			t.Errorf("%s bogus: code=%d err=%q", group, code, errOut)
		}
	}
	if srv.last("vault_secret_read") != nil {
		t.Error("the removed tool must never be called")
	}
	// The group alone shows help and succeeds.
	if code, out, _ := run(t, "", "secrets"); code != 0 || !strings.Contains(out, "run") || !strings.Contains(out, "check") {
		t.Errorf("secrets alone: code=%d out=%q", code, out)
	}
}

func TestSecretsListAndDeleteViaMCP(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}

	code, out, errOut := run(t, "", append(base, "secrets", "list", "--scope", "tenant", "--path", "live", "--limit", "5", "--json")...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", err, out)
	}
	got := srv.last("vault_secrets_list")
	if got["scope"] != "tenant" || got["path"] != "live" || got["limit"] != float64(5) {
		t.Errorf("list request = %v", got)
	}
	// The old spelling still works.
	if code, _, _ := run(t, "", append(base, "vault", "ls")...); code != 0 {
		t.Errorf("vault ls: exit %d", code)
	}

	code, _, _ = run(t, "", append(base, "secrets", "delete", "a/b", "--yes", "--scope", "user")...)
	if code != 1 { // the fake server answers with an error for delete
		t.Errorf("delete exit %d, want 1", code)
	}
	if got := srv.last("vault_secrets_delete"); got["path"] != "a/b" || got["scope"] != "user" {
		t.Errorf("delete request = %v", got)
	}
}

// ---- small pieces -------------------------------------------------------------------

func TestMergeEnv(t *testing.T) {
	base := []string{"A=1", "a=2", "PATH=/bin", "=C:=C:\\dir", "EMPTY="}
	set := map[string]string{"A": "new", "Z": "z"}

	got := mergeEnv(base, set, false)
	want := []string{"a=2", "PATH=/bin", "=C:=C:\\dir", "EMPTY=", "A=new", "Z=z"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("case-sensitive: %v want %v", got, want)
	}
	got = mergeEnv(base, set, true)
	want = []string{"PATH=/bin", "=C:=C:\\dir", "EMPTY=", "A=new", "Z=z"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("case-insensitive: %v want %v", got, want)
	}
	keys := []string{envKey("A=1"), envKey("=C:=C:\\dir"), envKey("NOEQ"), envKey(""), envKey("X=a=b")}
	if strings.Join(keys, "|") != "A|=C:|NOEQ||X" {
		t.Errorf("envKey: %v", keys)
	}
	if !sort.StringsAreSorted(got[len(got)-2:]) {
		t.Errorf("added variables should be sorted: %v", got)
	}
}

// ignoreTerm makes the helper process survive SIGTERM (a no-op where it does not exist).
func ignoreTerm() { signal.Ignore(syscall.SIGTERM) }
