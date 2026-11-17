package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// Every value comes from the fake API in secrets_test.go; none is real.

const renderTemplate = `# generated
stripe = {{ secret "workspace/live/stripe#API_KEY" | quote }}
deploy = {{ secret "my/deploy#TOKEN" }}
{{- range $k, $v := fields "workspace/app" }}
app_{{ $k }} = {{ $v | quote }}
{{- end }}
db = {{ (fields "workspace/app").db_pass }}
`

// The same file as the template renders it: the names of a map come out in sorted order.
var renderExpected = "# generated\n" +
	`stripe = "` + fakeKey + `"` + "\n" +
	"deploy = " + fakeTok + "\n" +
	`app_API_KEY = "` + fakeAPIKey + `"` + "\n" +
	`app_Host = "db.example.test"` + "\n" +
	`app_db_pass = "` + fakeDBPass + `"` + "\n" +
	"db = " + fakeDBPass + "\n"

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runRender(t *testing.T, f *fakeBFF, tty bool, args ...string) (int, string, string) {
	t.Helper()
	isolate(t)
	return runApp(t, tty, nil, append([]string{"--pat", testToken, "secrets", "render", "--api-url", f.URL}, args...)...)
}

func names(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("%s: mode %v, want 0600", path, st.Mode().Perm())
	}
}

func TestRenderWritesTheFileOwnerOnlyFromOneFetch(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "app.conf.tmpl", renderTemplate)
	out := filepath.Join(dir, "app.conf")

	code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if got := mustRead(t, out); got != renderExpected {
		t.Errorf("file:\n%s\nwant:\n%s", got, renderExpected)
	}
	assertMode0600(t, out)
	if f.count() != 1 {
		t.Fatalf("%d fetch calls, want exactly 1 for every reference", f.count())
	}
	req := f.last()
	want := "workspace/live/stripe#API_KEY,my/deploy#TOKEN,workspace/app"
	if strings.Join(req.Refs, ",") != want || req.Check {
		t.Errorf("request = %+v, want refs %s and no check", req, want)
	}
	if h := f.hdrs[0]; h.Get("Authorization") != "Bearer "+testToken {
		t.Errorf("headers = %v", h)
	}
	// The CLI says what it wrote and that the file stays; it never prints a value.
	if !strings.Contains(stdout, "Wrote "+out) || !strings.Contains(stdout, "stays on disk") || !strings.Contains(stdout, "3 secret reference(s)") {
		t.Errorf("stdout: %q", stdout)
	}
	if stderr != "" {
		t.Errorf("a quiet render should print nothing on stderr: %q", stderr)
	}
	assertNoValue(t, "render", stdout, stderr)
	if names(t, dir) != "app.conf,app.conf.tmpl" {
		t.Errorf("files in the folder: %s", names(t, dir))
	}
}

func TestRenderJSONSummaryIsValidAndHasNoValue(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", renderTemplate)
	out := filepath.Join(dir, "app.conf")
	code, stdout, stderr := runRender(t, f, false, tpl, "--output", out, "--json")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	m := mustJSON(t, "render --json", stdout)
	if m["written"] != out || m["replaced"] != false || m["references"] != float64(3) || m["bytes"] != float64(len(renderExpected)) {
		t.Errorf("json %v", m)
	}
	assertNoValue(t, "render json", stdout, stderr)
}

func TestRenderNeverOverwritesAnExistingFile(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", renderTemplate)
	out := writeFile(t, dir, "app.conf", "ORIGINAL\n")

	code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
	if code != ExitUsage || !strings.Contains(stderr, "already exists") || !strings.Contains(stderr, "--replace") {
		t.Errorf("code=%d err=%q", code, stderr)
	}
	if got := mustRead(t, out); got != "ORIGINAL\n" {
		t.Errorf("an existing file was changed: %q", got)
	}
	if f.count() != 0 {
		t.Error("a refused render must not fetch (a one-time key has one use)")
	}
	assertNoValue(t, "no overwrite", stdout, stderr)

	// A folder or a link in the way is also "exists".
	sub := filepath.Join(dir, "folder")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runRender(t, f, false, tpl, "--output", sub); code != ExitUsage || !strings.Contains(stderr, "already exists") {
		t.Errorf("folder: code=%d err=%q", code, stderr)
	}
	if f.count() != 0 {
		t.Error("no fetch")
	}
}

func TestRenderReplaceReplacesAtomicallyAndLeavesNothingBehind(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", renderTemplate)
	out := writeFile(t, dir, "app.conf", "ORIGINAL\n")
	if runtime.GOOS != "windows" {
		if err := os.Chmod(out, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	code, stdout, stderr := runRender(t, f, false, tpl, "--output", out, "--replace")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if got := mustRead(t, out); got != renderExpected {
		t.Errorf("file:\n%s", got)
	}
	assertMode0600(t, out) // the old 0644 does not carry over to a file that holds secrets
	if !strings.Contains(stdout, "Replaced "+out) {
		t.Errorf("stdout: %q", stdout)
	}
	if names(t, dir) != "app.conf,t.tmpl" {
		t.Errorf("a temporary file was left behind: %s", names(t, dir))
	}
	assertNoValue(t, "replace", stdout, stderr)

	// --json says it was a replacement.
	code, stdout, _ = runRender(t, f, false, tpl, "--output", out, "--replace", "--json")
	if m := mustJSON(t, "replace --json", stdout); code != 0 || m["replaced"] != true {
		t.Errorf("code=%d json=%v", code, m)
	}
	// --replace with nothing there just creates the file.
	fresh := filepath.Join(dir, "new.conf")
	if code, stdout, _ := runRender(t, f, false, tpl, "--output", fresh, "--replace"); code != 0 || !strings.Contains(stdout, "Wrote "+fresh) {
		t.Errorf("fresh: code=%d stdout=%q", code, stdout)
	}
	assertMode0600(t, fresh)
}

// All or nothing: a reference the server will not resolve means nothing is written, and an existing file stays.
func TestRenderIsAllOrNothing(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", `a = {{ secret "workspace/live/stripe#API_KEY" }}
b = {{ secret "my/missing#X" }}
`)
	out := filepath.Join(dir, "app.conf")
	code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
	if code != ExitError || !strings.Contains(stderr, "not_found") {
		t.Errorf("code=%d err=%q", code, stderr)
	}
	if exists(out) {
		t.Error("one unresolved reference must stop everything: no file")
	}
	if f.count() != 1 {
		t.Errorf("%d calls, want 1", f.count())
	}
	assertNoValue(t, "all or nothing", stdout, stderr)

	// With --replace the old file is still there, untouched, and nothing is left beside it.
	writeFile(t, dir, "app.conf", "ORIGINAL\n")
	if code, _, _ := runRender(t, f, false, tpl, "--output", out, "--replace"); code != ExitError {
		t.Errorf("replace: code=%d", code)
	}
	if got := mustRead(t, out); got != "ORIGINAL\n" {
		t.Errorf("the old file changed: %q", got)
	}
	if names(t, dir) != "app.conf,t.tmpl" {
		t.Errorf("files: %s", names(t, dir))
	}
}

func TestRenderServerErrorCodes(t *testing.T) {
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
		{"ambiguous_ref", 409, nil, `{"error":"ambiguous_ref","message":"Ambiguous.","rooms":["my","workspace"]}`, []string{"Ambiguous.", "my, workspace"}},
		{"uses_exhausted", 403, nil, `{"error":"uses_exhausted","message":"No uses left."}`, []string{"No uses left.", "(uses_exhausted)"}},
		{"rate_limited", 429, map[string]string{"Retry-After": "17"}, `{"error":"rate_limited","message":"Slow down."}`, []string{"Slow down.", "17 seconds"}},
		{"bad_ref", 400, nil, `{"error":"bad_ref","message":"Not valid."}`, []string{"Not valid.", "(bad_ref)"}},
		{"too_large", 413, nil, `{"error":"too_large","message":"Too much."}`, []string{"Too much.", "(too_large)"}},
		{"audit_failed", 503, nil, `{"error":"audit_failed","message":"Not recorded."}`, []string{"Not recorded.", "(audit_failed)"}},
		{"401", 401, nil, ``, []string{"HTTP 401", "agentruntime login"}},
	}
	for _, c := range cases {
		f := newFakeBFF(t)
		f.override = func(bffReq) (int, string, map[string]string) { return c.status, c.body, c.header }
		dir := t.TempDir()
		tpl := writeFile(t, dir, "t.tmpl", renderTemplate)
		out := filepath.Join(dir, "app.conf")
		code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
		if code != ExitError {
			t.Errorf("%s: exit %d, want 1", c.code, code)
		}
		for _, w := range c.want {
			if !strings.Contains(stderr, w) {
				t.Errorf("%s: stderr lacks %q:\n%s", c.code, w, stderr)
			}
		}
		if stdout != "" || exists(out) {
			t.Errorf("%s: no output and no file on a refused fetch (stdout %q)", c.code, stdout)
		}
		if f.count() != 1 {
			t.Errorf("%s: %d calls, want 1", c.code, f.count())
		}
		assertNoValue(t, c.code, stdout, stderr)
	}
}

func TestRenderRefusesAnAnswerThatSkipsAReference(t *testing.T) {
	f := newFakeBFF(t)
	f.override = func(r bffReq) (int, string, map[string]string) {
		return 200, fmt.Sprintf(`{"values":{%q:%q}}`, r.Refs[0], fakeKey), nil
	}
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", renderTemplate)
	out := filepath.Join(dir, "app.conf")
	code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
	if code != ExitError || !strings.Contains(stderr, "did not answer for every reference") || exists(out) {
		t.Errorf("code=%d err=%q file=%v", code, stderr, exists(out))
	}
	assertNoValue(t, "incomplete", stdout, stderr)
}

// A dynamic reference is refused before anything is fetched or written.
func TestRenderRefusesDynamicReferencesBeforeAnyCall(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	for name, src := range map[string]string{
		"variable":        `{{ $r := "workspace/live/stripe#API_KEY" }}{{ secret $r }}`,
		"printf":          `{{ secret (printf "workspace/live/%s#API_KEY" "stripe") }}`,
		"piped printf":    `{{ printf "workspace/live/stripe#%s" "API_KEY" | secret }}`,
		"field of dot":    `{{ secret .Ref }}`,
		"fields by value": `{{ fields (secret "my/deploy#TOKEN") }}`,
		"in a define":     `{{ define "x" }}{{ secret .R }}{{ end }}{{ template "x" . }}`,
	} {
		tpl := writeFile(t, dir, "t.tmpl", src)
		out := filepath.Join(dir, "out.conf")
		code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
		if code != ExitUsage || !strings.Contains(stderr, "quoted") || stdout != "" {
			t.Errorf("%s: code=%d stdout=%q err=%q", name, code, stdout, stderr)
		}
		if exists(out) {
			t.Errorf("%s: a file was written", name)
		}
	}
	if f.count() != 0 {
		t.Errorf("%d calls: nothing may be fetched for a template that is refused", f.count())
	}
}

func TestRenderRefusesMoreThanTwentyReferencesBeforeAnyCall(t *testing.T) {
	f := newFakeBFF(t)
	var body21, body20 strings.Builder
	for i := 1; i <= 21; i++ {
		f.put(fmt.Sprintf("workspace/many/s%02d", i), map[string]string{"V": fmt.Sprintf("manyvalue_FAKE_%02d", i)})
		line := fmt.Sprintf("v%02d = {{ secret \"workspace/many/s%02d#V\" }}\n", i, i)
		body21.WriteString(line)
		if i <= 20 {
			body20.WriteString(line)
		}
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out.conf")

	tpl := writeFile(t, dir, "t21.tmpl", body21.String())
	code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
	if code != ExitUsage || !strings.Contains(stderr, "at most 20 different references") || !strings.Contains(stderr, "got 21") || stdout != "" {
		t.Errorf("21 refs: code=%d stdout=%q err=%q", code, stdout, stderr)
	}
	if f.count() != 0 || exists(out) {
		t.Errorf("21 refs: %d calls, file %v: refused before any call", f.count(), exists(out))
	}

	// Twenty is fine, in one call; the same reference named twice counts once.
	tpl = writeFile(t, dir, "t20.tmpl", body20.String()+`again = {{ secret "workspace/many/s01#V" }}`+"\n")
	if code, stdout, stderr := runRender(t, f, false, tpl, "--output", out); code != 0 {
		t.Fatalf("20 refs: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if f.count() != 1 || len(f.last().Refs) != 20 {
		t.Errorf("20 refs: %d calls, %d refs in the call", f.count(), len(f.last().Refs))
	}
	got := mustRead(t, out)
	if !strings.Contains(got, "v20 = manyvalue_FAKE_20\n") || !strings.HasSuffix(got, "again = manyvalue_FAKE_01\n") {
		t.Errorf("file:\n%s", got)
	}
}

func TestRenderMissingFieldsAreErrorsAndNothingIsWritten(t *testing.T) {
	for name, src := range map[string]string{
		"field syntax": `{{ (fields "workspace/app").nope }}`,
		"index":        `{{ index (fields "workspace/app") "nope" }}`,
		"dot":          `{{ secret "my/pin#PIN" }}{{ .Anything }}`,
		"secret field": `{{ secret "workspace/app#nope" }}`,
	} {
		f := newFakeBFF(t)
		dir := t.TempDir()
		tpl := writeFile(t, dir, "t.tmpl", "x = "+src+"\n")
		out := filepath.Join(dir, "out.conf")
		code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
		if code != ExitError || exists(out) || stdout != "" {
			t.Errorf("%s: code=%d stdout=%q file=%v err=%q", name, code, stdout, exists(out), stderr)
		}
		assertNoValue(t, name, stdout, stderr)
	}
}

func TestRenderRangeOverFieldsIsSortedAndComplete(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", `{{ range $k, $v := fields "workspace/app" }}{{ $k }};{{ end }}`)
	out := filepath.Join(dir, "out.conf")
	if code, stdout, stderr := runRender(t, f, false, tpl, "--output", out); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if got := mustRead(t, out); got != "API_KEY;Host;db_pass;" {
		t.Errorf("file %q", got)
	}
	if req := f.last(); len(req.Refs) != 1 || req.Refs[0] != "workspace/app" {
		t.Errorf("request %+v: a whole secret is one reference", req)
	}
}

func TestRenderHelperFunctions(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", `{{ secret "workspace/special#P" | json }}
{{ secret "my/pin#PIN" | b64enc }}
{{ secret "my/pin#PIN" | quote }}
{{ fields "my/deploy" | json }}
{{ "{{" }} literal
`)
	out := filepath.Join(dir, "out.conf")
	if code, stdout, stderr := runRender(t, f, false, tpl, "--output", out); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	want := `"` + fakeSpecial + `"` + "\n" + // json does not escape <, > or & (this is not HTML)
		"MTJhYg==\n" +
		`"12ab"` + "\n" +
		`{"HOST":"deploy-host.test","TOKEN":"` + fakeTok + `"}` + "\n" +
		"{{ literal\n"
	if got := mustRead(t, out); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
}

// The engine can quote a value in an error (ranging over a string). Nothing of the engine's text reaches the person:
// the error is a fixed sentence and the line, so no value can be in it, however short (a one- or two-character value
// is no longer left in by a masker that cannot tell it from ordinary text).
func TestRenderErrorMessagesNeverQuoteAValue(t *testing.T) {
	for _, ref := range []string{"workspace/live/stripe#API_KEY", "my/pin#PIN", "workspace/tiny#ONE", "workspace/tiny#TWO"} {
		f := newFakeBFF(t)
		f.put("workspace/tiny", map[string]string{"ONE": "z", "TWO": "zq"})
		dir := t.TempDir()
		tpl := writeFile(t, dir, "t.tmpl", fmt.Sprintf("first line\n{{ range (secret %q) }}x{{ end }}\n", ref))
		out := filepath.Join(dir, "out.conf")
		code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
		if code != ExitError || exists(out) {
			t.Errorf("%s: code=%d file=%v", ref, code, exists(out))
		}
		if strings.Contains(stderr, fakeKey) || strings.Contains(stderr, fakeShort) || strings.Contains(stderr, "zq") || strings.Contains(stdout, fakeKey) {
			t.Errorf("%s: a value is in the output: %q", ref, stderr)
		}
		want := "error: the template failed at line 2: range was used on text; to loop over the fields of a secret, range over fields \"REF\"\n"
		if stderr != want {
			t.Errorf("%s: stderr %q, want the fixed sentence %q", ref, stderr, want)
		}
	}
}

// What can be refused without a value is refused when the template is read, so the fetch (which spends a one-use key)
// never happens for a template that would not finish.
func TestRenderRefusesExplosiveTemplatesBeforeTheFetch(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out.conf")
	for name, src := range map[string]string{
		"range over 3 billion":     `{{ range 3000000000 }}{{ end }}`,
		"nested number loops":      `{{ range 5000 }}{{ range 5000 }}{{ end }}{{ end }}`,
		"printf with a huge width": `{{ printf "%999999999d" 1 }}`,
		"printf with a star":       `{{ printf "%*d" 99999999 1 }}`,
	} {
		tpl := writeFile(t, dir, "t.tmpl", `key = {{ secret "workspace/live/stripe#API_KEY" }}`+"\n"+src+"\n")
		code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "line 2") {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
		if exists(out) {
			t.Errorf("%s: a file was written", name)
		}
		assertNoValue(t, name, stdout, stderr)
	}
	if f.count() != 0 {
		t.Errorf("%d calls: nothing may be fetched for a template that would not finish", f.count())
	}
}

// Whatever the static checks cannot see (a format built from a variable, a string that a loop doubles) is stopped
// while the template runs: fast, with a fixed sentence, and with nothing written.
func TestRenderStopsWhatOnlyShowsWhileItRuns(t *testing.T) {
	f := newFakeBFF(t)
	kb := strings.Repeat("x", 1024)
	for name, src := range map[string]string{
		"format from a variable": `{{ $f := "%999999999d" }}{{ printf $f 1 }}`,
		"a doubling string":      `{{ $s := "` + kb + `" }}{{ range 12 }}{{ $s = printf "%s%s" $s $s }}{{ end }}{{ len $s }}`,
	} {
		dir := t.TempDir()
		tpl := writeFile(t, dir, "t.tmpl", `k = {{ secret "workspace/live/stripe#API_KEY" }}`+"\n"+src+"\n")
		out := filepath.Join(dir, "out.conf")
		start := time.Now()
		code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
		took := time.Since(start)
		if code != ExitError || stdout != "" || exists(out) || !strings.HasPrefix(stderr, "error: the template failed at line 2: ") {
			t.Errorf("%s: code=%d stdout=%q file=%v stderr=%q", name, code, stdout, exists(out), stderr)
		}
		if took > 5*time.Second {
			t.Errorf("%s: took %v", name, took)
		}
		assertNoValue(t, name, stdout, stderr)
	}
}

// --output - shows the result on a terminal and nowhere else.
func TestRenderToTheTerminalOnly(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", renderTemplate)

	// Piped or redirected: refused before anything is fetched.
	code, stdout, stderr := runRender(t, f, false, tpl, "--output", "-")
	if code != ExitUsage || !strings.Contains(stderr, "not a terminal") || stdout != "" {
		t.Errorf("piped: code=%d stdout=%q err=%q", code, stdout, stderr)
	}
	if f.count() != 0 {
		t.Error("a refused print must not fetch")
	}
	assertNoValue(t, "piped", stdout, stderr)

	// On a terminal: the rendered text is printed, and nothing is written.
	isolate(t)
	t.Chdir(dir)
	code, stdout, stderr = runApp(t, true, nil, "--pat", testToken, "secrets", "render", "--api-url", f.URL, tpl, "--output", "-")
	if code != 0 || stdout != renderExpected {
		t.Errorf("terminal: code=%d stdout=%q err=%q", code, stdout, stderr)
	}
	if names(t, dir) != "t.tmpl" {
		t.Errorf("files in the folder: %s", names(t, dir))
	}

	// Flags that make no sense with it.
	n := f.count()
	for _, extra := range [][]string{{"--replace"}, {"--json"}} {
		args := append([]string{"--pat", testToken, "secrets", "render", "--api-url", f.URL, tpl, "--output", "-"}, extra...)
		if code, _, stderr := runApp(t, true, nil, args...); code != ExitUsage || stderr == "" {
			t.Errorf("%v: code=%d err=%q", extra, code, stderr)
		}
	}
	if f.count() != n {
		t.Error("no fetch for a flag combination that is refused")
	}
}

// What a terminal would act on is shown as \xNN, as with `get --print`.
func TestRenderToTheTerminalEscapesControlCharacters(t *testing.T) {
	f := newFakeBFF(t)
	f.put("workspace/evil", map[string]string{"OSC": "ok\x1b]52;c;ZmFrZV9jbGlwYm9hcmQ=\x07tail"})
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", `{{ secret "workspace/evil#OSC" }}`+"\n")
	isolate(t)
	code, stdout, stderr := runApp(t, true, nil, "--pat", testToken, "secrets", "render", "--api-url", f.URL, tpl, "--output", "-")
	if code != 0 || strings.ContainsAny(stdout, "\x1b\x07") || !strings.Contains(stdout, `ok\x1b]52;c;ZmFrZV9jbGlwYm9hcmQ=\x07tail`) {
		t.Errorf("code=%d stdout=%q", code, stdout)
	}
	if !strings.Contains(stderr, "control character(s)") {
		t.Errorf("stderr: %q", stderr)
	}
}

func TestRenderUsageErrorsBeforeAnyCall(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", renderTemplate)
	plain := writeFile(t, dir, "plain.tmpl", "no secrets here\n")
	big := writeFile(t, dir, "big.tmpl", strings.Repeat("x", (1<<20)+1))
	bad := writeFile(t, dir, "bad.tmpl", "\xff\xfe not utf-8 {{ secret \"my/a#b\" }}")
	broken := writeFile(t, dir, "broken.tmpl", `{{ secret "my/a#b" `)
	badRef := writeFile(t, dir, "badref.tmpl", `{{ secret "workspace/a/../b#c" }}`)
	sub := filepath.Join(dir, "folder")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.conf")
	cases := map[string]struct {
		args []string
		want string
	}{
		"no output":              {[]string{tpl}, "--output is required"},
		"missing template":       {[]string{filepath.Join(dir, "nope.tmpl"), "--output", out}, "cannot read the template"},
		"template is a dir":      {[]string{sub, "--output", out}, "regular file"},
		"too large":              {[]string{big, "--output", out}, "larger than 1 MiB"},
		"not utf-8":              {[]string{bad, "--output", out}, "not valid UTF-8"},
		"no references":          {[]string{plain, "--output", out}, "nothing to fetch"},
		"parse error":            {[]string{broken, "--output", out}, "unclosed action"},
		"bad reference":          {[]string{badRef, "--output", out}, "'.' and '..'"},
		"missing folder":         {[]string{tpl, "--output", filepath.Join(dir, "nope", "out.conf")}, "folder does not exist"},
		"output is the template": {[]string{tpl, "--output", tpl, "--replace"}, "is the template itself"},
		"replace a folder":       {[]string{tpl, "--output", sub, "--replace"}, "not a regular file"},
	}
	for name, c := range cases {
		code, stdout, stderr := runRender(t, f, false, c.args...)
		if code != ExitUsage || !strings.Contains(stderr, c.want) || stdout != "" {
			t.Errorf("%s: code=%d stdout=%q err=%q (want %q)", name, code, stdout, stderr, c.want)
		}
	}
	// The command takes exactly one template (cobra's own check, so the usual exit code 1).
	for name, args := range map[string][]string{"two templates": {tpl, tpl, "--output", out}, "no template": {"--output", out}} {
		if code, _, stderr := runRender(t, f, false, args...); code == 0 || !strings.Contains(stderr, "accepts 1 arg") {
			t.Errorf("%s: code=%d err=%q", name, code, stderr)
		}
	}
	if f.count() != 0 {
		t.Errorf("%d calls: every one of these is wrong before the server is asked", f.count())
	}
	if got := mustRead(t, tpl); got != renderTemplate {
		t.Errorf("the template was changed: %q", got)
	}
	if exists(out) {
		t.Error("an output file was written")
	}
}

func TestRenderDoesNotFollowALinkWithReplace(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", renderTemplate)
	real := writeFile(t, dir, "real.conf", "REAL\n")
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot make a symbolic link here: %v", err)
	}
	for _, extra := range [][]string{{"--replace"}, {}} {
		code, _, stderr := runRender(t, f, false, append([]string{tpl, "--output", link}, extra...)...)
		if code != ExitUsage {
			t.Errorf("%v: code=%d err=%q", extra, code, stderr)
		}
	}
	if got := mustRead(t, real); got != "REAL\n" {
		t.Errorf("the file behind the link changed: %q", got)
	}
	if f.count() != 0 {
		t.Error("no fetch")
	}
}

func TestRenderNeedsALoginAndASafeAddress(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	tpl := writeFile(t, dir, "t.tmpl", renderTemplate)
	out := filepath.Join(dir, "out.conf")
	isolate(t)
	code, _, stderr := runApp(t, false, nil, "secrets", "render", "--api-url", f.URL, tpl, "--output", out)
	if code != 1 || !strings.Contains(stderr, "agentruntime login") {
		t.Errorf("not logged in: code=%d err=%q", code, stderr)
	}
	code, _, stderr = runApp(t, false, nil, "--pat", testToken, "secrets", "render", "--api-url", "http://203.0.113.9:8080", tpl, "--output", out)
	if code != 1 || !strings.Contains(stderr, "plain http") {
		t.Errorf("plain http: code=%d err=%q", code, stderr)
	}
	if f.count() != 0 || exists(out) {
		t.Error("nothing may be fetched or written")
	}
}

func TestRenderHelpIsHonestAboutWhatItLeavesBehind(t *testing.T) {
	isolate(t)
	_, out, _ := run(t, "", "secrets", "render", "--help")
	out = flat(out)
	for _, want := range []string{
		"STAYS on disk", "that is its purpose", "'secrets run --secret-file' is the one that removes its file",
		"never overwritten", "--replace replaces an existing regular file", "renamed over it", "A link or a folder is refused",
		"owner-only permissions (0600 on macOS and Linux; on Windows it keeps the permissions of its folder)",
		"quoted string in the template", "at most 20 different references", "all or nothing", "nothing is written",
		"only when standard output is a terminal", "exit code 2", "{{ \"{{\" }}", "A name that is not in the secret is an error",
		"secret \"REF#FIELD\"", "fields \"REF\"", "b64enc", "quote", "json",
		"A template runs after the fetch, when a one-use key is already spent", "calls itself (directly or through other templates)",
		"calls a template that is not defined in the file", "more than 50 deep", "more than 100 deep in a row", "a number above 1000000 inside {{ }}",
		"a verb that does not end in a letter", "all the text they build at 16 MiB", "refuse a map of fields as an argument", "stops after 10 seconds",
		"That is not a promise about every template's memory or time", "runs until the 10 seconds are up", "keeps going in the background until the command exits",
		"fixed sentence and the line number", "none of it is shown",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render --help lacks %q", want)
		}
	}
}

// A template that calls itself overflows the stack of the program, which nothing can catch, and a call to a template
// that does not exist fails only when the run reaches it. Both would happen after the fetch, so both are refused when
// the template is read: nothing is fetched, nothing is written.
func TestRenderRefusesRecursiveAndMissingTemplatesBeforeTheFetch(t *testing.T) {
	f := newFakeBFF(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out.conf")
	// The ~900-byte template that took the program down: a define that calls itself under 40 nested ifs.
	repro := `{{ define "a" }}` + strings.Repeat(`{{ if true }}`, 40) + `{{ template "a" }}` + strings.Repeat(`{{ end }}`, 40) + `{{ end }}{{ template "a" }}`
	for name, src := range map[string]string{
		"the repro":                       repro,
		"self call":                       `{{ define "a" }}{{ template "a" }}{{ end }}{{ template "a" }}`,
		"mutual":                          `{{ define "a" }}{{ template "b" }}{{ end }}{{ define "b" }}{{ template "a" }}{{ end }}{{ template "a" }}`,
		"a typo":                          `{{ define "header" }}x{{ end }}{{ template "heder" }}`,
		"a call in a loop":                `{{ range 2 }}{{ template "missing" }}{{ end }}`,
		"the format that slipped through": `{{ printf "%1+%999999d" 1 1 }}`,
	} {
		tpl := writeFile(t, dir, "t.tmpl", `key = {{ secret "workspace/live/stripe#API_KEY" }}`+"\n"+src+"\n")
		code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "line 2") {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
		if exists(out) {
			t.Errorf("%s: a file was written", name)
		}
		assertNoValue(t, name, stdout, stderr)
	}
	if f.count() != 0 {
		t.Errorf("%d calls: nothing may be fetched for a template that would not finish or names a template that is not there", f.count())
	}
	// A template that calls another one and ends is fine, and fetches once.
	tpl := writeFile(t, dir, "ok.tmpl", `{{ define "line" }}key = {{ secret "workspace/live/stripe#API_KEY" }}{{ end }}{{ template "line" }}`+"\n")
	if code, stdout, stderr := runRender(t, f, false, tpl, "--output", out); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if got := mustRead(t, out); got != "key = "+fakeKey+"\n" || f.count() != 1 {
		t.Errorf("file %q after %d calls", got, f.count())
	}
}

// What only shows while the template runs is stopped there, after the fetch, with a fixed sentence and nothing written:
// a map of fields given to printf, and more text than the total allows.
func TestRenderStopsAMapInPrintfAndTheTotalBudgetWhileItRuns(t *testing.T) {
	f := newFakeBFF(t)
	chunk := strings.Repeat("x", 256<<10)
	for name, src := range map[string]string{
		"a map with a width": `{{ printf "%4096v" (fields "workspace/app") }}`,
		"the total of text":  `{{ $b := "` + chunk + `" }}{{ range 70 }}{{ $x := printf "%s" $b }}{{ end }}`,
	} {
		dir := t.TempDir()
		tpl := writeFile(t, dir, "t.tmpl", `k = {{ secret "workspace/live/stripe#API_KEY" }}`+"\n"+src+"\n")
		out := filepath.Join(dir, "out.conf")
		start := time.Now()
		code, stdout, stderr := runRender(t, f, false, tpl, "--output", out)
		if code != ExitError || stdout != "" || exists(out) || !strings.HasPrefix(stderr, "error: the template failed at line 2: ") {
			t.Errorf("%s: code=%d stdout=%q file=%v stderr=%q", name, code, stdout, exists(out), stderr)
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("%s: took %v", name, time.Since(start))
		}
		assertNoValue(t, name, stdout, stderr)
	}
}
