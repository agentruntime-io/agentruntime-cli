package secrets

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestFormatForPath(t *testing.T) {
	for in, want := range map[string]FileFormat{
		".env":              FormatDotenv,
		"app.env":           FormatDotenv,
		"/x/y/prod.ENV":     FormatDotenv,
		`C:\x\.env`:         FormatDotenv,
		"creds.json":        FormatJSON,
		"/tmp/a.b.JSON":     FormatJSON,
		"./relative/a.json": FormatJSON,
	} {
		got, err := FormatForPath(in)
		if err != nil || got != want {
			t.Errorf("%q => %v, %v (want %v)", in, got, err, want)
		}
	}
	for _, bad := range []string{"secrets", "secrets.txt", ".env.local", "env", "a.yaml", ""} {
		if _, err := FormatForPath(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestRenderDotenv(t *testing.T) {
	got, err := RenderDotenv(map[string]string{
		"ZED":     "plain-value_1.2",
		"API_KEY": "sk_fake_0123456789",
		"EMPTY":   "",
		"SPACED":  "has space",
		"DOLLAR":  "pa$$word",
		"HOME_":   "$HOME",
		"TICK":    "`id`",
		"HASH":    "a#b",
		"QUOTE":   "it's",
		"APOSBS":  `it's a\b`,
		"TRAIL":   `abc\`,
		"TWOBS":   `a\\b`,
		"MULTI":   "line1\nline2",
		"MIXED":   "a\"b\\c\nd",
		"DQUOTE":  `say "hi"`,
		"URL":     "https://x.test/a?b=c",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		`API_KEY=sk_fake_0123456789`,
		`APOSBS="it's a\\b"`,
		`DOLLAR='pa$$word'`,
		`DQUOTE='say "hi"'`,
		`EMPTY=""`,
		`HASH='a#b'`,
		`HOME_='$HOME'`,
		`MIXED='a"b\c`,
		`d'`,
		`MULTI='line1`,
		`line2'`,
		`QUOTE="it's"`,
		`SPACED='has space'`,
		`TICK='` + "`id`" + `'`,
		`TRAIL="abc\\"`,
		`TWOBS="a\\\\b"`,
		`URL='https://x.test/a?b=c'`,
		`ZED=plain-value_1.2`,
	}, "\n") + "\n"
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// dotenvValues is every value a dotenv file is expected to carry intact.
var dotenvValues = []string{
	"plain", "", "with space", "it's", "line1\nline2", "q\"uote\\back", "$HOME and $X", "#not-a-comment",
	"tab\there", "ünïcödé ✓", "trailing ", " leading", `abc\`, `a\\b`, `it's a\b`, `it's "quoted"` + `\\`,
	"pa$$word", "`id`", "$(id)", "$", `a\$HOME`, "50%", "a=b", "a,b:c/d@e+f",
	"-----BEGIN KEY-----\nMIIB+/=\nabc==\n-----END KEY-----", "a\nb\n", "\n", `say "hi"`, "a!b", "a\\\nb",
}

// parseDotenv reads back what RenderDotenv writes. It follows the rules that
// bash (`source`), docker compose and python-dotenv were all found to share for
// the forms RenderDotenv uses (bash 5.2, docker compose 5.6, python-dotenv 1.2,
// checked on 2026-11-16): bare to the end of the line; single quotes literal up
// to the next '; double quotes closed by the first " that is not escaped, with
// only \\ and \" as escapes.
func parseDotenv(t *testing.T, data string) map[string]string {
	t.Helper()
	out := map[string]string{}
	rest := data
	for rest != "" {
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			t.Fatalf("no '=' in %q", rest)
		}
		var val string
		switch {
		case strings.HasPrefix(after, `"`):
			var sb strings.Builder
			i := 1
		loop:
			for ; i < len(after); i++ {
				switch after[i] {
				case '\\':
					i++
					if after[i] != '\\' && after[i] != '"' {
						t.Fatalf("an escape this writer never produces: \\%c in %q", after[i], after)
					}
					sb.WriteByte(after[i])
				case '"':
					break loop
				default:
					sb.WriteByte(after[i])
				}
			}
			val, rest = sb.String(), strings.TrimPrefix(after[i+1:], "\n")
		case strings.HasPrefix(after, "'"):
			end := strings.Index(after[1:], "'")
			val, rest = after[1:1+end], strings.TrimPrefix(after[end+2:], "\n")
		default:
			line, r, _ := strings.Cut(after, "\n")
			val, rest = line, r
		}
		out[key] = val
	}
	return out
}

func TestRenderDotenvRoundTrips(t *testing.T) {
	in := map[string]string{}
	for i, v := range dotenvValues {
		in["K"+string(rune('A'+i/26))+string(rune('a'+i%26))] = v
	}
	b, err := RenderDotenv(in)
	if err != nil {
		t.Fatal(err)
	}
	got := parseDotenv(t, string(b))
	if len(got) != len(in) {
		t.Fatalf("got %d keys, want %d:\n%s", len(got), len(in), b)
	}
	for k, v := range in {
		if got[k] != v {
			t.Errorf("%s: got %q want %q\nfile:\n%s", k, got[k], v, b)
		}
	}
}

// findBash returns a real bash, or skips the test. On Windows only Git's bash is
// used: `bash` on the PATH is often the WSL launcher.
func findBash(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramW6432")} {
			if root == "" {
				continue
			}
			p := filepath.Join(root, "Git", "usr", "bin", "bash.exe")
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		t.Skip("no Git bash found")
	}
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on PATH")
	}
	return p
}

// A real `source` must read every value back unchanged, and must never run or
// expand anything in it.
func TestRenderDotenvIsSafeForBashSource(t *testing.T) {
	bash := findBash(t)
	dir := t.TempDir()
	in := map[string]string{}
	var keys []string
	for i, v := range dotenvValues {
		k := "K" + string(rune('A'+i/26)) + string(rune('a'+i%26))
		in[k] = v
		keys = append(keys, k)
	}
	// Values that bash would run or expand if they were quoted the old way.
	marker := filepath.Join(dir, "pwned")
	for k, v := range map[string]string{
		"KX1": "$(touch pwned)",
		"KX2": "`touch pwned`",
		"KX3": "it's fine; touch pwned",
		"KX4": "$HOME/$((1+1))",
		"KX5": "x\" ; touch pwned ; \"y",
	} {
		in[k] = v
		keys = append(keys, k)
	}
	b, err := RenderDotenv(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "t.env"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	sort.Strings(keys)
	var args []string
	for _, k := range keys {
		args = append(args, `"$`+k+`"`)
	}
	cmd := exec.Command(bash, "-c", `. ./t.env; printf '%s\0' `+strings.Join(args, " "))
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, b)
	}
	parts := strings.Split(string(out), "\x00")
	if len(parts) != len(keys)+1 {
		t.Fatalf("bash printed %d values, want %d\nfile:\n%s", len(parts)-1, len(keys), b)
	}
	for i, k := range keys {
		if parts[i] != in[k] {
			t.Errorf("%s: bash read %q, want %q", k, parts[i], in[k])
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("sourcing the file ran a command from a value")
	}
}

func TestRenderDotenvRefusesWhatTheReadersDisagreeOn(t *testing.T) {
	for _, v := range []string{
		"it's $(id)",                 // ' and $: no quote form is read the same by bash and python-dotenv
		"it's `id`",                  // ' and a backtick
		"${HOME}",                    // python-dotenv expands ${...} in every quoting style
		`a\\$b`,                      // two backslashes and $
		`pw$` + `\`,                  // trailing backslash and $
		"it's ${X}",                  // both
		"a\x00b", "a\rb", "a\r\nb\n", // NUL and carriage returns, always
	} {
		_, err := RenderDotenv(map[string]string{"SECRET_FIELD": "FAKE_PREFIX_" + v})
		if err == nil {
			t.Errorf("%q should be refused", v)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, `"SECRET_FIELD"`) || !strings.Contains(msg, ".json") {
			t.Errorf("%q: the message should name the field and point to JSON: %s", v, msg)
		}
		if strings.Contains(msg, "FAKE_PREFIX_") || strings.Contains(msg, "id`") || strings.Contains(msg, "HOME") {
			t.Errorf("%q: the message contains part of the value: %s", v, msg)
		}
	}
	// The same values are fine in a JSON file.
	if _, err := RenderJSON(map[string]string{"SECRET_FIELD": "it's $(id)\r\x00"}); err != nil {
		t.Errorf("JSON has no such limit: %v", err)
	}
}

func TestRenderDotenvRejectsBadKeys(t *testing.T) {
	// '.' and '-' are refused because bash reads such a line as a command, not an
	// assignment. The rest are not plain ASCII names, or start with the reserved prefix.
	for _, k := range []string{
		"", "1A", "A B", "A=B", "a\nb", "\U000000e9", "#A", "a.b", "a-b", "A.B", "x;touch pwned;y", "$(id)",
		"\U00000131d", "agentruntim\U00000131e_pat",
		"AGENTRUNTIME_PAT", "agentruntime_api_url", "AgentRuntime_X",
	} {
		_, err := RenderDotenv(map[string]string{k: "FAKE_VALUE_FOR_KEY"})
		if err == nil {
			t.Errorf("key %q should be refused", k)
			continue
		}
		if strings.Contains(err.Error(), "FAKE_VALUE_FOR_KEY") {
			t.Errorf("key %q: the message contains the value: %v", k, err)
		}
	}
	for _, k := range []string{"A", "A1", "_x", "db_pass", "Host", "AGENTRUNTIME", "path", "NODE_OPTIONS"} {
		if _, err := RenderDotenv(map[string]string{k: "x"}); err != nil {
			t.Errorf("key %q should be accepted: %v", k, err)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	in := map[string]string{"b": "<&>", "a": "ünï \"q\"\n"}
	b, err := RenderJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), "}\n") {
		t.Errorf("no trailing newline: %q", b)
	}
	if strings.Contains(string(b), `\u003c`) {
		t.Errorf("HTML escaping should be off: %s", b)
	}
	var back map[string]string
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, b)
	}
	for k, v := range in {
		if back[k] != v {
			t.Errorf("%s: %q != %q", k, back[k], v)
		}
	}
	if empty, _ := RenderJSON(nil); string(empty) != "{}\n" {
		t.Errorf("nil map: %q", empty)
	}
}

func TestWriteOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.env")
	if err := WriteOwnerOnly(path, []byte("K=v\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "K=v\n" {
		t.Errorf("content %q", b)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, want 0600", st.Mode().Perm())
		}
	}
	// An existing file is never touched.
	err := WriteOwnerOnly(path, []byte("OTHER=1\n"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("overwrite should be refused, got %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "K=v\n" {
		t.Errorf("existing file was changed: %q", b)
	}
	// A missing folder is an error, not a created folder.
	if err := WriteOwnerOnly(filepath.Join(dir, "nope", "a.env"), nil); err == nil {
		t.Error("missing folder should fail")
	}
}

func TestFilesRemoveAll(t *testing.T) {
	dir := t.TempDir()
	var f Files
	a, b := filepath.Join(dir, "a.env"), filepath.Join(dir, "b.json")
	if err := f.Write(a, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := f.Write(b, []byte("y")); err != nil {
		t.Fatal(err)
	}
	// A second write to the same path fails and is not tracked twice.
	if err := f.Write(a, []byte("z")); err == nil {
		t.Fatal("expected refusal")
	}
	if got := f.Paths(); len(got) != 2 {
		t.Fatalf("paths %v", got)
	}
	// A file already gone is not an error.
	_ = os.Remove(b)
	if err := f.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	for _, p := range []string{a, b} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists", p)
		}
	}
	if len(f.Paths()) != 0 {
		t.Error("paths should be cleared")
	}
}
