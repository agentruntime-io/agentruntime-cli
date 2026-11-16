package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fake values. Nothing here is a real credential.
const (
	fakeNLToken = "nl_token_FAKE_abcdef\n"

	fakePEMBegin = "-----BEGIN FAKE PRIVATE KEY-----"
	fakePEMLine1 = "MIIFAKEFAKEFAKE0123456789abcdefGHIJKLMNOP"
	fakePEMLine2 = "qrstuvwxyzFAKEFAKE+/0123456789ABCDEFGH=="
	fakePEMShort = "ab12"
	fakePEMEnd   = "-----END FAKE PRIVATE KEY-----"
	fakePEM      = fakePEMBegin + "\n" + fakePEMLine1 + "\n" + fakePEMLine2 + "\n" + fakePEMShort + "\n" + fakePEMEnd + "\n"
)

// put stores a secret in the fake server.
func (f *fakeBFF) put(ref string, fields map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store[ref] = fields
}

// unsetEnv removes variables from this process for the test, so a probe in the
// child that finds one unset really means the secret did not set it.
func unsetEnv(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if old, ok := os.LookupEnv(n); ok {
			t.Cleanup(func() { _ = os.Setenv(n, old) })
			_ = os.Unsetenv(n)
		}
	}
}

// ---- --env-from: the person names the fields ---------------------------------------------

func TestSecretsRunEnvFromSetsOnlyTheFieldsYouName(t *testing.T) {
	withHelper(t)
	probes := []string{"DB_PASS", "API_KEY", "PIP_INDEX_URL", "NODE_OPTIONS", "GOFLAGS", "LD_PRELOAD", "PATH_PREFIX", "EXTRA"}
	unsetEnv(t, probes...)
	f := newFakeBFF(t)
	// The secret also holds fields that change how a build or a program runs. Nobody
	// named them, so none of them may become a variable (or even be fetched).
	f.put("workspace/mixed", map[string]string{
		"db_pass": "dbpass_FAKE_value_7", "api_key": "apikey_FAKE_value_8",
		"PIP_INDEX_URL": "https://index.example.test/FAKE_simple", "NODE_OPTIONS": "--require=FAKE_hook_value_1",
		"GOFLAGS": "-toolexec=FAKE_hook_value_2", "LD_PRELOAD": "/tmp/FAKE_hook_value_3.so", "EXTRA": "extra_FAKE_value_9",
	})
	dump := filepath.Join(t.TempDir(), "env.txt")
	args := append([]string{"--env-from", "workspace/mixed#db_pass,api_key", "--"}, helper(append([]string{"dump-env", dump}, probes...)...)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	want := "DB_PASS=dbpass_FAKE_value_7\nAPI_KEY=apikey_FAKE_value_8\n" +
		"PIP_INDEX_URL=<unset>\nNODE_OPTIONS=<unset>\nGOFLAGS=<unset>\nLD_PRELOAD=<unset>\nPATH_PREFIX=<unset>\nEXTRA=<unset>\n"
	if got := mustRead(t, dump); got != want {
		t.Errorf("child environment:\n%s\nwant:\n%s", got, want)
	}
	// One call, for exactly the fields that were named.
	if f.count() != 1 {
		t.Fatalf("%d fetch calls, want 1", f.count())
	}
	if got := strings.Join(f.last().Refs, ","); got != "workspace/mixed#db_pass,workspace/mixed#api_key" {
		t.Errorf("request refs = %s: only the named fields may be asked for", got)
	}
}

// Even a server that answers with more than was asked for cannot add variables.
func TestSecretsRunEnvFromIgnoresAnythingThatWasNotAskedFor(t *testing.T) {
	withHelper(t)
	probes := []string{"DB_PASS", "PIP_INDEX_URL", "NODE_OPTIONS", "GOFLAGS"}
	unsetEnv(t, probes...)
	f := newFakeBFF(t)
	f.override = func(r bffReq) (int, string, map[string]string) {
		return 200, `{"values":{"workspace/mixed#db_pass":"dbpass_FAKE_value_7",` +
			`"workspace/mixed#PIP_INDEX_URL":"https://index.example.test/FAKE_simple",` +
			`"workspace/mixed":{"NODE_OPTIONS":"--require=FAKE_hook_value_1","GOFLAGS":"-toolexec=FAKE_hook_value_2","db_pass":"dbpass_FAKE_value_7"}}}`, nil
	}
	dump := filepath.Join(t.TempDir(), "env.txt")
	args := append([]string{"--env-from", "workspace/mixed#db_pass", "--"}, helper(append([]string{"dump-env", dump}, probes...)...)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	want := "DB_PASS=dbpass_FAKE_value_7\nPIP_INDEX_URL=<unset>\nNODE_OPTIONS=<unset>\nGOFLAGS=<unset>\n"
	if got := mustRead(t, dump); got != want {
		t.Errorf("child environment:\n%s\nwant:\n%s", got, want)
	}
}

// What the variable is called is the person's decision once they name the field.
func TestSecretsRunEnvFromAndEnvTakeTheNamesYouGive(t *testing.T) {
	withHelper(t)
	probes := []string{"NODE_OPTIONS", "DB_PASS", "HOST", "RENAMED"}
	unsetEnv(t, probes...)
	f := newFakeBFF(t)
	f.put("workspace/d", map[string]string{"node_options": "explicit_FAKE_value_1", "db_pass": "explicit_FAKE_value_2", "Host": "from-env-from.test"})
	dump := filepath.Join(t.TempDir(), "env.txt")
	args := []string{
		"--env-from", "workspace/d#node_options,db_pass,Host",
		"--env", "RENAMED=workspace/d#db_pass", // another name for a field: --env
		"--env", "HOST=my/deploy#HOST", // an explicit --env wins over --env-from
		"--",
	}
	args = append(args, helper(append([]string{"dump-env", dump}, probes...)...)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	want := "NODE_OPTIONS=explicit_FAKE_value_1\nDB_PASS=explicit_FAKE_value_2\nHOST=deploy-host.test\nRENAMED=explicit_FAKE_value_2\n"
	if got := mustRead(t, dump); got != want {
		t.Errorf("child environment:\n%s\nwant:\n%s", got, want)
	}
	// db_pass is asked for once although two flags use it.
	if got := strings.Join(f.last().Refs, ","); got != "workspace/d#db_pass,my/deploy#HOST,workspace/d#node_options,workspace/d#Host" {
		t.Errorf("refs = %s", got)
	}
}

// Everything that can be judged from the command line is refused before the
// fetch, so a mistake does not use up one of a limited key's uses.
func TestSecretsRunEnvFromRefusalsComeBeforeTheFetch(t *testing.T) {
	withHelper(t)
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"no names", []string{"--env-from", "workspace/app"}, []string{"name the fields", "--env-from REF#DB_USER,DB_PASS", "--env NAME=REF#FIELD"}},
		{"a hash and nothing after it", []string{"--env-from", "workspace/app#"}, []string{"nothing after '#'"}},
		{"a wildcard", []string{"--env-from", "workspace/app#*"}, []string{"'*' is not accepted", "name each field", "--env NAME=REF#FIELD"}},
		{"a wildcard among names", []string{"--env-from", "workspace/app#API_KEY,*"}, []string{"'*' is not accepted"}},
		{"an empty name", []string{"--env-from", "workspace/app#API_KEY,,Host"}, []string{"field 2 is empty"}},
		{"a trailing comma", []string{"--env-from", "workspace/app#API_KEY,"}, []string{"field 2 is empty"}},
		{"the same name twice", []string{"--env-from", "workspace/app#API_KEY,Host,API_KEY"}, []string{"field 3 repeats field 1"}},
		{"names that differ only in case", []string{"--env-from", "workspace/app#db_pass,DB_PASS"}, []string{"would both set DB_PASS"}},
		{"two flags, the same variable", []string{"--env-from", "workspace/c1#x_y", "--env-from", "workspace/c2#X_Y"}, []string{"would both set X_Y"}},
		{"a dash", []string{"--env-from", "workspace/badnames#api-key"}, []string{"not a plain ASCII name", "--env NAME=REF#FIELD"}},
		{"a dot", []string{"--env-from", "workspace/app#a.b"}, []string{"not a plain ASCII name"}},
		{"a leading digit", []string{"--env-from", "workspace/app#1abc"}, []string{"not a plain ASCII name"}},
		{"a space", []string{"--env-from", "workspace/app#API_KEY, Host"}, []string{"field 2", "not a plain ASCII name"}},
		{"AGENTRUNTIME_PAT", []string{"--env-from", "workspace/app#AGENTRUNTIME_PAT"}, []string{"reserved", "AGENTRUNTIME_", "would set AGENTRUNTIME_PAT"}},
		{"agentruntime_api_url in lower case", []string{"--env-from", "workspace/app#agentruntime_api_url"}, []string{"reserved", "would set AGENTRUNTIME_API_URL"}},
		{"AgentRuntime_X in mixed case", []string{"--env-from", "workspace/app#Db_pass,AgentRuntime_X"}, []string{"field 2", "reserved"}},
		// strings.ToUpper turns these into ASCII names, so the check must see the raw name.
		{"dotless i", []string{"--env-from", "workspace/app#\xc4\xb1d_token"}, []string{"not a plain ASCII name"}},
		{"dotless i in the reserved prefix", []string{"--env-from", "workspace/app#agentruntim\xc4\xb1e_pat"}, []string{"not a plain ASCII name"}},
		{"long s", []string{"--env-from", "workspace/app#\xc5\xbfecret_key"}, []string{"not a plain ASCII name"}},
		{"Kelvin sign", []string{"--env-from", "workspace/app#\xe2\x84\xaaey"}, []string{"not a plain ASCII name"}},
		{"an accent", []string{"--env-from", "workspace/app#caf\xc3\xa9"}, []string{"not a plain ASCII name"}},
	}
	for _, c := range cases {
		f := newFakeBFF(t)
		marker := filepath.Join(t.TempDir(), "ran")
		args := append(append([]string{}, c.args...), "--")
		args = append(args, helper("touch", marker)...)
		code, out, errOut := runSecrets(t, f, "", "run", args...)
		if code != ExitUsage {
			t.Errorf("%s: exit %d, want 2\n%s", c.name, code, errOut)
		}
		for _, w := range c.want {
			if !strings.Contains(errOut, w) {
				t.Errorf("%s: stderr lacks %q:\n%s", c.name, w, errOut)
			}
		}
		if f.count() != 0 {
			t.Errorf("%s: a refused command line must not fetch", c.name)
		}
		if exists(marker) {
			t.Errorf("%s: the command must not start", c.name)
		}
		if strings.Contains(out+errOut, "_FAKE_") || out != "" {
			t.Errorf("%s: unexpected output\n%s\n%s", c.name, out, errOut)
		}
	}
}

// A field that is named but is not in the secret is the server's all-or-nothing
// not-found: nothing runs and nothing from the other fields leaks.
func TestSecretsRunEnvFromANamedFieldThatDoesNotExistStopsEverything(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	marker := filepath.Join(t.TempDir(), "ran")
	args := append([]string{"--env-from", "workspace/app#db_pass,no_such_field", "--"}, helper("touch", marker)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != ExitError || !strings.Contains(errOut, "not_found") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if exists(marker) {
		t.Error("the command must not start")
	}
	if f.count() != 1 {
		t.Errorf("%d calls, want 1", f.count())
	}
	assertNoValue(t, "missing field", out, errOut)
}

func TestSecretsRunCountsEveryNamedFieldAsOneReference(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	var names []string
	for i := 0; i < 21; i++ {
		names = append(names, "F"+strings.Repeat("x", i))
	}
	args := append([]string{"--env-from", "my/a#" + strings.Join(names, ","), "--"}, helper("touch", filepath.Join(t.TempDir(), "ran"))...)
	code, _, errOut := runSecrets(t, f, "", "run", args...)
	if code != ExitUsage || !strings.Contains(errOut, "at most 20") || !strings.Contains(errOut, "counts as one") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if f.count() != 0 {
		t.Error("no fetch")
	}
}

// ---- --secret-file: dotenv takes named fields, JSON may take a whole secret ----------------

func TestSecretsRunDotenvFileHoldsOnlyTheNamedFields(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	f.put("workspace/mixed", map[string]string{
		"DB_PASS": "dbpass_FAKE_value_7", "db_user": "dbuser_FAKE_value_8",
		"PIP_INDEX_URL": "https://index.example.test/FAKE_simple", "NODE_OPTIONS": "--require=FAKE_hook_value_1",
		"dotted.name": "dotted_FAKE_value_2", "dash-name": "dashed_FAKE_value_3", "AGENTRUNTIME_PAT": "pat_FAKE_value_4",
	})
	dir := t.TempDir()
	file, copyTo := filepath.Join(dir, "app.env"), filepath.Join(dir, "copy.env")
	args := append([]string{"--secret-file", file + "=workspace/mixed#db_user,DB_PASS", "--"}, helper("copy-file", file, copyTo)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if got, want := mustRead(t, copyTo), "DB_PASS=dbpass_FAKE_value_7\ndb_user=dbuser_FAKE_value_8\n"; got != want {
		t.Errorf("dotenv content:\n%s\nwant:\n%s", got, want)
	}
	if got := strings.Join(f.last().Refs, ","); got != "workspace/mixed#db_user,workspace/mixed#DB_PASS" {
		t.Errorf("request refs = %s: only the named fields may be asked for", got)
	}
	if exists(file) {
		t.Error("the file must be removed when the command ends")
	}
}

func TestSecretsRunDotenvFileRefusalsComeBeforeTheFetch(t *testing.T) {
	withHelper(t)
	dir := t.TempDir()
	envFile := filepath.Join(dir, "app.env")
	cases := []struct {
		name string
		ref  string
		want []string
	}{
		{"no names", "workspace/app", []string{"a dotenv file needs the fields to write", "--secret-file " + envFile + "=REF#DB_USER,DB_PASS", ".json"}},
		{"a hash and nothing after it", "workspace/app#", []string{"nothing after '#'"}},
		{"a wildcard", "workspace/app#*", []string{"a dotenv file needs the fields to write"}},
		{"a wildcard among names", "workspace/app#db_pass,*", []string{"a dotenv file needs the fields to write"}},
		{"a dot in a key", "workspace/app#db_pass,a.b", []string{"field 2", "cannot be a key in a dotenv file", ".json"}},
		{"a dash in a key", "workspace/app#api-key", []string{"field 1", "cannot be a key in a dotenv file", "not a shell variable name"}},
		{"a non-ASCII key", "workspace/app#caf\xc3\xa9", []string{"cannot be a key in a dotenv file"}},
		{"dotless i", "workspace/app#\xc4\xb1d", []string{"cannot be a key in a dotenv file"}},
		{"AGENTRUNTIME_PAT", "workspace/app#AGENTRUNTIME_PAT", []string{"reserved", "AGENTRUNTIME_"}},
		{"agentruntime_x in lower case", "workspace/app#agentruntime_x", []string{"reserved"}},
		{"the same name twice", "workspace/app#db_pass,db_pass", []string{"field 2 repeats field 1"}},
	}
	for _, c := range cases {
		f := newFakeBFF(t)
		marker := filepath.Join(t.TempDir(), "ran")
		args := append([]string{"--secret-file", envFile + "=" + c.ref, "--"}, helper("touch", marker)...)
		code, out, errOut := runSecrets(t, f, "", "run", args...)
		if code != ExitUsage {
			t.Errorf("%s: exit %d, want 2\n%s", c.name, code, errOut)
		}
		for _, w := range c.want {
			if !strings.Contains(errOut, w) {
				t.Errorf("%s: stderr lacks %q:\n%s", c.name, w, errOut)
			}
		}
		if f.count() != 0 || exists(marker) || exists(envFile) {
			t.Errorf("%s: nothing may be fetched, run or written (fetches=%d)", c.name, f.count())
		}
		assertNoValue(t, c.name, out, errOut)
	}
}

func TestSecretsRunJSONFileTakesTheWholeSecretOrNamedFields(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dir := t.TempDir()
	whole, named := filepath.Join(dir, "whole.json"), filepath.Join(dir, "named.json")
	copyWhole, copyNamed := filepath.Join(dir, "copy-whole.json"), filepath.Join(dir, "copy-named.json")

	// The whole secret, as before: a JSON file is not loaded into an environment.
	args := append([]string{"--secret-file", whole + "=my/deploy", "--"}, helper("copy-file", whole, copyWhole)...)
	if code, out, errOut := runSecrets(t, f, "", "run", args...); code != 0 {
		t.Fatalf("whole: exit %d\n%s\n%s", code, out, errOut)
	}
	if got := f.last().Refs; len(got) != 1 || got[0] != "my/deploy" {
		t.Errorf("whole: request refs = %v", got)
	}
	if got := mustRead(t, copyWhole); !strings.Contains(got, `"TOKEN": "`+fakeTok+`"`) || !strings.Contains(got, `"HOST": "deploy-host.test"`) {
		t.Errorf("whole: json content: %s", got)
	}

	// Named fields: a JSON object with just those fields, and only those are asked for.
	args = append([]string{"--secret-file", named + "=my/deploy#TOKEN", "--"}, helper("copy-file", named, copyNamed)...)
	if code, out, errOut := runSecrets(t, f, "", "run", args...); code != 0 {
		t.Fatalf("named: exit %d\n%s\n%s", code, out, errOut)
	}
	if got := f.last().Refs; len(got) != 1 || got[0] != "my/deploy#TOKEN" {
		t.Errorf("named: request refs = %v", got)
	}
	if got, want := mustRead(t, copyNamed), "{\n  \"TOKEN\": \""+fakeTok+"\"\n}\n"; got != want {
		t.Errorf("named: json content:\n%s\nwant:\n%s", got, want)
	}
	for _, p := range []string{whole, named} {
		if exists(p) {
			t.Errorf("%s must be removed when the command ends", p)
		}
	}
}

func TestSecretsRunJSONFileRefusals(t *testing.T) {
	withHelper(t)
	dir := t.TempDir()
	for name, c := range map[string]struct{ ref, want string }{
		"a wildcard":                  {"my/deploy#*", "'*' is not accepted"},
		"a hash and nothing after it": {"my/deploy#", "nothing after '#'"},
		"an empty name":               {"my/deploy#TOKEN,,HOST", "field 2 is empty"},
		"the same name twice":         {"my/deploy#TOKEN,TOKEN", "field 2 repeats field 1"},
	} {
		f := newFakeBFF(t)
		file := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		args := append([]string{"--secret-file", file + "=" + c.ref, "--"}, helper("touch", filepath.Join(dir, "ran"))...)
		code, _, errOut := runSecrets(t, f, "", "run", args...)
		if code != ExitUsage || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: code=%d err=%q", name, code, errOut)
		}
		if f.count() != 0 || exists(file) {
			t.Errorf("%s: nothing may be fetched or written", name)
		}
	}
	// A JSON file takes field names a dotenv key cannot have.
	f := newFakeBFF(t)
	f.put("workspace/odd", map[string]string{"dotted.name": "dotted_FAKE_value_2", "dash-name": "dashed_FAKE_value_3"})
	file, copyTo := filepath.Join(dir, "odd.json"), filepath.Join(dir, "odd-copy.json")
	args := append([]string{"--secret-file", file + "=workspace/odd#dotted.name,dash-name", "--"}, helper("copy-file", file, copyTo)...)
	if code, out, errOut := runSecrets(t, f, "", "run", args...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if got := mustRead(t, copyTo); !strings.Contains(got, `"dotted.name"`) || !strings.Contains(got, `"dash-name"`) {
		t.Errorf("json content: %s", got)
	}
}

// ---- dotenv quoting ------------------------------------------------------------------------

func TestSecretsRunDotenvFileNeverRunsOrExpandsAValue(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	f.put("workspace/tricky", map[string]string{
		"CMD":  "$(touch pwned)",
		"HOME": "$HOME",
		"TICK": "`id`",
		"BS":   `abc\`,
		"APOS": "it's fine",
	})
	dir := t.TempDir()
	file, copyTo := filepath.Join(dir, "app.env"), filepath.Join(dir, "copy.env")
	args := append([]string{"--secret-file", file + "=workspace/tricky#CMD,HOME,TICK,BS,APOS", "--"}, helper("copy-file", file, copyTo)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	want := "APOS=\"it's fine\"\nBS=\"abc\\\\\"\nCMD='$(touch pwned)'\nHOME='$HOME'\nTICK='`id`'\n"
	if got := mustRead(t, copyTo); got != want {
		t.Errorf("dotenv content:\n%s\nwant:\n%s", got, want)
	}
}

func TestSecretsRunDotenvRefusesAValueNoQuoteCanCarry(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	f.put("workspace/hard", map[string]string{"PW": "FAKE_it's_$(id)_VALUE", "OK": "fine_FAKE_value_1"})
	dir := t.TempDir()
	file, marker := filepath.Join(dir, "app.env"), filepath.Join(dir, "ran")
	args := append([]string{"--secret-file", file + "=workspace/hard#PW,OK", "--"}, helper("touch", marker)...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != ExitError {
		t.Errorf("exit %d, want 1", code)
	}
	for _, want := range []string{`field "PW"`, ".json"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	if strings.Contains(out+errOut, "FAKE_it") || strings.Contains(out+errOut, "$(id)") {
		t.Errorf("the message must not contain the value:\n%s", errOut)
	}
	if exists(marker) || exists(file) {
		t.Error("nothing may run or be written")
	}
	// The same secret as a JSON file works.
	jsonFile, copyTo := filepath.Join(dir, "app.json"), filepath.Join(dir, "copy.json")
	args = append([]string{"--secret-file", jsonFile + "=workspace/hard", "--"}, helper("copy-file", jsonFile, copyTo)...)
	if code, _, errOut := runSecrets(t, f, "", "run", args...); code != 0 {
		t.Fatalf("json: exit %d: %s", code, errOut)
	}
	if got := mustRead(t, copyTo); !strings.Contains(got, `"PW": "FAKE_it's_$(id)_VALUE"`) {
		t.Errorf("json content: %s", got)
	}
}

// ---- masking trimmed values and single lines -----------------------------------------------

func TestSecretsRunMasksTrimmedValueAndPEMLines(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	args := []string{"--env", "TOK=workspace/nl#TOKEN", "--env", "KEY=workspace/pem#KEY", "--"}
	args = append(args, helper("print-lines", "TOK", "KEY")...)
	code, out, errOut := runSecrets(t, f, "", "run", args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, leak := range []string{"nl_token_FAKE", fakePEMBegin, fakePEMLine1, fakePEMLine2, fakePEMEnd, "FAKEFAKE"} {
		if strings.Contains(out+errOut, leak) {
			t.Errorf("%q leaked:\n%s\n%s", leak, out, errOut)
		}
	}
	for _, want := range []string{"TOK (trimmed): ***", "KEY (trimmed): ***", "line: " + fakePEMShort} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "line: ***"); n != 5 { // the token's line and four PEM lines
		t.Errorf("%d masked lines, want 5:\n%s", n, out)
	}
	if errOut != "" {
		t.Errorf("no note expected, every value is long enough: %q", errOut)
	}
}
