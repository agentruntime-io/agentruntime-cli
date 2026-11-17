package secrets

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Every value below is fake.
const (
	tplKey  = "sk_test_FAKE_0123456789abcdef"
	tplPass = "dbpass_FAKE_value_55"
	tplPin  = "12ab"
)

func TestTemplateCollectsEveryLiteralReferenceInOrderAndOnce(t *testing.T) {
	src := `# config
key = {{ secret "workspace/live/stripe#API_KEY" }}
again = {{ secret "secret:workspace/live/stripe#API_KEY" | quote }}
{{ "my/deploy#TOKEN" | secret | b64enc }}
{{- range $name, $v := fields "workspace/app" }}{{ $name }}={{ $v }}{{ end }}
{{ if secret "short/name#X" }}yes{{ else }}{{ secret "else/branch#Y" }}{{ end }}
{{ with fields "with/whole" }}{{ . }}{{ end }}
{{ printf "%s" (secret ` + "`raw/literal#Z`" + `) }}
{{ (secret "paren/ok#P") }}
{{ define "helper" }}{{ secret "defined/in#D" }}{{ end }}
{{ template "helper" }}
`
	tm, err := ParseTemplate("app.tmpl", src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"workspace/live/stripe#API_KEY", "my/deploy#TOKEN", "workspace/app", "short/name#X", "else/branch#Y",
		"with/whole", "raw/literal#Z", "paren/ok#P", "defined/in#D",
	}
	if got := tm.Refs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("refs\n got %v\nwant %v", got, want)
	}
}

// The tree is read in full: a reference inside a {{ block }}, an else branch, a range body or a nested template
// definition is collected the same way as one at the top.
func TestTemplateReadsDefineBlockAndNestedBodies(t *testing.T) {
	tm, err := ParseTemplate("t", `{{ block "b" . }}{{ secret "in/block#A" }}{{ end }}
{{ define "x" }}{{ range fields "in/define" }}{{ secret "in/range#B" }}{{ else }}{{ secret "in/else#C" }}{{ end }}{{ end }}`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range tm.Refs() {
		got[r] = true
	}
	for _, want := range []string{"in/block#A", "in/define", "in/range#B", "in/else#C"} {
		if !got[want] {
			t.Errorf("reference %s was not collected: %v", want, tm.Refs())
		}
	}
}

// The order of Refs does not depend on map order (templates are kept in a map).
func TestTemplateRefOrderIsStable(t *testing.T) {
	src := `{{ define "z" }}{{ secret "z/z#Z" }}{{ end }}{{ define "a" }}{{ secret "a/a#A" }}{{ end }}{{ secret "main/m#M" }}`
	first, err := ParseTemplate("t", src)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		again, _ := ParseTemplate("t", src)
		if !reflect.DeepEqual(again.Refs(), first.Refs()) {
			t.Fatalf("order changed: %v vs %v", again.Refs(), first.Refs())
		}
	}
	if want := []string{"main/m#M", "a/a#A", "z/z#Z"}; !reflect.DeepEqual(first.Refs(), want) {
		t.Fatalf("refs %v, want the main template first, then the others by name: %v", first.Refs(), want)
	}
}

// Anything that is not a quoted string written out in the template is refused, so the list of secrets a template
// reads is fixed by its text.
func TestTemplateRefusesEveryDynamicReference(t *testing.T) {
	for name, src := range map[string]string{
		"variable":                   `{{ $r := "a/b#C" }}{{ secret $r }}`,
		"field of dot":               `{{ secret .Ref }}`,
		"parenthesised literal":      `{{ secret ("a/b#C") }}`,
		"printf result":              `{{ secret (printf "a/b#%s" "C") }}`,
		"printf piped in":            `{{ printf "a/b#%s" "C" | secret }}`,
		"transformed then piped":     `{{ "a/b#C" | quote | secret }}`,
		"secret piped into secret":   `{{ "a/b#C" | secret | secret }}`,
		"fields from a secret":       `{{ fields (secret "a/b#C") }}`,
		"no argument":                `{{ secret }}`,
		"two arguments":              `{{ secret "a/b#C" "x" }}`,
		"literal and a piped value":  `{{ "x" | secret "a/b#C" }}`,
		"a number":                   `{{ secret 5 }}`,
		"a character constant":       `{{ secret 'a' }}`,
		"secret as a value":          `{{ printf "%s" secret }}`,
		"fields as a value":          `{{ printf "%v" fields }}`,
		"secret in an if":            `{{ if secret }}x{{ end }}`,
		"secret as an argument":      `{{ call secret }}`,
		"variable set to a function": `{{ $f := secret }}{{ $f }}`,
		"in a chain":                 `{{ (secret).Foo }}`,
		"inside a define":            `{{ define "x" }}{{ secret .R }}{{ end }}`,
		"in an else branch":          `{{ if true }}{{ else }}{{ secret .R }}{{ end }}`,
		"as the key of with":         `{{ with $x := secret .R }}{{ $x }}{{ end }}`,
		"fields over a range var":    `{{ range $k, $v := fields "a/b" }}{{ secret $k }}{{ end }}`,
	} {
		tm, err := ParseTemplate("t", src)
		var te *TemplateError
		switch {
		case err == nil || !errors.As(err, &te):
			t.Errorf("%s: %q was accepted (refs %v, err %v)", name, src, refsOf(tm), err)
		case !strings.Contains(err.Error(), "written out as a quoted string") && !strings.Contains(err.Error(), "must be called with a quoted reference"):
			// It must be the reference rule that refused it, not an unrelated parse error.
			t.Errorf("%s: %q was refused for another reason: %v", name, src, err)
		}
	}
}

func refsOf(t *Template) []string {
	if t == nil {
		return nil
	}
	return t.Refs()
}

// Pipelines and parentheses that only ever hold literals are fine, so ordinary templates need no workaround.
func TestTemplateAcceptsLiteralsInPipelinesAndExpressions(t *testing.T) {
	for _, src := range []string{
		`{{ secret "a/b#C" | quote }}`,
		`{{ "a/b#C" | secret | quote | printf "%s" }}`,
		`{{ index (fields "a/b") (secret "a/c#D") }}`,
		`{{ printf "%s-%s" (secret "a/b#C") (secret "a/b#D") }}`,
		`{{ $v := secret "a/b#C" }}{{ $v }}`,
		`{{ with $f := fields "a/b" }}{{ index $f "C" }}{{ end }}`,
		`{{ if eq (secret "a/b#C") "x" }}y{{ end }}`,
		`{{ json (fields "a/b") }}`,
	} {
		if _, err := ParseTemplate("t", src); err != nil {
			t.Errorf("%q refused: %v", src, err)
		}
	}
}

func TestTemplateRefusesABadReferenceWithoutRepeatingIt(t *testing.T) {
	const pasted = "PASTEDVALUE-9876543210"
	cases := map[string]struct{ src, want string }{
		"no path":           {`{{ secret "my#` + pasted + `" }}`, "name the secret after the room"},
		"traversal":         {`{{ secret "a/../b#` + pasted + `" }}`, "'.' and '..'"},
		"shared":            {`{{ secret "shared/x#` + pasted + `" }}`, "shared secrets cannot be fetched"},
		"wildcard":          {`{{ secret "a/*#` + pasted + `" }}`, "wildcards"},
		"empty":             {`{{ secret "" }}`, "it is empty"},
		"nothing after #":   {`{{ secret "a/b#" }}`, "nothing after '#'"},
		"secret, whole":     {`{{ secret "a/` + pasted + `" }}`, "needs #FIELD"},
		"fields, with #":    {`{{ fields "a/b#` + pasted + `" }}`, "must not have #FIELD"},
		"backslash":         {`{{ secret "a\\` + pasted + `#C" }}`, "use '/' between folders"},
		"control character": {`{{ secret "a/` + pasted + `\n#C" }}`, "control characters"},
	}
	for name, c := range cases {
		_, err := ParseTemplate("t", c.src)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), pasted) || strings.Contains(err.Error(), "PASTED") {
			t.Errorf("%s: the error repeats the reference: %v", name, err)
		}
		if !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%s: the error does not say where: %v", name, err)
		}
	}
}

func TestTemplateErrorsNameTheLine(t *testing.T) {
	_, err := ParseTemplate("t", "first\n\nthird {{ secret .X }}\n")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("err = %v", err)
	}
	_, err = ParseTemplate("t", "a\nb\n{{ define \"d\" }}\nline 4 {{ fields \"x/y#Z\" }}{{ end }}")
	if err == nil || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("define body: err = %v", err)
	}
}

func TestTemplateParseErrorsComeBackAsTemplateErrors(t *testing.T) {
	for _, src := range []string{`{{ secret "a/b#C" `, `{{ nosuchfunction }}`, `{{ if }}`, `{{ end }}`} {
		_, err := ParseTemplate("t", src)
		var te *TemplateError
		if err == nil || !errors.As(err, &te) {
			t.Errorf("%q: err = %v", src, err)
		}
	}
}

func values() map[string]TemplateValue {
	return map[string]TemplateValue{
		"workspace/live/stripe#API_KEY": {String: tplKey},
		"workspace/app#db_user":         {String: "app_user"},
		"my/pin#PIN":                    {String: tplPin},
		"workspace/app": {IsObject: true, Fields: map[string]string{
			"db_pass": tplPass, "Host": "db.example.test", "api-key": "dash_FAKE_value_7", "multi": "line one\nline \"two\"",
		}},
	}
}

func execute(t *testing.T, src string) (string, error) {
	t.Helper()
	tm, err := ParseTemplate("t", src)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	out, err := tm.Execute(values())
	return string(out), err
}

func TestTemplateExecuteSecretFieldsAndTheHelperFunctions(t *testing.T) {
	out, err := execute(t, `KEY={{ secret "workspace/live/stripe#API_KEY" }}
Q={{ secret "workspace/app#db_user" | quote }}
B={{ secret "workspace/app#db_user" | b64enc }}
J={{ secret "my/pin#PIN" | json }}
{{ range $k, $v := fields "workspace/app" }}{{ $k }}={{ $v | quote }}
{{ end -}}
D={{ (fields "workspace/app").db_pass }}
I={{ index (fields "workspace/app") "api-key" }}
ALL={{ fields "workspace/app" | json }}
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"KEY=" + tplKey + "\n",
		`Q="app_user"` + "\n",
		"B=YXBwX3VzZXI=\n",
		`J="12ab"` + "\n",
		// range over a map walks the names in sorted order, so the output is stable.
		`Host="db.example.test"` + "\n" + `api-key="dash_FAKE_value_7"` + "\n" + `db_pass="` + tplPass + `"` + "\n" + `multi="line one\nline \"two\""` + "\n",
		"D=" + tplPass + "\n",
		"I=dash_FAKE_value_7\n",
		`ALL={"Host":"db.example.test","api-key":"dash_FAKE_value_7","db_pass":"` + tplPass + `","multi":"line one\nline \"two\""}` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}

// json does not escape <, > and & (the rendered file is a config file, not HTML).
func TestTemplateJSONDoesNotEscapeHTMLCharacters(t *testing.T) {
	tm, err := ParseTemplate("t", `{{ secret "x/y#Z" | json }}`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tm.Execute(map[string]TemplateValue{"x/y#Z": {String: "a<b>&c"}})
	if err != nil || string(out) != `"a<b>&c"` {
		t.Fatalf("out %q err %v", out, err)
	}
}

// missingkey=error: a name that is not in the secret is an error, never an empty string.
func TestTemplateMissingNamesAreErrors(t *testing.T) {
	for name, src := range map[string]string{
		"field syntax":    `{{ (fields "workspace/app").NOPE }}`,
		"index":           `{{ index (fields "workspace/app") "nope" }}`,
		"dot":             `{{ .Anything }}`,
		"with, field":     `{{ with (fields "workspace/app").NOPE }}x{{ end }}`,
		"index of string": `{{ index (secret "my/pin#PIN") "x" }}`,
	} {
		out, err := execute(t, src)
		if err == nil {
			t.Errorf("%s: no error, output %q", name, out)
		}
		if out != "" {
			t.Errorf("%s: output %q must be empty on an error", name, out)
		}
	}
	// The error says where, and what kind of mistake; it does not repeat the name (it may come from another secret)
	// or anything the secret holds.
	_, err := execute(t, "x\n{{ index (fields \"workspace/app\") \"nope\" }}")
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "no field with that name") ||
		strings.Contains(err.Error(), "nope") || strings.Contains(err.Error(), tplPass) {
		t.Errorf("err = %v", err)
	}
	_, err = execute(t, "x\n\n{{ (fields \"workspace/app\").NOPE }}")
	if err == nil || !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), "not in the secret") || strings.Contains(err.Error(), "NOPE") {
		t.Errorf("field syntax: err = %v", err)
	}
}

// The engine can quote a value in an error ("range can't iterate over <value>"). Nothing of the engine's text is
// used: the error is a fixed sentence and a line number, so no value can be in it, whatever its length, also a value
// of one or two characters, which no masker could take out of a message.
func TestTemplateErrorMessagesNeverQuoteAValue(t *testing.T) {
	tiny := map[string]TemplateValue{
		"my/tiny#ONE": {String: "z"},
		"my/tiny#TWO": {String: "zq"},
		"my/tiny":     {IsObject: true, Fields: map[string]string{"A": "zq", "B": "q9"}},
	}
	all := map[string]TemplateValue{}
	for k, v := range values() {
		all[k] = v
	}
	for k, v := range tiny {
		all[k] = v
	}
	// Each of these makes the engine (or a function) fail in a different way.
	for name, src := range map[string]string{
		"range over text":         `x` + "\n" + `{{ range (secret "REF") }}x{{ end }}`,
		"field of text":           `{{ (secret "REF").Foo }}`,
		"call text":               `{{ call (secret "REF") }}`,
		"compare text":            `{{ eq (secret "REF") 3 }}`,
		"index text":              `{{ index (secret "REF") "k" }}`,
		"slice out of range":      `{{ slice (secret "REF") 1 100 }}`,
		"with field":              `{{ with (secret "REF") }}{{ .x }}{{ end }}`,
		"index a missing name":    `{{ index (fields "my/tiny") (secret "REF") }}`,
		"json of text then range": `{{ range (secret "REF" | json) }}x{{ end }}`,
	} {
		for _, ref := range []string{"workspace/live/stripe#API_KEY", "my/pin#PIN", "my/tiny#ONE", "my/tiny#TWO"} {
			tm, err := ParseTemplate("t", strings.ReplaceAll(src, "REF", ref))
			if err != nil {
				t.Fatalf("%s: parse: %v", name, err)
			}
			_, err = tm.Execute(all)
			if err == nil {
				t.Errorf("%s %s: expected an error", name, ref)
				continue
			}
			for _, v := range []string{tplKey, tplPin, "zq", "q9"} {
				if strings.Contains(err.Error(), v) {
					t.Errorf("%s %s: the error quotes the value %q: %v", name, ref, v, err)
				}
			}
			// One value is a single letter that any sentence holds, so it is not looked for; the error is still a fixed
			// sentence: it starts the same way whatever the value.
			if !strings.HasPrefix(err.Error(), "the template failed") {
				t.Errorf("%s %s: error is not one of ours: %v", name, ref, err)
			}
		}
	}
	// The line is kept, and the kind of mistake is named.
	tm, _ := ParseTemplate("t", "a\nb\n{{ range (secret \"my/tiny#TWO\") }}x{{ end }}")
	_, err := tm.Execute(all)
	if err == nil || err.Error() != "the template failed at line 3: range was used on text; to loop over the fields of a secret, range over fields \"REF\"" {
		t.Errorf("err = %v", err)
	}
}

func TestScrub(t *testing.T) {
	got := Scrub("range can't iterate over "+tplKey+" and "+tplPin+" and ab", []string{tplKey, tplPin, "ab", ""})
	want := "range can't iterate over *** and *** and ab"
	if got != want {
		t.Errorf("got %q, want %q (a value of two characters is not replaced: it would garble ordinary text)", got, want)
	}
}

func TestTemplateRefusesAWrongKindOfAnswer(t *testing.T) {
	tm, err := ParseTemplate("t", `{{ secret "a/b#C" }}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tm.Execute(map[string]TemplateValue{"a/b#C": {IsObject: true, Fields: map[string]string{"x": tplKey}}}); err == nil ||
		!strings.Contains(err.Error(), "wrong kind of value") || strings.Contains(err.Error(), tplKey) {
		t.Errorf("secret over an object: %v", err)
	}
	tm, _ = ParseTemplate("t", `{{ fields "a/b" }}`)
	if _, err := tm.Execute(map[string]TemplateValue{"a/b": {String: tplKey}}); err == nil || !strings.Contains(err.Error(), "wrong kind of value") {
		t.Errorf("fields over a string: %v", err)
	}
	// A reference the server did not answer is an error too (the client already refuses such an answer).
	tm, _ = ParseTemplate("t", `{{ secret "a/b#C" }}`)
	if _, err := tm.Execute(map[string]TemplateValue{}); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("missing answer: %v", err)
	}
}

// Nothing a template does can change what other references read: it has no way to change a map.
func TestTemplateCannotChangeTheFieldsItReads(t *testing.T) {
	vals := map[string]TemplateValue{"a/b": {IsObject: true, Fields: map[string]string{"K": "v1"}}}
	tm, _ := ParseTemplate("t", `{{ $m := fields "a/b" }}{{ index $m "K" }}`)
	if out, err := tm.Execute(vals); err != nil || string(out) != "v1" {
		t.Fatalf("%q %v", out, err)
	}
	if !reflect.DeepEqual(vals["a/b"].Fields, map[string]string{"K": "v1"}) {
		t.Fatal("the answer was changed")
	}
}

func TestTemplateOutputIsCapped(t *testing.T) {
	tm, err := ParseTemplate("t", `{{ range $i := 1000 }}{{ range $j := 1000 }}xxxxxxxxxxxxxxxx{{ end }}{{ end }}`)
	if err != nil {
		t.Fatal(err)
	}
	// 16 MB of text against a cap of 8 MiB. (A reference-less template never reaches Execute in the CLI, but the cap
	// holds on its own.)
	out, err := tm.Execute(nil)
	if err == nil || out != nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("out %d bytes, err %v", len(out), err)
	}
}

// A template can be executed more than once with different answers, and each run sees only its own.
func TestTemplateKeepsNoValuesAfterExecute(t *testing.T) {
	tm, _ := ParseTemplate("t", `{{ secret "a/b#C" }}`)
	if out, err := tm.Execute(map[string]TemplateValue{"a/b#C": {String: "first"}}); err != nil || string(out) != "first" {
		t.Fatalf("%q %v", out, err)
	}
	if out, err := tm.Execute(map[string]TemplateValue{"a/b#C": {String: "second"}}); err != nil || string(out) != "second" {
		t.Fatalf("%q %v", out, err)
	}
}
