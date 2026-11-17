package secrets

import (
	"fmt"
	"strings"
	"testing"
)

// A template that calls itself would run until the stack of the program overflows ("fatal error: stack overflow"),
// which nothing can catch, and it would do so after the fetch has spent a one-use key. So every cycle among the
// templates of a file is refused when the file is read, and so is a {{ template }} that names nothing (a typo would be
// found only when the run got there, also after the fetch).

// reproRecursion is the template a fuzz found: under a thousand bytes, and it takes down the program.
func reproRecursion() string {
	return `{{ define "a" }}` + strings.Repeat(`{{ if true }}`, 40) + `{{ template "a" }}` + strings.Repeat(`{{ end }}`, 40) + `{{ end }}{{ template "a" }}`
}

func TestTemplateRefusesEveryCycleOfTemplateCallsWhenItIsRead(t *testing.T) {
	repro := reproRecursion()
	if len(repro) < 800 || len(repro) > 1000 {
		t.Fatalf("the repro is %d bytes; it was reported as about 900", len(repro))
	}
	for name, src := range map[string]string{
		"the repro that overflowed the stack":    repro,
		"self call":                              `{{ define "a" }}{{ template "a" }}{{ end }}{{ template "a" }}`,
		"self call, never started":               `{{ define "a" }}x{{ template "a" }}{{ end }}plain text`,
		"mutual":                                 `{{ define "a" }}{{ template "b" }}{{ end }}{{ define "b" }}{{ template "a" }}{{ end }}{{ template "a" }}`,
		"three in a ring":                        `{{ define "a" }}{{ template "b" }}{{ end }}{{ define "b" }}{{ template "c" }}{{ end }}{{ define "c" }}{{ template "a" }}{{ end }}{{ template "a" }}`,
		"a ring that the main body never enters": `{{ define "a" }}{{ template "b" }}{{ end }}{{ define "b" }}{{ template "a" }}{{ end }}main body`,
		"self call inside if":                    `{{ define "a" }}{{ if true }}{{ template "a" }}{{ end }}{{ end }}{{ template "a" }}`,
		"self call inside else":                  `{{ define "a" }}{{ if false }}x{{ else }}{{ template "a" }}{{ end }}{{ end }}{{ template "a" }}`,
		"self call inside range":                 `{{ define "a" }}{{ range 3 }}{{ template "a" }}{{ end }}{{ end }}{{ template "a" }}`,
		"self call inside range else":            `{{ define "a" }}{{ range fields "x/y" }}{{ else }}{{ template "a" }}{{ end }}{{ end }}{{ template "a" }}`,
		"self call inside with":                  `{{ define "a" }}{{ with "x" }}{{ template "a" }}{{ end }}{{ end }}{{ template "a" }}`,
		"self call inside with else":             `{{ define "a" }}{{ with "" }}{{ else }}{{ template "a" }}{{ end }}{{ end }}{{ template "a" }}`,
		"self call inside nested control":        `{{ define "a" }}{{ if true }}{{ range 2 }}{{ with "x" }}{{ template "a" }}{{ end }}{{ end }}{{ end }}{{ end }}{{ template "a" }}`,
		"a block that calls itself":              `{{ block "x" . }}{{ template "x" . }}{{ end }}`,
		"a block inside a define that calls it":  `{{ define "a" }}{{ block "b" . }}{{ template "a" . }}{{ end }}{{ end }}{{ template "a" }}`,
		"the file calls itself by its own name":  `{{ template "t" }}`,
		"a call with an argument":                `{{ define "a" }}{{ template "a" (printf "%s" "x") }}{{ end }}{{ template "a" }}`,
		"a call through a pipeline in the pipe":  `{{ define "a" }}{{ template "b" (printf "%s" "x" | quote) }}{{ end }}{{ define "b" }}{{ template "a" }}{{ end }}{{ template "a" }}`,
		"a define called before it is written":   `{{ template "a" }}{{ define "a" }}{{ template "a" }}{{ end }}`,
		"a cycle behind a long acyclic chain":    chain(30) + `{{ define "end" }}{{ template "a0" }}{{ end }}{{ template "a0" }}`,
	} {
		_, err := ParseTemplate("t", src)
		var te *TemplateError
		if err == nil || !asTemplateError(err, &te) || !strings.Contains(err.Error(), "already running") || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%s: err = %v (a cycle must be refused when the template is read)", name, err)
		}
	}
	// The line of the call that closes the cycle is named.
	_, err := ParseTemplate("t", "{{ define \"a\" }}\nx\n{{ template \"a\" }}\n{{ end }}\n{{ template \"a\" }}")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("err = %v", err)
	}
}

// chain builds a0 -> a1 -> ... -> a(n-1) -> end, as {{ define }}s.
func chain(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		next := fmt.Sprintf("a%d", i+1)
		if i == n-1 {
			next = "end"
		}
		fmt.Fprintf(&sb, `{{ define "a%d" }}{{ template %q }}{{ end }}`, i, next)
	}
	return sb.String()
}

func TestTemplateRefusesACallToATemplateThatIsNotDefined(t *testing.T) {
	for name, src := range map[string]string{
		"a typo":                        `{{ template "typo" }}`,
		"a typo with an argument":       `{{ template "typo" (secret "a/b#C") }}`,
		"the wrong case":                `{{ define "Header" }}x{{ end }}{{ template "header" }}`,
		"a typo in a define":            `{{ define "a" }}{{ template "typo" }}{{ end }}{{ template "a" }}`,
		"a typo in an if":               `{{ if true }}{{ template "typo" }}{{ end }}`,
		"a typo in an else":             `{{ if true }}x{{ else }}{{ template "typo" }}{{ end }}`,
		"a typo in a range":             `{{ range 2 }}{{ template "typo" }}{{ end }}`,
		"a typo in a with":              `{{ with "x" }}{{ template "typo" }}{{ end }}`,
		"a typo in a define never used": `{{ define "unused" }}{{ template "typo" }}{{ end }}`,
		"a space in the name":           `{{ define "a" }}x{{ end }}{{ template "a " }}`,
	} {
		_, err := ParseTemplate("t", src)
		var te *TemplateError
		if err == nil || !asTemplateError(err, &te) || !strings.Contains(err.Error(), "not defined in this file") || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%s: err = %v (a missing template must be refused when the template is read)", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "typo") {
			t.Errorf("%s: the error repeats the name: %v", name, err)
		}
	}
	_, err := ParseTemplate("t", "a\n\n{{ template \"typo\" }}")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("err = %v", err)
	}
}

// Calls that end are fine, in any order, shared, nested, and to templates that are written later or are empty.
func TestTemplateAcceptsCallsThatEnd(t *testing.T) {
	vals := map[string]TemplateValue{"a/b#C": {String: "v"}}
	for name, c := range map[string]struct{ src, want string }{
		"a call":                {`{{ define "in" }}[{{ secret "a/b#C" }}]{{ end }}{{ template "in" }}`, "[v]"},
		"called twice":          {`{{ define "in" }}[{{ secret "a/b#C" }}]{{ end }}{{ template "in" }}{{ template "in" }}`, "[v][v]"},
		"defined after the use": {`{{ template "in" }}{{ define "in" }}x{{ end }}`, "x"},
		"an empty define":       {`{{ define "e" }}{{ end }}a{{ template "e" }}b`, "ab"},
		"a diamond":             {`{{ define "d" }}d{{ end }}{{ define "b" }}b{{ template "d" }}{{ end }}{{ define "c" }}c{{ template "d" }}{{ end }}{{ template "b" }}{{ template "c" }}`, "bdcd"},
		"a chain":               {`{{ define "a" }}a{{ template "b" }}{{ end }}{{ define "b" }}b{{ template "c" }}{{ end }}{{ define "c" }}c{{ end }}{{ template "a" }}`, "abc"},
		"a block":               {`{{ block "x" . }}default{{ end }}`, "default"},
		"a call with data":      {`{{ define "q" }}{{ . | quote }}{{ end }}{{ template "q" (secret "a/b#C") }}`, `"v"`},
		"calls in loops":        {`{{ define "i" }}i{{ end }}{{ range 3 }}{{ template "i" }}{{ end }}`, "iii"},
		"the main body by name": {`x`, "x"},
	} {
		tm, err := ParseTemplate("t", c.src)
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		out, err := tm.Execute(vals)
		if err != nil || string(out) != c.want {
			t.Errorf("%s: out %q err %v, want %q", name, out, err, c.want)
		}
	}
}

// Nesting and call depth have caps (the stack of a run must stay small), and the caps are not ones people reach.
func TestTemplateDepthCaps(t *testing.T) {
	nest := func(n int) string { return strings.Repeat(`{{ if true }}`, n) + "x" + strings.Repeat(`{{ end }}`, n) }
	for _, c := range []struct {
		name string
		src  string
		ok   bool
	}{
		{"50 nested in the main body", nest(50), true},
		{"51 nested in the main body", nest(51), false},
		{"50 nested in a define", `{{ define "a" }}` + nest(50) + `{{ end }}{{ template "a" }}`, true},
		{"51 nested in a define", `{{ define "a" }}` + nest(51) + `{{ end }}{{ template "a" }}`, false},
		{"50 of mixed kinds", strings.Repeat(`{{ if true }}{{ range 1 }}{{ with "x" }}`, 16) + "x" + strings.Repeat(`{{ end }}{{ end }}{{ end }}`, 16) + nest(2), true},
		{"siblings are not nested", strings.Repeat(`{{ if true }}x{{ end }}`, 500), true},
		// Nesting is counted in one body: 50 here and 50 there are fine, even when one calls the other.
		{"50 in a define called from 50 in the main body", `{{ define "a" }}` + nest(50) + `{{ end }}` + strings.Repeat(`{{ if true }}`, 50) + `{{ template "a" }}` + strings.Repeat(`{{ end }}`, 50), true},
		{"99 templates calling on", chain(98) + `{{ define "end" }}x{{ end }}{{ template "a0" }}`, true},   // main + a0..a97 + end = 100
		{"100 templates calling on", chain(99) + `{{ define "end" }}x{{ end }}{{ template "a0" }}`, false}, // 101 in a row
	} {
		_, err := ParseTemplate("t", c.src)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "deep") {
			t.Errorf("%s: the error does not say it is depth: %v", c.name, err)
		}
	}
	// The deepest allowed template still runs.
	tm, err := ParseTemplate("t", chain(98)+`{{ define "end" }}x{{ end }}{{ template "a0" }}`)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := tm.Execute(nil); err != nil || string(out) != "x" {
		t.Errorf("out %q err %v", out, err)
	}
	tm, _ = ParseTemplate("t", nest(50))
	if out, err := tm.Execute(nil); err != nil || string(out) != "x" {
		t.Errorf("nest(50): out %q err %v", out, err)
	}
}
