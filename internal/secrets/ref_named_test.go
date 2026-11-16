package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestParseNamedValid(t *testing.T) {
	cases := []struct {
		in    string
		root  string // the secret, normalized
		names []string
		refs  []string // what is sent to the server
	}{
		{"workspace/live/stripe#API_KEY", "workspace/live/stripe", []string{"API_KEY"}, []string{"workspace/live/stripe#API_KEY"}},
		{"secret:workspace/live/stripe#API_KEY,WEBHOOK", "workspace/live/stripe", []string{"API_KEY", "WEBHOOK"},
			[]string{"workspace/live/stripe#API_KEY", "workspace/live/stripe#WEBHOOK"}},
		{"my/deploy#b,a,c", "my/deploy", []string{"b", "a", "c"}, []string{"my/deploy#b", "my/deploy#a", "my/deploy#c"}}, // order kept
		{"live/stripe#K", "live/stripe", []string{"K"}, []string{"live/stripe#K"}},                                       // short name
		{"  my/a#X,Y  ", "my/a", []string{"X", "Y"}, []string{"my/a#X", "my/a#Y"}},
		// The same field in two cases are two fields (the secret's names are case-sensitive).
		{"my/a#db,DB", "my/a", []string{"db", "DB"}, []string{"my/a#db", "my/a#DB"}},
	}
	for _, c := range cases {
		got, err := ParseNamed(c.in)
		if err != nil {
			t.Errorf("ParseNamed(%q): %v", c.in, err)
			continue
		}
		if got.Secret.String() != c.root || !got.Secret.Whole() {
			t.Errorf("ParseNamed(%q).Secret = %q (whole %v), want %q", c.in, got.Secret, got.Secret.Whole(), c.root)
		}
		if strings.Join(got.Names, ",") != strings.Join(c.names, ",") {
			t.Errorf("ParseNamed(%q).Names = %v, want %v", c.in, got.Names, c.names)
		}
		var refs []string
		for _, r := range got.Refs() {
			refs = append(refs, r.String())
			// Every one of them is also a valid single-field reference.
			if again, err := Parse(r.String()); err != nil || again != r {
				t.Errorf("%q: %q does not parse back: %+v, %v", c.in, r, again, err)
			}
		}
		if strings.Join(refs, "|") != strings.Join(c.refs, "|") {
			t.Errorf("ParseNamed(%q).Refs() = %v, want %v", c.in, refs, c.refs)
		}
	}
}

func TestParseNamedWithoutNamesOrWithAWildcard(t *testing.T) {
	for _, in := range []string{"workspace/live/stripe", "secret:my/a", "a"} {
		if _, err := ParseNamed(in); !errors.Is(err, ErrNoFieldNames) {
			t.Errorf("%q: err = %v, want ErrNoFieldNames", in, err)
		}
	}
	for _, in := range []string{"workspace/live/stripe#*", "my/a#*", "my/a#A,*", "my/a#*,A", "my/a#A,*,B"} {
		if _, err := ParseNamed(in); !errors.Is(err, ErrWildcardFields) {
			t.Errorf("%q: err = %v, want ErrWildcardFields", in, err)
		}
	}
}

func TestParseNamedRefusesBadLists(t *testing.T) {
	long := strings.Repeat("f", maxFieldLen+1)
	for name, in := range map[string]string{
		"a hash and nothing after": "my/a#",
		"empty name in the middle": "my/a#A,,B",
		"trailing comma":           "my/a#A,",
		"leading comma":            "my/a#,A",
		"only a comma":             "my/a#,",
		"repeated name":            "my/a#A,B,A",
		"repeated name next to it": "my/a#A,A",
		"control character":        "my/a#A,B\x01",
		"name too long":            "my/a#A," + long,
		"bad secret":               "my/../b#A",
		"no secret":                "#A,B",
		"wildcard in the path":     "my/*#A",
		"shared room":              "shared/x#A",
		"invalid UTF-8":            "my/a#A,\xff",
	} {
		_, err := ParseNamed(in)
		var re *RefError
		if err == nil || !errors.As(err, &re) {
			t.Errorf("%s: ParseNamed(%q) = %v, want a *RefError", name, in, err)
		}
	}
}

// A mistyped reference can be a pasted value, so no error may echo the text it
// was given, field names included.
func TestParseNamedErrorsNeverEchoTheInput(t *testing.T) {
	for _, in := range []string{
		"my/FAKEVALUE123/../x#A",
		"my/a#FAKEVALUE123,FAKEVALUE123",
		"my/a#A,,FAKEVALUE123",
		"my/a#FAKEVALUE123\x00",
		"FAKEVALUE123*#A",
		"my/a#" + strings.Repeat("FAKEVALUE123", 20),
		"shared/FAKEVALUE123#A",
	} {
		_, err := ParseNamed(in)
		if err == nil {
			t.Fatalf("%q should be invalid", in)
		}
		if strings.Contains(err.Error(), "FAKEVALUE123") {
			t.Errorf("error for %q echoes the input: %v", in, err)
		}
	}
}
