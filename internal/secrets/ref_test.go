package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	long := strings.Repeat("a", maxPathLen)
	cases := []struct {
		in   string
		want Ref
		norm string
	}{
		{"workspace/live/stripe", Ref{"workspace", "live/stripe", ""}, "workspace/live/stripe"},
		{"secret:workspace/live/stripe#API_KEY", Ref{"workspace", "live/stripe", "API_KEY"}, "workspace/live/stripe#API_KEY"},
		{"my/deploy", Ref{"my", "deploy", ""}, "my/deploy"},
		{"secret:my/deploy#TOKEN", Ref{"my", "deploy", "TOKEN"}, "my/deploy#TOKEN"},
		{"project/a/b/c#X", Ref{"project", "a/b/c", "X"}, "project/a/b/c#X"},
		{"live/stripe", Ref{"", "live/stripe", ""}, "live/stripe"},
		{"secret:live/stripe#K", Ref{"", "live/stripe", "K"}, "live/stripe#K"},
		{"deploy", Ref{"", "deploy", ""}, "deploy"},
		// A first segment my/project/workspace is always a room; the way to a
		// workspace folder called "my" is to name the room.
		{"workspace/my/x", Ref{"workspace", "my/x", ""}, "workspace/my/x"},
		{"  secret:my/a  ", Ref{"my", "a", ""}, "my/a"},
		{"my/a#b#c", Ref{"my", "a", "b#c"}, "my/a#b#c"},
		{"my/a#api key", Ref{"my", "a", "api key"}, "my/a#api key"},
		{"my/with space/x", Ref{"my", "with space/x", ""}, "my/with space/x"},
		// Matching is exact-case: My/ is not the room.
		{"My/a", Ref{"", "My/a", ""}, "My/a"},
		{"my/" + long[:maxPathLen-3], Ref{"my", long[:maxPathLen-3], ""}, "my/" + long[:maxPathLen-3]},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, got, c.want)
		}
		if got.String() != c.norm {
			t.Errorf("Parse(%q).String() = %q, want %q", c.in, got.String(), c.norm)
		}
		if again, err := Parse(got.String()); err != nil || again != got {
			t.Errorf("round trip of %q: %+v, %v", c.in, again, err)
		}
		if got.Whole() != (c.want.Field == "") {
			t.Errorf("Whole() wrong for %q", c.in)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{"empty", ""},
		{"blank", "   "},
		{"only prefix", "secret:"},
		{"room only my", "my"},
		{"room only workspace", "workspace"},
		{"room only project", "project"},
		{"room with trailing slash", "my/"},
		{"leading slash", "/a"},
		{"trailing slash", "a/"},
		{"double slash", "a//b"},
		{"dot dot", "a/../b"},
		{"dot dot only", ".."},
		{"dot segment", "a/./b"},
		{"backslash", `a\b`},
		{"wildcard last", "workspace/live/*"},
		{"wildcard anywhere", "a*b/c"},
		{"empty field", "my/a#"},
		{"shared room", "shared/x"},
		{"shared alone", "shared"},
		{"nul in path", "a\x00b"},
		{"control in field", "my/a#b\x01"},
		{"newline in path", "a\nb"},
		{"invalid utf8", "a\xff\xfeb"},
		{"path too long", "my/" + strings.Repeat("a", maxPathLen)},
		{"field too long", "my/a#" + strings.Repeat("f", maxFieldLen+1)},
	}
	for _, c := range cases {
		_, err := Parse(c.in)
		if err == nil {
			t.Errorf("%s: Parse(%q) should fail", c.name, c.in)
			continue
		}
		var re *RefError
		if !errors.As(err, &re) {
			t.Errorf("%s: want *RefError, got %T", c.name, err)
		}
	}
}

// A mistyped reference can be a pasted value, so the error must never echo it.
func TestParseErrorNeverEchoesInput(t *testing.T) {
	for _, in := range []string{
		"my/FAKEVALUE123/../x",
		"FAKEVALUE123*",
		"my/FAKEVALUE123#",
		"shared/FAKEVALUE123",
		`FAKEVALUE123\x`,
		"//FAKEVALUE123",
		"my/a#FAKEVALUE123\x00",
	} {
		_, err := Parse(in)
		if err == nil {
			t.Fatalf("%q should be invalid", in)
		}
		if strings.Contains(err.Error(), "FAKEVALUE123") {
			t.Errorf("error for %q echoes the input: %v", in, err)
		}
	}
}
