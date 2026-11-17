package apihost

import (
	"net/url"
	"testing"
)

// Lookalike characters are built from code points, so that no invisible or confusable character sits in this file.
func r(cp ...rune) string { return string(cp) }

var (
	dottedI   = r(0x130)  // LATIN CAPITAL LETTER I WITH DOT ABOVE: lower-cases to "i" under Unicode case mapping
	dotlessI  = r(0x131)  // LATIN SMALL LETTER DOTLESS I: upper-cases to "I"
	kelvin    = r(0x212A) // KELVIN SIGN: lower-cases to "k"
	longS     = r(0x17F)  // LATIN SMALL LETTER LONG S: folds to "s"
	fullA     = r(0xFF41) // FULLWIDTH LATIN SMALL LETTER A
	cyrA      = r(0x430)  // CYRILLIC SMALL LETTER A
	cyrE      = r(0x435)  // CYRILLIC SMALL LETTER IE, looks like "e"
	greekO    = r(0x3BF)  // GREEK SMALL LETTER OMICRON, looks like "o"
	zeroWidth = r(0x200B)
)

func TestFoldIsASCIIOnly(t *testing.T) {
	cases := map[string]string{
		"API.AgentRuntime.IO": "api.agentruntime.io",
		"already.lower":       "already.lower",
		"127.0.0.1:8080":      "127.0.0.1:8080",
		"[::1]":               "[::1]",
		// Nothing that is not an ASCII capital changes, whatever Unicode would do with it.
		"evil.agentrunt" + dottedI + "me.io": "evil.agentrunt" + dottedI + "me.io",
		kelvin + "." + dotlessI:              kelvin + "." + dotlessI,
		fullA + "BC":                         fullA + "bc",
	}
	for in, want := range cases {
		if got := Fold(in); got != want {
			t.Errorf("Fold(%q) = %q, want %q", in, got, want)
		}
	}
	// strings.ToLower maps U+0130 to "i" and the Kelvin sign to "k"; Same must not.
	if Same("agentrunt"+dottedI+"me.io", "agentruntime.io") || Same("a"+kelvin, "ak") {
		t.Error("Same used Unicode case mapping")
	}
}

func TestOfficial(t *testing.T) {
	official := []string{
		"agentruntime.io", "api.agentruntime.io", "a.b.agentruntime.io", "API.AgentRuntime.IO", "console.AGENTRUNTIME.io",
		"localhost", "LOCALHOST", "127.0.0.1", "::1",
	}
	for _, h := range official {
		if !Official(h) {
			t.Errorf("Official(%q) = false", h)
		}
	}
	foreign := map[string]string{
		"evil.example":                         "another domain",
		"agentruntime.io.evil.example":         "official name as a prefix",
		"evilagentruntime.io":                  "no dot before the name",
		"notagentruntime.io":                   "no dot before the name",
		"agentruntime.com":                     "another top-level domain",
		"api.agentruntime.io.":                 "trailing dot",
		"agentruntime.io.":                     "trailing dot",
		"api.agentruntime.io.evil.test":        "official name inside",
		"127.0.0.2":                            "not the exact loopback host",
		"foo.localhost":                        "not the exact loopback host",
		"localhost.example":                    "loopback name as a prefix",
		"":                                     "empty",
		"io":                                   "bare suffix",
		"evil.xn--agentruntime-v4g.io":         "the punycode form of a lookalike",
		"api.agentruntime.io@evil.test":        "user-info trick (a host never holds an @)",
		"api.agentruntime.io:8443":             "a port is not part of a host",
		"api.agentruntime.io evil":             "a space",
		"api.agentruntime.io\t":                "a control character",
		"a_b.agentruntime.io":                  "an underscore is outside the plain host characters",
		"evil.agentrunt" + dottedI + "me.io":   "U+0130 (a Unicode case mapping turns it into i)",
		"evil.agentruntime.io" + dotlessI:      "dotless i",
		"a" + kelvin + ".agentruntime.io":      "Kelvin sign (maps to k)",
		longS + ".agentruntime.io":             "long s under the official domain",
		fullA + "gentruntime.io":               "full-width a",
		cyrA + "gentruntime.io":                "Cyrillic a",
		"agentruntim" + cyrE + ".io":           "Cyrillic e",
		"agentruntime.i" + greekO:              "Greek omicron",
		"api.agentruntime" + zeroWidth + ".io": "a zero-width character",
		"api.agentruntime.io" + zeroWidth:      "a zero-width character at the end",
		"%C4%B0.agentruntime.io":               "an escape that was not decoded",
		"api.agentruntime.io/evil":             "a path",
		"[::1]":                                "brackets are not part of a host name",
	}
	for h, why := range foreign {
		if Official(h) {
			t.Errorf("Official(%q) = true, but it is foreign: %s", h, why)
		}
	}
}

func TestASCIIAndClean(t *testing.T) {
	for _, h := range []string{"a", "api.agentruntime.io", "127.0.0.1", "::1", "xn--agentruntime-v4g.io", "a_b"} {
		if !ASCII(h) {
			t.Errorf("ASCII(%q) = false", h)
		}
	}
	for _, h := range []string{"", " ", "a b", "a\tb", "a\x7fb", "a" + dottedI, r(0xE9), "a\x00"} {
		if ASCII(h) {
			t.Errorf("ASCII(%q) = true", h)
		}
	}
	for _, h := range []string{"api.agentruntime.io", "127.0.0.1", "::1", "a-b.c", "xn--a-b"} {
		if !Clean(h) {
			t.Errorf("Clean(%q) = false", h)
		}
	}
	for _, h := range []string{"", "a_b", "a b", "a@b", "a/b", "a%41", "[::1]", "a:b/c", "a" + kelvin} {
		if Clean(h) {
			t.Errorf("Clean(%q) = true", h)
		}
	}
}

func TestAuthority(t *testing.T) {
	cases := map[string]string{
		"https://api.agentruntime.io":      "api.agentruntime.io",
		"https://API.AgentRuntime.io:443/": "api.agentruntime.io",
		"http://127.0.0.1:8080":            "127.0.0.1:8080",
		"http://[::1]:9":                   "[::1]:9",
		"https://[::1]":                    "[::1]",
		"https://h.example:8443":           "h.example:8443",
		"http://h.example:80":              "h.example",
		"https://h.example:80":             "h.example:80",
		"https://h.example/base/path":      "h.example",
		"https://api.agentruntime.io.":     "api.agentruntime.io.",
		"://":                              "",
		"":                                 "",
		// Not ASCII, however it is written: no authority at all, so it can neither be shown nor stored as another name.
		"https://evil.agentrunt" + dottedI + "me.io":    "",
		"https://evil.agentrunt%C4%B0me.io":             "",
		"https://" + fullA + "pi.agentruntime.io":       "",
		"https://api.agentruntime.io" + zeroWidth + "/": "",
	}
	for in, want := range cases {
		if got := AuthorityOf(in); got != want {
			t.Errorf("AuthorityOf(%q) = %q, want %q", in, got, want)
		}
	}
	u, _ := url.Parse("https://API.Example.test:8443")
	if got := Authority(u); got != "api.example.test:8443" {
		t.Errorf("Authority = %q", got)
	}
}

func TestDisplayShowsEveryOtherCharacterAsAnEscape(t *testing.T) {
	bs := string(rune(0x5c)) // a backslash, written without one in this file
	cases := map[string]string{
		"api.agentruntime.io":                "api.agentruntime.io",
		"evil.agentrunt" + dottedI + "me.io": "evil.agentrunt" + bs + "u0130me.io",
		kelvin:                               bs + "u212a",
		"a" + r(0x1F600) + "b":               "a" + bs + "U0001f600b",
		"a b":                                "a" + bs + "u0020b",
	}
	for in, want := range cases {
		if got := Display(in); got != want {
			t.Errorf("Display(%q) = %q, want %q", in, got, want)
		}
	}
}
