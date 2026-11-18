package bffclient

import (
	"strings"
	"testing"
)

// The API address is read by three constructors (the client that holds a key, the device client and the CI sign-in
// client). They share one parse, and so one rule about the host: plain ASCII, no empty label. Hosts with other characters
// are built from code points and percent escapes, so that no confusable character sits in this file.

func cp(r ...rune) string { return string(r) }

type constructor struct {
	name string
	new  func(base string) error
}

func constructors() []constructor {
	return []constructor{
		{"New", func(base string) error { _, err := New(base, "pat_FAKE-key-0123456789"); return err }},
		{"NewDeviceClient", func(base string) error { _, err := NewDeviceClient(base); return err }},
		{"NewWorkloadClient", func(base string) error { _, err := NewWorkloadClient(base); return err }},
	}
}

func TestEveryConstructorRefusesAHostThatIsNotPlainASCII(t *testing.T) {
	hosts := map[string]string{
		"an escaped U+0130 (maps to i)":      "evil.agentrunt%C4%B0me.io",
		"an escaped Kelvin sign (maps to k)": "a%E2%84%AA.example.test",
		"an escaped zero-width space":        "api.agentruntime.io%E2%80%8B",
		"an escaped full-width a":            "%EF%BD%81pi.agentruntime.io",
		"U+0130 written out":                 "evil.agentrunt" + cp(0x130) + "me.io",
		"a Kelvin sign written out":          "a" + cp(0x212A) + ".example.test",
		"a Cyrillic a":                       cp(0x430) + "pi.agentruntime.io",
		"a full-width a":                     cp(0xFF41) + "pi.agentruntime.io",
		"a zero-width space":                 "api.agentruntime" + cp(0x200B) + ".io",
		"a Greek omicron":                    "api.agentruntime.i" + cp(0x3BF),
		"an e with an accent":                "caf" + cp(0xE9) + ".example.test",
	}
	for _, c := range constructors() {
		for name, host := range hosts {
			for _, scheme := range []string{"https://", "http://"} {
				err := c.new(scheme + host)
				if err == nil {
					t.Errorf("%s accepted %s%q (%s)", c.name, scheme, host, name)
					continue
				}
				if !strings.Contains(err.Error(), "plain ASCII host name") {
					t.Errorf("%s: %s: error %q does not say the host must be plain ASCII", c.name, name, err)
				}
				// The refusal says nothing about the address it refused.
				if strings.Contains(err.Error(), host) || strings.Contains(err.Error(), "evil") {
					t.Errorf("%s: the error repeats the address: %v", c.name, err)
				}
			}
		}
	}
}

func TestEveryConstructorRefusesAHostWithAnEmptyLabel(t *testing.T) {
	for _, c := range constructors() {
		for _, host := range []string{".agentruntime.io", "..agentruntime.io", "a..agentruntime.io", "api..agentruntime.io", "agentruntime..io", ".example.test", "a.b..c"} {
			err := c.new("https://" + host)
			if err == nil || !strings.Contains(err.Error(), "empty part in its host name") {
				t.Errorf("%s: https://%s: error %v", c.name, host, err)
			}
		}
	}
}

func TestEveryConstructorStillTakesAnOrdinaryHost(t *testing.T) {
	for _, c := range constructors() {
		for _, base := range []string{
			"https://api.agentruntime.io", "https://API.AgentRuntime.IO", "https://api.example.test:8443/base", "https://xn--agentruntime-v4g.io",
			"https://api.agentruntime.io.", "https://[2001:db8::1]/x", "http://127.0.0.1:8080", "http://localhost:9", "http://[::1]:9",
		} {
			if err := c.new(base); err != nil {
				t.Errorf("%s refused %q: %v", c.name, base, err)
			}
		}
	}
}

func TestTheCaseOfTheHostIsFoldedOnceForEveryConstructor(t *testing.T) {
	k, err := New("https://API.AgentRuntime.IO/", "pat_FAKE-key-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDeviceClient("https://API.AgentRuntime.IO/")
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWorkloadClient("https://API.AgentRuntime.IO/")
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{"New": k.Authority(), "NewDeviceClient": d.Authority(), "NewWorkloadClient": w.Authority(), "Host": d.Host()} {
		if got != "api.agentruntime.io" {
			t.Errorf("%s = %q, want api.agentruntime.io", name, got)
		}
	}
	if k.BaseURL() != "https://api.agentruntime.io" || d.BaseURL() != "https://api.agentruntime.io" || w.BaseURL() != "https://api.agentruntime.io" {
		t.Errorf("base URLs %q %q %q: the request goes to the folded host", k.BaseURL(), d.BaseURL(), w.BaseURL())
	}
}
