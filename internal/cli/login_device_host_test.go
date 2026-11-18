package cli

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
	"github.com/agentruntime-io/agentruntime-cli/internal/render"
)

// Review round 2: a host that only looks like an AgentRuntime host must not pass as one, and a saved key must not
// go to a host other than the one that issued it. Lookalike characters are written as code points so that no
// confusable character sits in this file.

func cp(r ...rune) string { return string(r) }

var (
	dottedI = cp(0x130)  // LATIN CAPITAL LETTER I WITH DOT ABOVE: Unicode case mapping turns it into "i"
	dotless = cp(0x131)  // LATIN SMALL LETTER DOTLESS I
	kelvin  = cp(0x212A) // KELVIN SIGN: Unicode case mapping turns it into "k"
	fullA   = cp(0xFF41) // FULLWIDTH LATIN SMALL LETTER A
	cyrA    = cp(0x430)  // CYRILLIC SMALL LETTER A
	greekO  = cp(0x3BF)  // GREEK SMALL LETTER OMICRON
	zeroW   = cp(0x200B)
	slash   = cp(0x5c)
)

// network replaces the transport every client in this package uses by default with a recorder that never connects, so
// a test can see what would have been dialled and sent without any traffic.
type network struct {
	mu   sync.Mutex
	seen []seenRequest
}

type seenRequest struct{ Host, Auth, Path string }

func (n *network) record(req *http.Request) {
	n.mu.Lock()
	n.seen = append(n.seen, seenRequest{req.URL.Host, req.Header.Get("Authorization"), req.URL.Path})
	n.mu.Unlock()
}

func (n *network) RoundTrip(req *http.Request) (*http.Response, error) {
	n.record(req)
	return nil, errors.New("recorded: no network in tests")
}

func (n *network) requests() []seenRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]seenRequest(nil), n.seen...)
}

func recordNetwork(t *testing.T) *network {
	t.Helper()
	n := &network{}
	orig := http.DefaultTransport
	http.DefaultTransport = n
	t.Cleanup(func() { http.DefaultTransport = orig })
	return n
}

// ---- a lookalike host never gets as far as a request, a line of output, or an "official" verdict ----------------------

func TestDeviceLoginRefusesAHostWithCharactersOutsideASCII(t *testing.T) {
	hosts := map[string]string{
		"U+0130 (maps to i)":      "evil.agentrunt" + dottedI + "me.io",
		"dotless i":               "evil.agentruntime.io" + dotless,
		"Kelvin sign (maps to k)": "a" + kelvin + ".agentruntime.io",
		"full-width a":            fullA + "pi.agentruntime.io",
		"Cyrillic a":              cyrA + "pi.agentruntime.io",
		"Greek omicron":           "api.agentruntime.i" + greekO,
		"zero-width character":    "api.agentruntime" + zeroW + ".io",
		"an escaped U+0130":       "evil.agentrunt%C4%B0me.io",
		"an escaped Kelvin sign":  "a%E2%84%AA.agentruntime.io",
	}
	for name, host := range hosts {
		isolate(t)
		net := recordNetwork(t)
		code, out, errOut := runApp(t, false, newDevEnv().tweak, "login", "--device", "--api-url", "https://"+host, "--ref", "my/*", "--yes")
		if code != 1 || !strings.Contains(errOut, "the API address must use a plain ASCII host name") {
			t.Errorf("%s: exit %d\n%s\n%s", name, code, out, errOut)
		}
		// Nothing is printed (so no "API:" line with a spoofed name), nothing is dialled, nothing is saved.
		if out != "" || len(net.requests()) != 0 {
			t.Errorf("%s: stdout %q, requests %v", name, out, net.requests())
		}
		nothingSaved(t)
	}
}

func TestDeviceLoginTreatsAnASCIIFormOfALookalikeAsForeign(t *testing.T) {
	// The punycode form of agentrunt<U+0130>me.io is what the network would dial for the lookalike. It is plain ASCII,
	// and it is not an AgentRuntime host.
	for _, host := range []string{"evil.xn--agentruntime-v4g.io", "api.agentruntime.io.", "api.agentruntime.io.evil.example", "evilagentruntime.io", "a_b.agentruntime.io"} {
		isolate(t)
		net := recordNetwork(t)
		code, out, errOut := runApp(t, false, func(a *App) { newDevEnv().tweak(a); noTerminal(t)(a) }, "login", "--device", "--api-url", "https://"+host, "--ref", "my/*")
		if code != 2 || !strings.Contains(errOut, "WARNING: the API host is "+host+", which is not an agentruntime.io host.") ||
			!strings.Contains(errOut, "refusing to use an API host outside agentruntime.io without a person to confirm it") {
			t.Errorf("%s: exit %d\n%s\n%s", host, code, out, errOut)
		}
		if !strings.HasPrefix(out, "API: "+host+"\n") || len(net.requests()) != 0 {
			t.Errorf("%s: stdout %q, requests %v", host, out, net.requests())
		}
		nothingSaved(t)
	}
}

func TestTheFirstLineNamesTheHostThatIsDialledAndNoOtherForm(t *testing.T) {
	// An official host written in capitals and with its default port: the line, the stored value and the request all
	// carry one lower-case ASCII form. The transport is a recorder, so nothing leaves the machine.
	isolate(t)
	net := recordNetwork(t)
	code, out, errOut := runApp(t, false, newDevEnv().tweak, "login", "--device", "--api-url", "HTTPS://API.AgentRuntime.IO:443", "--ref", "my/*")
	if code != 1 || !strings.HasPrefix(out, "API: api.agentruntime.io\n") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	reqs := net.requests()
	if len(reqs) != 1 || reqs[0].Host != "api.agentruntime.io:443" && reqs[0].Host != "api.agentruntime.io" {
		t.Errorf("requests %v: the dialled host must be the one that was printed", reqs)
	}
	if strings.Contains(errOut, "WARNING") {
		t.Errorf("an official host gave a warning:\n%s", errOut)
	}
}

func TestAVerificationAddressOnALookalikeHostIsNotUsable(t *testing.T) {
	for _, address := range []string{
		"https://console.agentrunt%C4%B0me.io/device", // U+0130, escaped
		"https://a%E2%84%AA.agentruntime.io/device",   // Kelvin sign, escaped
		"https://console.agentruntime.io%E2%80%8B/device",
	} {
		if u, err := parseVerificationURL(address); err == nil {
			t.Errorf("%q accepted (host %q)", address, u.Hostname())
		}
	}
	// Written out as characters, they never pass the printable-ASCII rule.
	for _, host := range []string{"console.agentrunt" + dottedI + "me.io", "a" + kelvin + ".agentruntime.io"} {
		if _, err := parseVerificationURL("https://" + host + "/device"); err == nil {
			t.Errorf("%q accepted", host)
		}
	}
	// And the family check refuses them too, whatever Unicode case mapping would make of them.
	for _, host := range []string{"console.agentrunt" + dottedI + "me.io", "a" + kelvin + ".agentruntime.io", "agentruntime.io" + dotless} {
		if inAPIFamily("api.agentruntime.io", host) || inAPIFamily(host, "api.agentruntime.io") {
			t.Errorf("inAPIFamily accepted %q", host)
		}
	}
	// A start answer carrying one is refused as unusable.
	isolate(t)
	d := newDeviceAPI(t)
	d.start = func(int) devAnswer {
		return ok(codeBody("https://console.agentrunt%C4%B0me.io/device", "", 600, 5))
	}
	code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...)
	if code != 1 || !strings.Contains(errOut, "the sign-in address is not usable") || d.pollCount() != 0 {
		t.Errorf("exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestTheConfirmationDoesNotAcceptALookalikeOfTheHostName(t *testing.T) {
	// Typing a character that Unicode case folding equates with one of the host's letters is not typing the host name.
	confirm := func(typed string) error {
		var errb bytes.Buffer
		app := NewApp(strings.NewReader(typed+"\n"), io.Discard, &errb)
		app.stderr = render.NewStyle(&errb, true)
		return app.confirmForeignAPI("ak.example.test", "ak.example.test", false)
	}
	if err := confirm("ak.example.test"); err != nil {
		t.Errorf("the host name itself was not accepted: %v", err)
	}
	if err := confirm("AK.Example.TEST"); err != nil {
		t.Errorf("the host name in capitals was not accepted: %v", err)
	}
	for _, typed := range []string{"a" + kelvin + ".example.test", "ak" + zeroW + ".example.test", "ak.example.test."} {
		if err := confirm(typed); err == nil || !strings.Contains(err.Error(), "not confirmed") {
			t.Errorf("%q confirmed the host", typed)
		}
	}
}

// ---- a saved key is not sent to a host that did not issue it ------------------------------------------------------------

func storeKey(t *testing.T, issued string) {
	t.Helper()
	writeConfig(t, "default", map[string]*config.Profile{"default": {
		Token: testToken, ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339), IssuedByHost: issued}})
}

func TestTheSavedKeyIsRefusedToAnotherHostUnlessAllowOtherHostIsGiven(t *testing.T) {
	api := newVaultAPI(t)
	used := authority(&deviceAPI{Server: api.Server})
	args := []string{"secrets", "check", "--api-url", api.URL, "workspace/live/stripe#API_KEY"}
	refusal := `refusing to send the access key saved in profile "default" to ` + used + `: it was issued by other.example, and a key must only go to the host that issued it.`

	// Refused: a clear message, exit 1, and the fake received nothing (the key never left the CLI).
	isolate(t)
	storeKey(t, "other.example")
	code, out, errOut := runApp(t, false, atClock, args...)
	if code != 1 || !strings.Contains(errOut, refusal) || !strings.Contains(errOut, "add --allow-other-host") || strings.Contains(errOut, "add --yes") || out != "" || api.count() != 0 {
		t.Fatalf("exit %d, %d requests\n%s\n%s", code, api.count(), out, errOut)
	}
	if strings.Contains(errOut, testToken) {
		t.Errorf("the key is in the message:\n%s", errOut)
	}

	// With --allow-other-host (anywhere on the command line): a warning, once, and the key is sent.
	for _, withYes := range [][]string{append([]string{"--allow-other-host"}, args...), append(append([]string{}, args...), "--allow-other-host")} {
		isolate(t)
		storeKey(t, "other.example")
		before := api.count()
		_, _, errOut = runApp(t, false, atClock, withYes...)
		want := "warning: the saved access key was issued by other.example, but this command talks to " + used + " (sent because of --allow-other-host)\n"
		if !strings.HasPrefix(errOut, want) || strings.Count(errOut, "warning:") != 1 || api.count() != before+1 {
			t.Errorf("%v: stderr %q, requests %d -> %d", withYes, errOut, before, api.count())
		}
		if got := api.last(); got.Auth != "Bearer "+testToken {
			t.Errorf("the saved key was not the one sent: %+v", got)
		}
	}

	// The same host (case and a default port do not matter), no recorded host, a key from --pat or the environment:
	// no refusal and no warning.
	for _, c := range []struct {
		name, issued string
		extra        []string
		env          bool
	}{
		{"same host", used, nil, false},
		{"same host in capitals", strings.ToUpper(used), nil, false},
		{"no recorded host", "", nil, false},
		{"a key from --pat", "other.example", []string{"--pat", testToken}, false},
		{"a key from the environment", "other.example", nil, true},
	} {
		isolate(t)
		storeKey(t, c.issued)
		if c.env {
			t.Setenv("AGENTRUNTIME_PAT", testToken)
		}
		_, _, errOut := runApp(t, false, atClock, append(append([]string{}, c.extra...), args...)...)
		if strings.Contains(errOut, "refusing") || strings.Contains(errOut, "warning:") {
			t.Errorf("%s: %s", c.name, errOut)
		}
	}
}

func TestPlatformMCPCommandsRefuseTheSavedKeyToo(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	mcpHost := authority(&deviceAPI{Server: srv.Server})
	put := func(issued string) {
		writeConfig(t, "default", map[string]*config.Profile{"default": {URL: srv.URL, Token: testToken, ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339), IssuedByHost: issued}})
	}
	put("other.example")
	code, _, errOut := runApp(t, false, atClock, "workflows", "list")
	if code != 1 || !strings.Contains(errOut, "refusing to send the access key saved in profile \"default\" to "+mcpHost+": it was issued by other.example") || srv.last("workflows_list") != nil {
		t.Fatalf("exit %d, called %v\n%s", code, srv.last("workflows_list"), errOut)
	}
	// With --allow-other-host it goes, after a warning.
	code, _, errOut = runApp(t, false, atClock, "--allow-other-host", "workflows", "list")
	if code != 0 || !strings.HasPrefix(errOut, "warning: the saved access key was issued by other.example, but this command talks to "+mcpHost) || srv.last("workflows_list") == nil {
		t.Errorf("--allow-other-host: exit %d\n%s", code, errOut)
	}
	// The host that issued it: neither.
	isolate(t)
	put(mcpHost)
	if code, _, errOut := runApp(t, false, atClock, "workflows", "list"); code != 0 || strings.Contains(errOut, "warning:") || strings.Contains(errOut, "refusing") {
		t.Errorf("matching host: exit %d\n%s", code, errOut)
	}
}

func TestCommandsThatSendNothingAreNotRefused(t *testing.T) {
	isolate(t)
	storeKey(t, "other.example")
	for _, args := range [][]string{{"profile", "list"}, {"profile", "list", "--json"}, {"profile", "path"}, {"version"}, {"logout"}} {
		code, _, errOut := run(t, "", args...)
		if code != 0 || strings.Contains(errOut, "refusing") || strings.Contains(errOut, "warning:") {
			t.Errorf("%v: exit %d\n%s", args, code, errOut)
		}
	}
}

// ---- the issuing host is compared byte for byte (ASCII letter case aside) ------------------------------------------------

func TestALookalikeIssuingHostIsNeverTheSameHost(t *testing.T) {
	// A profile edited by hand, or written by something else, names the issuer with characters that Unicode case folding
	// would equate with the host in use. They are not the same host.
	cases := []struct{ name, issued, api string }{
		{"U+0130 for i", "api.agentrunt" + dottedI + "me.io", "api.agentruntime.io"},
		{"Kelvin sign for k", "a" + kelvin + ".example.test", "ak.example.test"},
		{"full-width a", fullA + "pi.agentruntime.io", "api.agentruntime.io"},
	}
	for _, c := range cases {
		isolate(t)
		net := recordNetwork(t)
		storeKey(t, c.issued)
		code, out, errOut := runApp(t, false, atClock, "secrets", "check", "--api-url", "https://"+c.api, "workspace/live/stripe#API_KEY")
		if code != 1 || !strings.Contains(errOut, "refusing to send the access key saved in profile \"default\" to "+c.api+": it was issued by ") {
			t.Errorf("%s: exit %d\n%s\n%s", c.name, code, out, errOut)
		}
		// The issuer is shown with its odd character as an escape, not as a letter that looks like the real one.
		if !strings.Contains(errOut, slash+"u") || strings.Contains(errOut, dottedI) || strings.Contains(errOut, kelvin) || strings.Contains(errOut, fullA) {
			t.Errorf("%s: the lookalike issuer is not shown escaped:\n%s", c.name, errOut)
		}
		if len(net.requests()) != 0 {
			t.Errorf("%s: the key was sent: %v", c.name, net.requests())
		}
	}
	// With --allow-other-host it is sent (to the recorder), and the one request carries the saved key.
	isolate(t)
	net := recordNetwork(t)
	storeKey(t, "api.agentrunt"+dottedI+"me.io")
	runApp(t, false, atClock, "--allow-other-host", "secrets", "check", "--api-url", "https://api.agentruntime.io", "workspace/live/stripe#API_KEY")
	if reqs := net.requests(); len(reqs) != 1 || reqs[0].Auth != "Bearer "+testToken || reqs[0].Host != "api.agentruntime.io" {
		t.Errorf("--allow-other-host: requests %v", reqs)
	}
}

func TestAPlatformMCPAddressWithALookalikeHostIsRefused(t *testing.T) {
	isolate(t)
	net := recordNetwork(t)
	writeConfig(t, "default", map[string]*config.Profile{"default": {
		URL: "https://mcp.agentrunt" + dottedI + "me.io/mcp", Token: testToken,
		ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339), IssuedByHost: "api.agentruntime.io"}})
	code, _, errOut := runApp(t, false, atClock, "workflows", "list")
	if code != 1 || !strings.Contains(errOut, "refusing to send the access key") || !strings.Contains(errOut, slash+"u0130") || strings.Contains(errOut, dottedI) {
		t.Errorf("exit %d\n%s", code, errOut)
	}
	if len(net.requests()) != 0 {
		t.Errorf("the key was sent: %v", net.requests())
	}
}
