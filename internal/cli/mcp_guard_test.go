package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

// The Platform MCP calls carry the saved access key too: they must neither follow a redirect nor go over plain http.

func TestAPlatformMCPCommandNeverSendsTheKeyOnAfterARedirect(t *testing.T) {
	var mu sync.Mutex
	var bAuth []string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		bAuth = append(bAuth, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer b.Close()
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", b.URL+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer a.Close()

	isolate(t)
	// The key was issued by the host the command talks to, so the key check passes and the request goes out.
	issuer := strings.TrimPrefix(a.URL, "http://")
	writeConfig(t, "default", map[string]*config.Profile{"default": {URL: a.URL + "/mcp", Token: testToken,
		ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339), IssuedByHost: issuer}})
	code, out, errOut := runApp(t, false, atClock, "workflows", "list")
	if code != 1 || !strings.Contains(errOut, "answered with a redirect") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bAuth) != 0 {
		t.Errorf("the server that was redirected to received %d request(s) with %v", len(bAuth), bAuth)
	}
	if strings.Contains(out+errOut, testToken) {
		t.Error("the key is in the output")
	}
}

func TestAPlatformMCPCommandRefusesPlainHTTPToTheOfficialHostEvenWhenTheKeyMatches(t *testing.T) {
	isolate(t)
	net := recordNetwork(t)
	// A saved key issued by the official API host, and the Platform MCP address pointed at the official host over http
	// (a variable in the environment is how that happens): the key check passes, the scheme check must not.
	writeConfig(t, "default", map[string]*config.Profile{"default": {Token: testToken,
		ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339), IssuedByHost: "api.agentruntime.io"}})
	t.Setenv("AGENTRUNTIME_MCP_URL", "http://mcp.agentruntime.io/mcp")
	code, out, errOut := runApp(t, false, atClock, "workflows", "list")
	if code != 1 || !strings.Contains(errOut, "refusing to send an access key over plain http") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if reqs := net.requests(); len(reqs) != 0 {
		t.Errorf("a request was made: %v", reqs)
	}
	if strings.Contains(out+errOut, testToken) {
		t.Error("the key is in the output")
	}
}

func TestReadmeSaysEveryKeyCarryingCallIsHTTPSAndFollowsNoRedirect(t *testing.T) {
	text := flat(readme(t))
	for _, want := range []string{
		"Every call that carries an access key, to Platform MCP or to the API, is made only over `https`",
		"never follows a redirect", "A host name must be plain ASCII",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
}
