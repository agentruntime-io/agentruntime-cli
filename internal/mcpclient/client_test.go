package mcpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every key below is fake.
const fakeKey = "pat_FAKE-mcp_key-0123456789abcdefghijklmnop"

// hitLog records the requests a fake server received.
type hitLog struct {
	mu   sync.Mutex
	auth []string
	path []string
}

func (h *hitLog) add(r *http.Request) {
	h.mu.Lock()
	h.auth = append(h.auth, r.Header.Get("Authorization"))
	h.path = append(h.path, r.URL.Path)
	h.mu.Unlock()
}

func (h *hitLog) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.auth)
}

func (h *hitLog) sawKey() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, a := range h.auth {
		if strings.Contains(a, fakeKey) {
			return true
		}
	}
	return false
}

// redirectPair is two servers: A answers every request with a redirect to B, and B records what reaches it.
func redirectPair(t *testing.T, status int) (a, b *httptest.Server, hitsA, hitsB *hitLog) {
	t.Helper()
	hitsA, hitsB = &hitLog{}, &hitLog{}
	b = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsB.add(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(b.Close)
	a = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsA.add(r)
		w.Header().Set("Location", b.URL+r.URL.Path)
		w.WriteHeader(status)
	}))
	t.Cleanup(a.Close)
	return a, b, hitsA, hitsB
}

func connectErr(t *testing.T, endpoint string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Connect(ctx, endpoint, fakeKey)
	if err == nil {
		_ = c.Close()
	}
	return err
}

func TestAnAnsweredRedirectIsNeverFollowedAndTheKeyNeverReachesTheOtherServer(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		a, b, hitsA, hitsB := redirectPair(t, status)
		err := connectErr(t, a.URL+"/mcp")
		if err == nil || !strings.Contains(err.Error(), "answered with a redirect") || !strings.Contains(err.Error(), "never follows redirects") {
			t.Errorf("%d: error %v", status, err)
			continue
		}
		if hitsB.count() != 0 {
			t.Errorf("%d: the server that was redirected to received %d request(s): %v", status, hitsB.count(), hitsB.auth)
		}
		if hitsB.sawKey() {
			t.Errorf("%d: the other server received the access key", status)
		}
		// The configured server did get the key: it is the one that was asked for.
		if !hitsA.sawKey() {
			t.Errorf("%d: the configured server did not get the key (the test is not exercising the request)", status)
		}
		if strings.Contains(err.Error(), fakeKey) || strings.Contains(err.Error(), b.URL) {
			t.Errorf("%d: the error repeats the key or the redirect target: %v", status, err)
		}
	}
}

func TestTheHTTPClientHasNoRedirectFollowing(t *testing.T) {
	c := newHTTPClient("  " + fakeKey + "  ")
	if c.CheckRedirect == nil || !errors.Is(c.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("the client follows redirects")
	}
	// Driven directly: the key is added with its white space trimmed, and the redirect is an error.
	a, _, hitsA, hitsB := redirectPair(t, 307)
	_, err := c.Get(a.URL + "/x")
	if err == nil || !strings.Contains(err.Error(), "answered with a redirect (HTTP 307)") {
		t.Errorf("error %v", err)
	}
	if hitsB.count() != 0 || !hitsA.sawKey() {
		t.Errorf("B %d requests, A saw the key: %v", hitsB.count(), hitsA.sawKey())
	}
	// Exactly the key, without the white space that came with it.
	hitsA.mu.Lock()
	defer hitsA.mu.Unlock()
	if len(hitsA.auth) != 1 || hitsA.auth[0] != "Bearer "+fakeKey {
		t.Errorf("the Authorization header was %q, want %q", hitsA.auth, "Bearer "+fakeKey)
	}
}

type fixedTransport struct{ status int }

func (f *fixedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.status, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
}

func TestOnlyARedirectStatusIsAnError(t *testing.T) {
	for status, wantErr := range map[int]bool{200: false, 201: false, 204: false, 304: false, 299: false, 300: true, 301: true, 302: true, 303: true, 305: true, 307: true, 308: true, 399: true, 400: false, 401: false, 404: false, 500: false} {
		rt := &headerRoundTripper{token: fakeKey, base: &fixedTransport{status: status}}
		req, _ := http.NewRequest(http.MethodPost, "https://mcp.example.test/mcp", nil)
		resp, err := rt.RoundTrip(req)
		if (err != nil) != wantErr {
			t.Errorf("status %d: error %v, want an error: %v", status, err, wantErr)
		}
		if err == nil && resp.StatusCode != status {
			t.Errorf("status %d: the answer changed to %d", status, resp.StatusCode)
		}
	}
}

// ---- plain http and odd hosts ------------------------------------------------------------------------------------------

type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.seen = append(r.seen, req.URL.Scheme+"://"+req.URL.Host)
	r.mu.Unlock()
	return nil, errors.New("recorded: no network in tests")
}

func (r *recorder) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// recordNetwork replaces the transport a client uses by default with a recorder that never connects.
func recordNetwork(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	orig := http.DefaultTransport
	http.DefaultTransport = r
	t.Cleanup(func() { http.DefaultTransport = orig })
	return r
}

func TestAKeyIsNeverSentOverPlainHTTPToAHostThatIsNotLoopback(t *testing.T) {
	net := recordNetwork(t)
	// The non-ASCII hosts are written as percent escapes, so that no confusable character sits in this file.
	for _, endpoint := range []string{
		"http://mcp.agentruntime.io/mcp", // the reported case: the right host, the wrong scheme
		"http://api.example.test/mcp", "http://127.0.0.2:8340/mcp", "http://127.1/mcp", "http://0.0.0.0/mcp", "http://2130706433/mcp",
		"http://foo.localhost/mcp", "http://localhost.example/mcp", "http://127.0.0.1.example/mcp", "http://[::ffff:127.0.0.1]/mcp",
		"http://LOCALHOST:8340/mcp", "http://Localhost/mcp",
		"ftp://mcp.agentruntime.io/mcp", "ws://localhost/mcp", "wss://mcp.agentruntime.io/mcp", "file:///etc/passwd", "javascript:alert(1)",
		"//mcp.agentruntime.io/mcp", "mcp.agentruntime.io/mcp", "/mcp", "not a url",
		"https://user:pw@mcp.agentruntime.io/mcp", "https://mcp.agentruntime.io@evil.example/mcp", "http://user@localhost/mcp",
		"https://mcp.agentrunt%C4%B0me.io/mcp", "https://a%E2%84%AA.example.test/mcp", "https://mcp.agentruntime.io%E2%80%8B/mcp",
		"https://.agentruntime.io/mcp", "https://a..agentruntime.io/mcp", "https://mcp..agentruntime.io/mcp",
	} {
		err := connectErr(t, endpoint)
		if err == nil {
			t.Errorf("%q: Connect succeeded", endpoint)
			continue
		}
		if strings.Contains(err.Error(), fakeKey) {
			t.Errorf("%q: the error carries the key: %v", endpoint, err)
		}
		if strings.HasPrefix(endpoint, "http://") && !strings.Contains(err.Error(), "refusing to send an access key over plain http") && !strings.Contains(err.Error(), "must not carry credentials") {
			t.Errorf("%q: error %v", endpoint, err)
		}
	}
	if reqs := net.requests(); len(reqs) != 0 {
		t.Errorf("requests were made for refused addresses: %v", reqs)
	}
}

func TestAddressesThatAreAllowed(t *testing.T) {
	for _, endpoint := range []string{
		"https://mcp.agentruntime.io/mcp", "https://MCP.AgentRuntime.IO/mcp", "https://mcp.example.test:8443/mcp", "https://[2001:db8::1]/mcp",
		"http://127.0.0.1:8340/mcp", "http://localhost:8340/mcp", "http://[::1]:8340/mcp", "http://127.0.0.1/mcp",
	} {
		if err := checkEndpoint(endpoint); err != nil {
			t.Errorf("%q refused: %v", endpoint, err)
		}
	}
	// An https address is reached (the recording transport refuses to connect, so Connect fails there, after the request
	// was made).
	net := recordNetwork(t)
	if err := connectErr(t, "https://MCP.AgentRuntime.IO/mcp"); err == nil {
		t.Error("Connect succeeded against the recorder")
	}
	if reqs := net.requests(); len(reqs) == 0 || reqs[0] != "https://MCP.AgentRuntime.IO" {
		t.Errorf("requests %v", reqs)
	}
}

func TestNoEndpointIsStillItsOwnError(t *testing.T) {
	if err := connectErr(t, "   "); err == nil || !strings.Contains(err.Error(), "no MCP endpoint configured") {
		t.Errorf("error %v", err)
	}
}

// A port such as 4010 or 4030 must not make a redirect read like a 401 or a 403 in the message.
func TestTheRedirectMessageIsNotMistakenForAStatusBecauseOfDigitsInTheAddress(t *testing.T) {
	for _, port := range []string{"4010", "4030", "40100", "14031"} {
		err := explainConnectError("http://127.0.0.1:"+port+"/mcp", fakeKey, errors.New(`Post "http://127.0.0.1:`+port+`/mcp": the Platform MCP address answered with a redirect (HTTP 307). The CLI never follows redirects`))
		if err == nil || !strings.Contains(err.Error(), "answered with a redirect") || strings.Contains(err.Error(), "rejected the token") || strings.Contains(err.Error(), "denied access") {
			t.Errorf("port %s: %v", port, err)
		}
	}
}
