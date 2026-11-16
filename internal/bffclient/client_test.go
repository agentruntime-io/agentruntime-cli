package bffclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testToken = "pat_fake_token_0123456789"

// fake is a stand-in for the API fetch route; it records what it was sent.
type fake struct {
	*httptest.Server
	mu     sync.Mutex
	hits   int
	header http.Header
	body   []byte
	status int
	answer string
	extra  map[string]string // response headers
}

func newFake(t *testing.T, status int, answer string) *fake {
	t.Helper()
	f := &fake{status: status, answer: answer}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		f.header = r.Header.Clone()
		f.body = make([]byte, 0, 256)
		buf := make([]byte, 256)
		for {
			n, err := r.Body.Read(buf)
			f.body = append(f.body, buf[:n]...)
			if err != nil {
				break
			}
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/secrets/fetch" {
			http.Error(w, "wrong route", http.StatusTeapot)
			return
		}
		for k, v := range f.extra {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.answer))
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fake) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(f.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDeriveAPIURL(t *testing.T) {
	ok := map[string]string{
		"https://mcp.agentruntime.io/mcp":      "https://api.agentruntime.io",
		"https://mcp.example.test/mcp":         "https://api.example.test",
		"https://mcp.agentruntime.io":          "https://api.agentruntime.io",
		"https://mcp.example.test:8443/mcp":    "https://api.example.test:8443",
		"  https://mcp.agentruntime.io/mcp  ":  "https://api.agentruntime.io",
		"http://mcp.localhost:8340/mcp":        "http://api.localhost:8340",
		"https://mcp.agentruntime.io/mcp?x=1#": "https://api.agentruntime.io",
	}
	for in, want := range ok {
		got, err := DeriveAPIURL(in)
		if err != nil || got != want {
			t.Errorf("%q => %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "not a url", "http://127.0.0.1:8340/mcp", "http://localhost:8340/mcp",
		"https://agentruntime.io/mcp", "https://api.agentruntime.io/mcp", "https://mcp./mcp", "/mcp",
	} {
		if got, err := DeriveAPIURL(bad); err == nil {
			t.Errorf("%q should not derive, got %q", bad, got)
		}
	}
}

func TestNewValidatesAddressAndToken(t *testing.T) {
	for _, base := range []string{
		"https://api.agentruntime.io", "https://api.agentruntime.io/", "https://api.x.test:8443/prefix",
		"http://127.0.0.1:8086", "http://localhost:8086", "http://[::1]:8086", "http://localhost", "http://127.0.0.1",
	} {
		if _, err := New(base, testToken); err != nil {
			t.Errorf("%q should be accepted: %v", base, err)
		}
	}
	for _, base := range []string{
		"", "api.agentruntime.io", "http://api.agentruntime.io", "http://10.0.0.5:8086", "ftp://api.x.test",
		"https://user:pass@api.x.test", "https://api.x.test?x=1", "https://api.x.test#frag", "https://",
	} {
		if _, err := New(base, testToken); err == nil {
			t.Errorf("%q should be refused", base)
		}
	}
	if _, err := New("https://api.x.test", "  "); err == nil {
		t.Error("an empty token should be refused")
	}
}

// Plain http is allowed for the exact hosts localhost, 127.0.0.1 and ::1 and for
// nothing else: not a name that merely ends in .localhost, not another loopback
// address, not a look-alike.
func TestPlainHTTPOnlyForTheExactLoopbackHosts(t *testing.T) {
	for _, base := range []string{
		"http://api.localhost:8086", "http://foo.localhost", "http://a.b.localhost:8086/prefix", "http://localhost.example.test",
		"http://localhost.:8086", "http://LOCALHOST:8086", "http://Localhost:8086", "http://127.0.0.2:8086", "http://127.1:8086",
		"http://127.0.0.1.example.test:8086", "http://[::ffff:127.0.0.1]:8086", "http://[::2]:8086", "http://0.0.0.0:8086",
		"http://[::]:8086", "http://mylocalhost", "http://example.test",
	} {
		_, err := New(base, testToken)
		if err == nil {
			t.Errorf("%q must be refused over plain http", base)
			continue
		}
		if !strings.Contains(err.Error(), "plain http") {
			t.Errorf("%q: unexpected message %q", base, err)
		}
	}
	// The same names are fine over https.
	for _, base := range []string{"https://api.localhost:8086", "https://127.0.0.2:8086"} {
		if _, err := New(base, testToken); err != nil {
			t.Errorf("%q should be accepted over https: %v", base, err)
		}
	}
}

func TestFetchSendsOneAuthenticatedPostAndDecodes(t *testing.T) {
	f := newFake(t, 200, `{"values":{"workspace/live/stripe#API_KEY":"fake-key-1","my/deploy":{"TOKEN":"fake-tok","HOST":"h.test"}}}`)
	refs := []string{"workspace/live/stripe#API_KEY", "my/deploy"}
	got, err := f.client(t).Fetch(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	if f.hits != 1 {
		t.Errorf("hits = %d, want 1", f.hits)
	}
	if h := f.header.Get("Authorization"); h != "Bearer "+testToken {
		t.Errorf("Authorization = %q", h)
	}
	if ct := f.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if ua := f.header.Get("User-Agent"); !strings.HasPrefix(ua, "agentruntime-cli/") {
		t.Errorf("User-Agent = %q", ua)
	}
	var sent struct {
		Refs  []string `json:"refs"`
		Check bool     `json:"check"`
	}
	dec := json.NewDecoder(strings.NewReader(string(f.body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sent); err != nil {
		t.Fatalf("body %q: %v", f.body, err)
	}
	if strings.Join(sent.Refs, ",") != strings.Join(refs, ",") || sent.Check {
		t.Errorf("sent %+v", sent)
	}
	if v := got["workspace/live/stripe#API_KEY"]; v.IsObject || v.String != "fake-key-1" {
		t.Errorf("string value: %+v", v)
	}
	if v := got["my/deploy"]; !v.IsObject || v.Fields["TOKEN"] != "fake-tok" || v.Fields["HOST"] != "h.test" {
		t.Errorf("object value: %+v", v)
	}
}

func TestFetchPrefixPathAndTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"values":{"my/a#B":"x"}}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL+"/gateway/", testToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Fetch(context.Background(), []string{"my/a#B"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/gateway/v1/secrets/fetch" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestFetchRejectsIncompleteOrMalformedAnswers(t *testing.T) {
	cases := map[string]string{
		"missing ref":      `{"values":{"my/a#B":"x"}}`,
		"no values key":    `{"items":[]}`,
		"values null":      `{"values":null}`,
		"not json":         `<html>proxy</html>`,
		"number value":     `{"values":{"my/a#B":5,"my/c":{}}}`,
		"null value":       `{"values":{"my/a#B":null,"my/c":{}}}`,
		"object of number": `{"values":{"my/a#B":"x","my/c":{"K":1}}}`,
		"array value":      `{"values":{"my/a#B":["x"],"my/c":{}}}`,
	}
	for name, body := range cases {
		f := newFake(t, 200, body)
		_, err := f.client(t).Fetch(context.Background(), []string{"my/a#B", "my/c"})
		if err == nil {
			t.Errorf("%s: should fail", name)
			continue
		}
		if strings.Contains(err.Error(), "proxy") {
			t.Errorf("%s: the answer body leaked into the error: %v", name, err)
		}
	}
}

func TestFetchErrorAnswers(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		retry     string
		wantCode  string
		wantInMsg string
		rooms     []string
		retryWant string
	}{
		{"server sentence wins", 404, `{"error":"not_found","message":"Server says not found."}`, "", "not_found", "Server says not found.", nil, ""},
		{"fallback for a known code", 403, `{"error":"missing_scope"}`, "", "missing_scope", "secrets:fetch", nil, ""},
		{"fetch_key_required", 403, `{"error":"fetch_key_required"}`, "", "fetch_key_required", "access key", nil, ""},
		{"fetch_disabled", 403, `{"error":"fetch_disabled"}`, "", "fetch_disabled", "turned off", nil, ""},
		{"view_disabled", 403, `{"error":"view_disabled"}`, "", "view_disabled", "not allow", nil, ""},
		{"uses_exhausted", 403, `{"error":"uses_exhausted"}`, "", "uses_exhausted", "no uses left", nil, ""},
		{"rate_limited with retry", 429, `{"error":"rate_limited"}`, "42", "rate_limited", "Too many", nil, "42"},
		{"bad retry-after ignored", 429, `{"error":"rate_limited"}`, "soon; DROP", "rate_limited", "Too many", nil, ""},
		{"bad_ref", 400, `{"error":"bad_ref"}`, "", "bad_ref", "not valid", nil, ""},
		{"too_large", 413, `{"error":"too_large"}`, "", "too_large", "64 KB", nil, ""},
		{"audit_failed", 503, `{"error":"audit_failed"}`, "", "audit_failed", "nothing was returned", nil, ""},
		{"ambiguous with rooms", 409, `{"error":"ambiguous_ref","message":"Ambiguous.","rooms":["my","workspace","evil","shared"]}`, "", "ambiguous_ref", "Ambiguous.", []string{"my", "workspace"}, ""},
		{"401 without a body", 401, ``, "", "", "HTTP 401", nil, ""},
		{"403 html", 403, `<html>nope</html>`, "", "", "HTTP 403", nil, ""},
		{"404 wrong address", 404, `not found`, "", "", "--api-url", nil, ""},
		{"500", 500, `{"oops":true}`, "", "", "HTTP 500", nil, ""},
		{"control chars and length are cleaned", 400, `{"error":"bad_ref","message":"line1\nline2\u0007 ` + strings.Repeat("x", 400) + `"}`, "", "bad_ref", "line1 line2", nil, ""},
	}
	for _, c := range cases {
		f := newFake(t, c.status, c.body)
		if c.retry != "" {
			f.extra = map[string]string{"Retry-After": c.retry}
		}
		got, err := f.client(t).Fetch(context.Background(), []string{"my/a#B"})
		if got != nil {
			t.Errorf("%s: no value may come back with an error", c.name)
		}
		var ae *APIError
		if !asAPIError(err, &ae) {
			t.Errorf("%s: want *APIError, got %T %v", c.name, err, err)
			continue
		}
		if ae.Status != c.status || ae.Code != c.wantCode {
			t.Errorf("%s: status %d code %q", c.name, ae.Status, ae.Code)
		}
		if !strings.Contains(ae.Message, c.wantInMsg) {
			t.Errorf("%s: message %q lacks %q", c.name, ae.Message, c.wantInMsg)
		}
		if strings.ContainsAny(ae.Message, "\n\a") || len([]rune(ae.Message)) > 300 {
			t.Errorf("%s: message not cleaned: %q", c.name, ae.Message)
		}
		if strings.Join(ae.Rooms, ",") != strings.Join(c.rooms, ",") {
			t.Errorf("%s: rooms %v, want %v", c.name, ae.Rooms, c.rooms)
		}
		if ae.RetryAfter != c.retryWant {
			t.Errorf("%s: retry-after %q, want %q", c.name, ae.RetryAfter, c.retryWant)
		}
		if f.hits != 1 {
			t.Errorf("%s: %d requests; an error must not be retried", c.name, f.hits)
		}
		if c.wantCode != "" && !strings.Contains(ae.Error(), "("+c.wantCode+")") {
			t.Errorf("%s: Error() = %q should carry the code", c.name, ae.Error())
		}
	}
}

func asAPIError(err error, target **APIError) bool {
	ae, ok := err.(*APIError)
	if ok {
		*target = ae
	}
	return ok
}

func TestRedirectIsNeverFollowed(t *testing.T) {
	var landed int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { landed++ }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/secrets/fetch", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, testToken)
	_, err := c.Fetch(context.Background(), []string{"my/a#B"})
	if err == nil {
		t.Fatal("a redirect must be an error")
	}
	if landed != 0 {
		t.Error("the redirect target received a request (and the access key)")
	}
}

func TestRequestTooLargeIsRefusedBeforeSending(t *testing.T) {
	f := newFake(t, 200, `{"values":{}}`)
	var refs []string
	for i := 0; i < 40; i++ {
		refs = append(refs, "my/"+strings.Repeat("a", 250)+string(rune('a'+i)))
	}
	if _, err := f.client(t).Fetch(context.Background(), refs); err == nil || !strings.Contains(err.Error(), "larger than the server accepts") {
		t.Errorf("err = %v", err)
	}
	if f.hits != 0 {
		t.Error("an oversized request must not be sent")
	}
}

func TestOversizedAnswerIsRefused(t *testing.T) {
	big := `{"values":{"my/a#B":"` + strings.Repeat("v", maxAnswerBytes) + `"}}`
	f := newFake(t, 200, big)
	_, err := f.client(t).Fetch(context.Background(), []string{"my/a#B"})
	if err == nil || strings.Contains(err.Error(), "vvvv") {
		t.Errorf("err = %v", err)
	}
}

func TestCheckSendsCheckTrueAndDecodes(t *testing.T) {
	f := newFake(t, 200, `{"items":[{"ref":"my/a","resolves":true},{"ref":"my/b#X","resolves":false}]}`)
	items, err := f.client(t).Check(context.Background(), []string{"my/a", "my/b#X"})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || !items[0].Resolves || items[1].Resolves || items[1].Ref != "my/b#X" {
		t.Errorf("items = %+v", items)
	}
	var sent struct {
		Check bool `json:"check"`
	}
	_ = json.Unmarshal(f.body, &sent)
	if !sent.Check {
		t.Errorf("body %s should have check:true", f.body)
	}
	bad := newFake(t, 200, `{"values":{}}`)
	if _, err := bad.client(t).Check(context.Background(), []string{"my/a"}); err == nil {
		t.Error("an answer with no items should fail")
	}
}

func TestUnreachableServerErrorHasNoSecrets(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, _ := New(url, testToken)
	_, err := c.Fetch(context.Background(), []string{"my/a#B"})
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "Bearer") {
		t.Errorf("error leaks the access key: %v", err)
	}
}

func TestContextCancelStopsTheCall(t *testing.T) {
	f := newFake(t, 200, `{"values":{"my/a#B":"x"}}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.client(t).Fetch(ctx, []string{"my/a#B"}); err == nil {
		t.Error("a cancelled context should fail the call")
	}
}
