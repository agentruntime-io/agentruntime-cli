package bffclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every token and key below is fake.
const (
	fakeIDToken      = "eyJhbGciOiJSUzI1NiJ9.eyJGQUtFLWNhbmFyeSI6IkNBTkFSWS1PSURDLUpXVCJ9.FAKE-signature_0123456789"
	fakeWorkKey      = "pat_FAKE-workload_key-0123456789abcdefghijklmnopqrstu"
	fakeTrustID      = "11111111-2222-4333-8444-555555555555"
	serverTextCanary = "SERVER-TEXT-CANARY-do-not-print"
)

func goodExchangeAnswer() string {
	return `{"token":"` + fakeWorkKey + `","expires_at":"2026-11-16T12:00:00Z","scopes":["secrets:fetch"],"trust":"` + fakeTrustID + `"}`
}

type wlCall struct {
	Method, Path string
	Header       http.Header
	Body         map[string]any
	Raw          string
}

type wlServer struct {
	*httptest.Server
	mu     sync.Mutex
	calls  []wlCall
	answer func(c wlCall) (int, map[string]string, string)
}

func newWLServer(t *testing.T, answer func(c wlCall) (int, map[string]string, string)) *wlServer {
	t.Helper()
	s := &wlServer{answer: answer}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 0, 512)
		tmp := make([]byte, 512)
		for {
			n, err := r.Body.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
		c := wlCall{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Raw: string(buf)}
		_ = json.Unmarshal(buf, &c.Body)
		s.mu.Lock()
		s.calls = append(s.calls, c)
		s.mu.Unlock()
		status, header, body := s.answer(c)
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *wlServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *wlServer) client(t *testing.T) *WorkloadClient {
	t.Helper()
	c, err := NewWorkloadClient(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func answering(status int, body string) func(wlCall) (int, map[string]string, string) {
	return func(wlCall) (int, map[string]string, string) { return status, nil, body }
}

func TestNewWorkloadClientAddressRules(t *testing.T) {
	good := []string{"https://api.example.test", "https://api.example.test/", "https://api.example.test/base", "http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:9"}
	for _, u := range good {
		if _, err := NewWorkloadClient(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	bad := map[string]string{
		"http://api.example.test":          "plain http",
		"http://127.0.0.2:8080":            "plain http",
		"http://foo.localhost":             "plain http",
		"http://localhost.example.test":    "plain http",
		"ftp://api.example.test":           "https://",
		"api.example.test":                 "not a valid URL",
		"":                                 "not a valid URL",
		"https://user:pw@api.example.test": "credentials",
		"https://api.example.test?x=1":     "credentials",
		"https://api.example.test#frag":    "credentials",
	}
	for u, want := range bad {
		c, err := NewWorkloadClient(u)
		if err == nil || c != nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: client %v, error %v, want one with %q", u, c, err, want)
		}
	}
	// The sentence for plain http is about this sign-in: it names the identity token.
	if _, err := NewWorkloadClient("http://api.example.test"); err == nil || !strings.Contains(err.Error(), "identity token") {
		t.Errorf("plain http error: %v", err)
	}
}

func TestWorkloadClientTimeoutAndRedirectRules(t *testing.T) {
	c, err := NewWorkloadClient("https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if c.http.Timeout <= 0 || c.http.Timeout > time.Minute {
		t.Errorf("request timeout %v", c.http.Timeout)
	}
	if c.http.CheckRedirect == nil || c.http.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("redirects are followed")
	}
	if c.Host() != "api.example.test" || c.BaseURL() != "https://api.example.test" {
		t.Errorf("host %q base %q", c.Host(), c.BaseURL())
	}
}

func TestExchangeSendsTheThreeFieldsAndNothingElse(t *testing.T) {
	// A key in the environment must not leak into this call, whatever the process holds.
	t.Setenv("AGENTRUNTIME_PAT", "pat_FAKE-environment-key-0123456789")
	s := newWLServer(t, answering(200, goodExchangeAnswer()))
	g, err := s.client(t).Exchange(context.Background(), ProviderGitHub, strings.ToUpper(fakeTrustID), fakeIDToken)
	if err != nil {
		t.Fatal(err)
	}
	if s.count() != 1 {
		t.Fatalf("%d requests", s.count())
	}
	c := s.calls[0]
	if c.Method != http.MethodPost || c.Path != "/v1/auth/workload/exchange" {
		t.Errorf("request %s %s", c.Method, c.Path)
	}
	if len(c.Body) != 3 || c.Body["provider"] != "github" || c.Body["trust"] != fakeTrustID || c.Body["token"] != fakeIDToken {
		t.Errorf("body %v: want exactly provider, the trust id in lower case, and the token", c.Body)
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Vault-Token", "Proxy-Authorization"} {
		if v := c.Header.Get(h); v != "" {
			t.Errorf("the request carries %s: %q", h, v)
		}
	}
	if c.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(c.Header.Get("User-Agent"), "agentruntime-cli/") {
		t.Errorf("headers %v", c.Header)
	}
	want := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	if g.Token != fakeWorkKey || !g.ExpiresAt.Equal(want) || fmt.Sprint(g.Scopes) != "[secrets:fetch]" || g.Trust != fakeTrustID {
		t.Errorf("grant %v", g)
	}
}

func TestExchangeRefusesBadInputBeforeSendingAnything(t *testing.T) {
	s := newWLServer(t, answering(200, goodExchangeAnswer()))
	c := s.client(t)
	cases := []struct{ name, provider, trust, token string }{
		{"provider", "gitlab", fakeTrustID, fakeIDToken},
		{"empty provider", "", fakeTrustID, fakeIDToken},
		{"trust", "github", "not-a-trust", fakeIDToken},
		{"empty trust", "github", "", fakeIDToken},
		{"token", "github", fakeTrustID, "not a token"},
		{"empty token", "github", fakeTrustID, ""},
		{"token with a newline", "github", fakeTrustID, "aaaaaaaa.bbbbbbbb\n.cccccccc"},
		{"too long token", "github", fakeTrustID, "aaaaaaaa.bbbbbbbb." + strings.Repeat("c", MaxIDTokenBytes)},
	}
	for _, tc := range cases {
		_, err := c.Exchange(context.Background(), tc.provider, tc.trust, tc.token)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if strings.Contains(err.Error(), tc.token) && tc.token != "" || strings.Contains(err.Error(), "not-a-trust") {
			t.Errorf("%s: the error repeats the input: %v", tc.name, err)
		}
	}
	if s.count() != 0 {
		t.Errorf("%d requests were sent", s.count())
	}
}

func TestExchangeRefusalKeepsOnlyAKnownCodeAndSaysItInFixedWords(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		header     map[string]string
		body       string
		wantCode   string
		wantStatus int
		wantText   string
	}{
		{"the one refusal", 401, nil, `{"error":"invalid_workload_token","message":"` + serverTextCanary + `"}`, "invalid_workload_token", 401, "did not accept this job's identity token"},
		{"the code in an unknown spelling", 401, nil, `{"error":"` + serverTextCanary + `\u001b[31m","message":"` + serverTextCanary + `"}`, "", 401, "(HTTP 401)"},
		{"401 without a body", 401, nil, ``, "", 401, "(HTTP 401)"},
		{"400", 400, nil, `{"error":"invalid_request","message":"` + serverTextCanary + `"}`, "", 400, "Check --trust"},
		{"403", 403, nil, `{"message":"` + serverTextCanary + `"}`, "", 403, "(HTTP 403)"},
		{"404", 404, nil, `<html>` + serverTextCanary + `</html>`, "", 404, "does not offer CI sign-in"},
		{"405", 405, nil, ``, "", 405, "does not offer CI sign-in"},
		{"429", 429, map[string]string{"Retry-After": "42"}, `{"message":"` + serverTextCanary + `"}`, "", 429, "Too many sign-in attempts"},
		{"500", 500, nil, `{"message":"` + serverTextCanary + `"}`, "", 500, "could not do this right now (HTTP 500)"},
		{"503", 503, nil, ``, "", 503, "(HTTP 503)"},
		{"302", 302, map[string]string{"Location": "https://elsewhere.example.test/x"}, ``, "", 302, "redirect"},
	}
	for _, tc := range cases {
		s := newWLServer(t, func(wlCall) (int, map[string]string, string) { return tc.status, tc.header, tc.body })
		_, err := s.client(t).Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken)
		var ae *APIError
		if !errors.As(err, &ae) {
			t.Errorf("%s: error %v", tc.name, err)
			continue
		}
		if ae.Status != tc.wantStatus || ae.Code != tc.wantCode || !strings.Contains(ae.Message, tc.wantText) {
			t.Errorf("%s: %+v, want status %d code %q text %q", tc.name, ae, tc.wantStatus, tc.wantCode, tc.wantText)
		}
		for _, secret := range []string{serverTextCanary, fakeIDToken, "elsewhere", "\x1b"} {
			if strings.Contains(err.Error(), secret) || strings.Contains(ae.Message, secret) || strings.Contains(ae.Code, secret) {
				t.Errorf("%s: the error carries %.12q: %v", tc.name, secret, err)
			}
		}
		if tc.status == 429 && ae.RetryAfter != "42" {
			t.Errorf("Retry-After %q", ae.RetryAfter)
		}
	}
}

func TestExchangeDoesNotFollowARedirect(t *testing.T) {
	target := newWLServer(t, answering(200, goodExchangeAnswer()))
	s := newWLServer(t, func(wlCall) (int, map[string]string, string) {
		return 307, map[string]string{"Location": target.URL + "/stolen"}, ``
	})
	_, err := s.client(t).Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 307 {
		t.Fatalf("error %v", err)
	}
	if target.count() != 0 {
		t.Error("the redirect was followed: the identity token went to the target")
	}
}

func TestExchangeRefusesAnAnswerItCannotUse(t *testing.T) {
	longKey := "pat_" + strings.Repeat("a", 300)
	good := func(mut func(m map[string]any)) string {
		m := map[string]any{"token": fakeWorkKey, "expires_at": "2026-11-16T12:00:00Z", "scopes": []string{"secrets:fetch"}, "trust": fakeTrustID}
		mut(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	bodies := map[string]string{
		"not json":                  "<html>" + serverTextCanary + "</html>",
		"empty":                     "",
		"an array":                  "[]",
		"an empty object":           "{}",
		"no token":                  good(func(m map[string]any) { delete(m, "token") }),
		"an empty token":            good(func(m map[string]any) { m["token"] = "" }),
		"a token that is not a key": good(func(m map[string]any) { m["token"] = "not-a-pat-0123456789" }),
		"just the prefix":           good(func(m map[string]any) { m["token"] = "pat_" }),
		"a token with a newline":    good(func(m map[string]any) { m["token"] = "pat_abc\nEVIL=1" }),
		"a token with a space":      good(func(m map[string]any) { m["token"] = "pat_abc def" }),
		"a token with an escape":    good(func(m map[string]any) { m["token"] = "pat_abc\u001b[31m" }),
		"a too long token":          good(func(m map[string]any) { m["token"] = longKey }),
		"a token that is a number":  good(func(m map[string]any) { m["token"] = 12345 }),
		"no expiry":                 good(func(m map[string]any) { delete(m, "expires_at") }),
		"an unreadable expiry":      good(func(m map[string]any) { m["expires_at"] = "tomorrow" }),
		"an expiry as a number":     good(func(m map[string]any) { m["expires_at"] = 1789000000 }),
		"too many scopes":           good(func(m map[string]any) { m["scopes"] = make([]string, 17) }),
		"another trust":             good(func(m map[string]any) { m["trust"] = "99999999-2222-4333-8444-555555555555" }),
		"text as the trust":         good(func(m map[string]any) { m["trust"] = serverTextCanary }),
	}
	for name, body := range bodies {
		s := newWLServer(t, answering(200, body))
		g, err := s.client(t).Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken)
		if err == nil || g != nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(err, ErrUnexpectedAnswer) {
			t.Errorf("%s: error %v is not ErrUnexpectedAnswer", name, err)
		}
		for _, secret := range []string{serverTextCanary, "EVIL", fakeWorkKey, "\x1b"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error repeats the answer (%.10q): %v", name, secret, err)
			}
		}
	}
}

// '=' is part of URL-safe base64, so a key that ends in padding is as plausible as the other keys the CLI reads. What
// matters for the files the key is written to is that it holds no newline, no space and no control character.
func TestExchangeAcceptsAKeyWithPaddingCharacters(t *testing.T) {
	s := newWLServer(t, answering(200, `{"token":"pat_abc_DEF-123==","expires_at":"2026-11-16T12:00:00Z"}`))
	g, err := s.client(t).Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken)
	if err != nil || g.Token != "pat_abc_DEF-123==" {
		t.Fatalf("grant %v err %v", g, err)
	}
}

func TestExchangeAcceptsAnAnswerWithoutTheTrustOrScopes(t *testing.T) {
	s := newWLServer(t, answering(200, `{"token":"`+fakeWorkKey+`","expires_at":"2026-11-16T12:00:00Z"}`))
	g, err := s.client(t).Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken)
	if err != nil || g.Token != fakeWorkKey || g.Trust != "" || len(g.Scopes) != 0 {
		t.Fatalf("grant %v err %v", g, err)
	}
}

func TestExchangeAnswerIsCapped(t *testing.T) {
	big := `{"token":"` + fakeWorkKey + `","expires_at":"2026-11-16T12:00:00Z","pad":"` + strings.Repeat("x", 70*1024) + `"}`
	s := newWLServer(t, answering(200, big))
	g, err := s.client(t).Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken)
	if err == nil || g != nil {
		t.Fatal("an answer over the cap was accepted")
	}
	if !strings.Contains(err.Error(), "larger than expected") {
		t.Errorf("error %v", err)
	}
	// One byte under the cap is read.
	pad := 64*1024 - len(`{"token":"`+fakeWorkKey+`","expires_at":"2026-11-16T12:00:00Z","pad":""}`)
	exact := `{"token":"` + fakeWorkKey + `","expires_at":"2026-11-16T12:00:00Z","pad":"` + strings.Repeat("x", pad) + `"}`
	if len(exact) != 64*1024 {
		t.Fatalf("test body is %d bytes", len(exact))
	}
	s2 := newWLServer(t, answering(200, exact))
	if _, err := s2.client(t).Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken); err != nil {
		t.Errorf("an answer exactly at the cap: %v", err)
	}
}

// The answer is read up to its cap and no further: a server that keeps sending does not make the client read it all.
func TestExchangeStopsReadingAtItsCap(t *testing.T) {
	const total = 128 << 20
	var written int64
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		w.Header().Set("Content-Type", "application/json")
		chunk := []byte(strings.Repeat("x", 32*1024))
		_, _ = w.Write([]byte(`{"token":"` + fakeWorkKey + `","pad":"`))
		for atomic.LoadInt64(&written) < total {
			n, err := w.Write(chunk)
			atomic.AddInt64(&written, int64(n))
			if err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	t.Cleanup(srv.Close)
	c, err := NewWorkloadClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken); err == nil {
		t.Fatal("an endless answer was accepted")
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the server never noticed that the client had stopped reading")
	}
	if got := atomic.LoadInt64(&written); got > total/2 {
		t.Errorf("the server sent %d of %d bytes: the client kept reading past its cap", got, int64(total))
	}
}

func TestExchangeNetworkErrorsCarryNoSecret(t *testing.T) {
	s := newWLServer(t, answering(200, goodExchangeAnswer()))
	c := s.client(t)
	s.Close()
	_, err := c.Exchange(context.Background(), ProviderGitHub, fakeTrustID, fakeIDToken)
	if err == nil {
		t.Fatal("no error")
	}
	for _, secret := range []string{fakeIDToken, fakeTrustID, "eyJ"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error carries %.12q: %v", secret, err)
		}
	}
}

func TestWorkloadGrantNeverPrintsTheKey(t *testing.T) {
	g := WorkloadGrant{Token: fakeWorkKey, ExpiresAt: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC), Scopes: []string{"secrets:fetch"}, Trust: fakeTrustID}
	for _, v := range []any{g, &g} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if s := fmt.Sprintf(f, v); strings.Contains(s, fakeWorkKey) || strings.Contains(s, "FAKE-workload") {
				t.Errorf("%s of %T prints the key: %s", f, v, s)
			}
		}
		raw, err := json.Marshal(v)
		if err != nil || strings.Contains(string(raw), "FAKE-workload") || strings.Contains(string(raw), "token") {
			t.Errorf("JSON of %T: %s (%v)", v, raw, err)
		}
	}
}

func TestNormalizeTrustID(t *testing.T) {
	good := map[string]string{
		fakeTrustID:                            fakeTrustID,
		"  " + fakeTrustID + "\n":              fakeTrustID,
		"ABCDEF01-2345-4678-89AB-CDEF01234567": "abcdef01-2345-4678-89ab-cdef01234567",
		"abcdef01-2345-4678-89ab-cdef01234567": "abcdef01-2345-4678-89ab-cdef01234567",
		"00000000-0000-0000-0000-000000000000": "00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF": "ffffffff-ffff-ffff-ffff-ffffffffffff",
	}
	for in, want := range good {
		if got, ok := NormalizeTrustID(in); !ok || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, ok, want)
		}
	}
	bad := []string{
		"", " ", "abc", "11111111222243338444555555555555", "11111111-2222-4333-8444-55555555555", "11111111-2222-4333-8444-5555555555555",
		"11111111-2222-4333-8444-55555555555g", "11111111_2222_4333_8444_555555555555", "1111111-12222-4333-8444-555555555555",
		"{11111111-2222-4333-8444-555555555555}", "urn:uuid:11111111-2222-4333-8444-555555555555", "11111111-2222-4333-8444-555555555555/x",
		"11111111-2222-4333-8444-5555555555é", "11111111-2222-4333-8444-55555555555\x00", "11111111-2222-4333-8444-555555555555\n1",
		"pat_FAKE-looks-like-a-secret-0123456789ab", "workspace/live/stripe",
	}
	for _, in := range bad {
		if got, ok := NormalizeTrustID(in); ok {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestPlausibleIDToken(t *testing.T) {
	for _, s := range []string{fakeIDToken, "aaaaaaaa.bbbbbbbb.cccccccc", "A-_9aaaaaaa.B-_9bbbbbbb.C-_9ccccccc"} {
		if !plausibleIDToken(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "a.b.c", "aaaaaaaa.bbbbbbbb", "aaaaaaaa.bbbbbbbb.cccccccc.dddddddd", "aaaaaaaa..cccccccc", "aaaaaaaa.bbbbbbbb.",
		"aaaaaaaa.bbbbbbbb.cccc cccc", "aaaaaaaa.bbbb\nbbbb.cccccccc", "aaaaaaaa.bbbbbbbb.ccccc=", "aaaaaaaa.bbbbbbbb.ccécccc",
		"aaaaaaaa.bbbbbbbb." + strings.Repeat("c", MaxIDTokenBytes)} {
		if plausibleIDToken(s) {
			t.Errorf("%.40q accepted", s)
		}
	}
	// Exactly at the limit is the longest token that is sent.
	at := "aaaaaaaa.bbbbbbbb." + strings.Repeat("c", MaxIDTokenBytes-len("aaaaaaaa.bbbbbbbb."))
	if len(at) != MaxIDTokenBytes || !plausibleIDToken(at) {
		t.Errorf("a token of %d bytes is refused", len(at))
	}
}

func TestWorkloadClientAuthorityIsTheOneFoldedHostThatIsDialled(t *testing.T) {
	cases := map[string]string{
		"https://API.AgentRuntime.IO":      "api.agentruntime.io",
		"https://api.agentruntime.io:443/": "api.agentruntime.io",
		"http://127.0.0.1:8080":            "127.0.0.1:8080",
		"https://h.example:8443/base":      "h.example:8443",
	}
	for in, want := range cases {
		c, err := NewWorkloadClient(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := c.Authority(); got != want {
			t.Errorf("Authority(%q) = %q, want %q", in, got, want)
		}
		if c.Host() != strings.Split(want, ":")[0] {
			t.Errorf("Host(%q) = %q does not match the authority %q", in, c.Host(), want)
		}
	}
	// A host that is not plain ASCII is refused here as it is everywhere else.
	for _, in := range []string{"https://evil.agentrunt%C4%B0me.io", "https://a%E2%84%AA.example.test"} {
		if _, err := NewWorkloadClient(in); err == nil || !strings.Contains(err.Error(), "plain ASCII host name") {
			t.Errorf("%q: %v", in, err)
		}
	}
}
