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
	"testing"
	"time"
)

// Every code and key below is fake.
const (
	fakeDeviceCode = "FAKE-device_code-0123456789abcdefghijklmnopqrstuvwxyz"
	fakeGrantToken = "pat_FAKE-device_key-0123456789abcdefghijklmnopqrstuvw"
)

const goodCodeAnswer = `{"device_code":"` + fakeDeviceCode + `","user_code":"BCDF-2345","verification_uri":"https://console.example.test/device",` +
	`"verification_uri_complete":"https://console.example.test/device?code=BCDF-2345","expires_in":600,"interval":5}`

const goodGrantAnswer = `{"token":"` + fakeGrantToken + `","expires_at":"2026-11-16T12:00:00Z","tenant_id":"tenant-1","scopes":["secrets:fetch"],"refs":["workspace/live/*"]}`

// devAPI is a stand-in for the two public device routes. It records every request.
type devAPI struct {
	*httptest.Server
	mu    sync.Mutex
	calls []devCall
	// answer decides the reply for a request.
	answer func(c devCall) (status int, header map[string]string, body string)
}

type devCall struct {
	Method, Path string
	Header       http.Header
	Body         map[string]any
	RawBody      string
}

func newDevAPI(t *testing.T, answer func(c devCall) (int, map[string]string, string)) *devAPI {
	t.Helper()
	d := &devAPI{answer: answer}
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 0, 512)
		tmp := make([]byte, 512)
		for {
			n, err := r.Body.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
		c := devCall{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), RawBody: string(buf)}
		_ = json.Unmarshal(buf, &c.Body)
		d.mu.Lock()
		d.calls = append(d.calls, c)
		d.mu.Unlock()
		status, header, body := d.answer(c)
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(d.Close)
	return d
}

func (d *devAPI) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func (d *devAPI) client(t *testing.T) *DeviceClient {
	t.Helper()
	c, err := NewDeviceClient(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func routeAnswers(code, token string) func(devCall) (int, map[string]string, string) {
	return func(c devCall) (int, map[string]string, string) {
		switch c.Path {
		case "/v1/auth/device/code":
			return 200, nil, code
		case "/v1/auth/device/token":
			return 200, nil, token
		}
		return 404, nil, ""
	}
}

var goodRequest = DeviceRequest{Name: "laptop", Scopes: []string{"secrets:fetch"}, Refs: []string{"workspace/live/*"}, TTLSeconds: 3600}

func TestNewDeviceClientAddressRules(t *testing.T) {
	good := []string{"https://api.example.test", "https://api.example.test/", "https://api.example.test/base", "http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:9"}
	for _, u := range good {
		if _, err := NewDeviceClient(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	bad := map[string]string{
		"http://api.example.test":          "plain http",
		"http://127.0.0.2:8080":            "plain http", // not one of the three exact loopback names
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
		_, err := NewDeviceClient(u)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want one mentioning %q", u, err, want)
		}
	}
}

func TestDeviceClientHasATimeoutAndNeverFollowsRedirects(t *testing.T) {
	c, err := NewDeviceClient("https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if c.http.Timeout != DeviceHTTPTimeout || c.http.Timeout <= 0 || c.http.Timeout > time.Minute {
		t.Errorf("request timeout %v", c.http.Timeout)
	}
	if c.http.CheckRedirect == nil {
		t.Fatal("no redirect rule")
	}
	if err := c.http.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("redirect rule returns %v", err)
	}
}

func TestStartSendsTheRequestWithNoKeyAndReadsTheAnswer(t *testing.T) {
	d := newDevAPI(t, routeAnswers(goodCodeAnswer, ""))
	got, err := d.client(t).Start(context.Background(), goodRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserCode != "BCDF-2345" || got.DeviceCode != fakeDeviceCode || got.ExpiresIn != 600 || got.Interval != 5 ||
		got.VerificationURI != "https://console.example.test/device" || got.VerificationURIComplete != "https://console.example.test/device?code=BCDF-2345" {
		t.Errorf("answer %+v", got)
	}
	c := d.calls[0]
	if c.Method != http.MethodPost || c.Path != "/v1/auth/device/code" {
		t.Errorf("request %s %s", c.Method, c.Path)
	}
	if v := c.Header.Get("Authorization"); v != "" || c.Header.Get("Cookie") != "" {
		t.Errorf("the request carried credentials: %q", v)
	}
	if c.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(c.Header.Get("User-Agent"), "agentruntime-cli/") {
		t.Errorf("headers %v", c.Header)
	}
	want := map[string]any{"client": "agentruntime-cli", "device_name": "laptop", "scopes": []any{"secrets:fetch"}, "refs": []any{"workspace/live/*"}, "allow_all": false, "ttl_seconds": float64(3600)}
	if len(c.Body) != len(want) {
		t.Errorf("body keys %v", c.Body)
	}
	for k, v := range want {
		if fmt.Sprint(c.Body[k]) != fmt.Sprint(v) {
			t.Errorf("body[%s] = %v, want %v", k, c.Body[k], v)
		}
	}
}

func TestStartAllowAllSendsNoRefs(t *testing.T) {
	d := newDevAPI(t, routeAnswers(goodCodeAnswer, ""))
	req := DeviceRequest{Name: "n", Scopes: []string{"secrets:fetch", "vault:read"}, AllowAll: true, TTLSeconds: 60}
	if _, err := d.client(t).Start(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	c := d.calls[0]
	if _, has := c.Body["refs"]; has || c.Body["allow_all"] != true {
		t.Errorf("body %s: allow_all must go without a refs list", c.RawBody)
	}
}

func TestStartNormalisesIntervalAndLifetime(t *testing.T) {
	cases := []struct {
		name, extra          string
		wantExpires, wantInt int
	}{
		{"absent", `"expires_in":0`, 600, 5},
		{"too long", `"expires_in":99999,"interval":9999`, 1800, 60},
		{"negative interval", `"expires_in":300,"interval":-3`, 300, 5},
		{"one", `"expires_in":120,"interval":1`, 120, 1},
	}
	for _, c := range cases {
		answer := `{"device_code":"` + fakeDeviceCode + `","user_code":"BCDF-2345","verification_uri":"https://c.example.test/d",` + c.extra + `}`
		d := newDevAPI(t, routeAnswers(answer, ""))
		got, err := d.client(t).Start(context.Background(), goodRequest)
		if err != nil || got.ExpiresIn != c.wantExpires || got.Interval != c.wantInt {
			t.Errorf("%s: %+v, %v", c.name, got, err)
		}
	}
}

func TestStartRefusesAnswersItCannotUse(t *testing.T) {
	long := strings.Repeat("a", 3000)
	cases := map[string]string{
		"not json":                 `<html>maintenance</html>`,
		"empty":                    ``,
		"array":                    `[]`,
		"no device code":           `{"user_code":"BCDF-2345","verification_uri":"https://c.example.test/d"}`,
		"short device code":        `{"device_code":"abc","user_code":"BCDF-2345","verification_uri":"https://c.example.test/d"}`,
		"device code spaces":       `{"device_code":"` + strings.Repeat("a b ", 10) + `","user_code":"BCDF-2345","verification_uri":"https://c.example.test/d"}`,
		"no user code":             `{"device_code":"` + fakeDeviceCode + `","verification_uri":"https://c.example.test/d"}`,
		"user code escape":         `{"device_code":"` + fakeDeviceCode + `","user_code":"AB\u001b[2JCD","verification_uri":"https://c.example.test/d"}`,
		"user code only an escape": `{"device_code":"` + fakeDeviceCode + `","user_code":"ABCD\u001bEF","verification_uri":"https://c.example.test/d"}`,
		"user code with a space":   `{"device_code":"` + fakeDeviceCode + `","user_code":"ABCD EFGH","verification_uri":"https://c.example.test/d"}`,
		"user code with a newline": `{"device_code":"` + fakeDeviceCode + `","user_code":"ABCD\nEFGH","verification_uri":"https://c.example.test/d"}`,
		"user code too short":      `{"device_code":"` + fakeDeviceCode + `","user_code":"AB","verification_uri":"https://c.example.test/d"}`,
		"user code too long":       `{"device_code":"` + fakeDeviceCode + `","user_code":"` + strings.Repeat("A", 17) + `","verification_uri":"https://c.example.test/d"}`,
		"no address":               `{"device_code":"` + fakeDeviceCode + `","user_code":"BCDF-2345"}`,
		"huge address":             `{"device_code":"` + fakeDeviceCode + `","user_code":"BCDF-2345","verification_uri":"https://c.example.test/` + long + `"}`,
		"number as string":         `{"device_code":"` + fakeDeviceCode + `","user_code":"BCDF-2345","verification_uri":"https://c.example.test/d","interval":"5"}`,
	}
	for name, answer := range cases {
		d := newDevAPI(t, routeAnswers(answer, ""))
		_, err := d.client(t).Start(context.Background(), goodRequest)
		if !errors.Is(err, ErrUnexpectedAnswer) {
			t.Errorf("%s: error %v, want an unexpected answer", name, err)
		} else if strings.Contains(err.Error(), fakeDeviceCode) || strings.Contains(err.Error(), "maintenance") {
			t.Errorf("%s: the error carries the body: %v", name, err)
		}
	}
}

func TestStartErrorAnswers(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		header       map[string]string
		body, wantIn string
		wantCode     string
	}{
		{"rate limited by code", 429, map[string]string{"Retry-After": "42"}, `{"error":"rate_limited","message":"Too many codes."}`, "Too many codes.", "rate_limited"},
		{"rate limited, no body", 429, nil, ``, "Too many sign-in attempts", ""},
		{"not found", 404, nil, `<html>`, "does not offer device sign-in", ""},
		{"not implemented", 501, nil, ``, "does not offer device sign-in", ""},
		{"invalid", 400, nil, `{"error":"invalid_request"}`, "Check --ref, --scope and --ttl", "invalid_request"},
		{"description spelling", 400, nil, `{"error":"invalid_scope","error_description":"scope not allowed"}`, "scope not allowed", "invalid_scope"},
		{"unavailable", 503, nil, `{}`, "right now (HTTP 503)", ""},
		{"server error", 500, nil, `oops`, "HTTP 500", ""},
		{"control characters in a message", 400, nil, `{"error":"x","message":"a\u001b[31mred\nline"}`, "a [31mred line", "x"},
		{"redirect", 302, map[string]string{"Location": "https://elsewhere.example.test/"}, ``, "answered with a redirect (HTTP 302)", ""},
	}
	for _, c := range cases {
		d := newDevAPI(t, func(devCall) (int, map[string]string, string) { return c.status, c.header, c.body })
		_, err := d.client(t).Start(context.Background(), goodRequest)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != c.status || ae.Code != c.wantCode || !strings.Contains(ae.Error(), c.wantIn) {
			t.Errorf("%s: %v (want status %d, code %q, text %q)", c.name, err, c.status, c.wantCode, c.wantIn)
			continue
		}
		if strings.ContainsRune(ae.Error(), '\x1b') || strings.ContainsRune(ae.Error(), '\n') {
			t.Errorf("%s: the message holds control characters: %q", c.name, ae.Error())
		}
	}
}

func TestPollAnswersFollowTheProtocol(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   PollState
	}{
		{"pending", 400, `{"error":"authorization_pending"}`, PollPending},
		{"slow down", 400, `{"error":"slow_down","message":"Wait."}`, PollSlowDown},
		{"denied", 400, `{"error":"access_denied"}`, PollDenied},
		{"expired", 400, `{"error":"expired_token"}`, PollExpired},
		{"code in the message only", 400, `{"message":"authorization_pending"}`, PollPending},
		{"RFC description spelling", 400, `{"error":"expired_token","error_description":"gone"}`, PollExpired},
		{"another 4xx status carrying the code", 403, `{"error":"access_denied"}`, PollDenied},
		{"granted", 200, goodGrantAnswer, PollGranted},
	}
	for _, c := range cases {
		d := newDevAPI(t, func(devCall) (int, map[string]string, string) { return c.status, nil, c.body })
		res, err := d.client(t).Poll(context.Background(), fakeDeviceCode)
		if err != nil || res.State != c.want {
			t.Errorf("%s: state %v, err %v, want %v", c.name, res.State, err, c.want)
		}
		if c.want == PollGranted && (res.Grant == nil || res.Grant.Token != fakeGrantToken) {
			t.Errorf("%s: no grant", c.name)
		}
		if c.want != PollGranted && res.Grant != nil {
			t.Errorf("%s: a grant without approval", c.name)
		}
	}
}

func TestPollSendsOnlyTheDeviceCodeAndNoKey(t *testing.T) {
	d := newDevAPI(t, routeAnswers("", goodGrantAnswer))
	if _, err := d.client(t).Poll(context.Background(), fakeDeviceCode); err != nil {
		t.Fatal(err)
	}
	c := d.calls[0]
	if c.Method != http.MethodPost || c.Path != "/v1/auth/device/token" || c.Header.Get("Authorization") != "" {
		t.Errorf("request %s %s auth=%q", c.Method, c.Path, c.Header.Get("Authorization"))
	}
	if len(c.Body) != 1 || c.Body["device_code"] != fakeDeviceCode {
		t.Errorf("body %s: want exactly the device code", c.RawBody)
	}
}

func TestPollGrantFields(t *testing.T) {
	answer := `{"token":"` + fakeGrantToken + `","expires_at":"2026-11-16T12:00:00+02:00","tenant_id":"t\u001b9","scopes":["secrets:fetch","vault:read"],"refs":["workspace/a/*","my/b"],"allow_all":false}`
	d := newDevAPI(t, routeAnswers("", answer))
	res, err := d.client(t).Poll(context.Background(), fakeDeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	g := res.Grant
	if !g.ExpiresAt.Equal(time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)) || g.TenantID != "t 9" ||
		strings.Join(g.Scopes, ",") != "secrets:fetch,vault:read" || strings.Join(g.Refs, ",") != "workspace/a/*,my/b" || g.AllowAll {
		t.Errorf("grant %+v", g)
	}
	allAll := `{"token":"` + fakeGrantToken + `","expires_at":"2026-11-16T12:00:00Z","scopes":["secrets:fetch"],"allow_all":true}`
	d = newDevAPI(t, routeAnswers("", allAll))
	if res, err := d.client(t).Poll(context.Background(), fakeDeviceCode); err != nil || !res.Grant.AllowAll {
		t.Errorf("allow_all: %+v %v", res, err)
	}
}

func TestPollRefusesAGrantItCannotUse(t *testing.T) {
	cases := map[string]string{
		"not json":           `<html>`,
		"no token":           `{"expires_at":"2026-11-16T12:00:00Z","scopes":["secrets:fetch"]}`,
		"not a key":          `{"token":"hello","expires_at":"2026-11-16T12:00:00Z"}`,
		"key with escape":    `{"token":"pat_ab\u001b[2Jcd","expires_at":"2026-11-16T12:00:00Z"}`,
		"key with a space":   `{"token":"pat_ab cd","expires_at":"2026-11-16T12:00:00Z"}`,
		"key too long":       `{"token":"pat_` + strings.Repeat("a", 300) + `","expires_at":"2026-11-16T12:00:00Z"}`,
		"no expiry":          `{"token":"` + fakeGrantToken + `","scopes":["secrets:fetch"]}`,
		"unreadable expiry":  `{"token":"` + fakeGrantToken + `","expires_at":"tomorrow"}`,
		"expiry as a number": `{"token":"` + fakeGrantToken + `","expires_at":1795000000}`,
		"too many scopes":    `{"token":"` + fakeGrantToken + `","expires_at":"2026-11-16T12:00:00Z","scopes":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q"]}`,
	}
	for name, answer := range cases {
		d := newDevAPI(t, routeAnswers("", answer))
		_, err := d.client(t).Poll(context.Background(), fakeDeviceCode)
		if !errors.Is(err, ErrUnexpectedAnswer) {
			t.Errorf("%s: error %v, want an unexpected answer", name, err)
			continue
		}
		if IsTransient(err) {
			t.Errorf("%s: an unreadable answer must never be retried", name)
		}
		if strings.Contains(err.Error(), "pat_") || strings.Contains(err.Error(), fakeGrantToken) {
			t.Errorf("%s: the error carries the key: %v", name, err)
		}
	}
}

func TestPollErrorsAndWhichOnesAreTransient(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		transient bool
	}{
		{"server error", 500, ``, true},
		{"unavailable", 503, `{"error":"x"}`, true},
		{"too many requests", 429, `{"error":"rate_limited"}`, true},
		{"request timeout", 408, ``, true},
		{"unknown 400", 400, `{"error":"something_new"}`, false},
		{"bad request, no body", 400, ``, false},
		{"not found", 404, ``, false},
		{"unauthorized", 401, ``, false},
		{"forbidden", 403, `{"error":"device_login_disabled"}`, false},
		{"429 saying pending is still a rate limit", 429, `{"error":"authorization_pending"}`, true},
	}
	for _, c := range cases {
		d := newDevAPI(t, func(devCall) (int, map[string]string, string) { return c.status, nil, c.body })
		res, err := d.client(t).Poll(context.Background(), fakeDeviceCode)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != c.status || res.State != 0 {
			t.Errorf("%s: %+v, %v", c.name, res, err)
			continue
		}
		if IsTransient(err) != c.transient {
			t.Errorf("%s: transient = %v, want %v", c.name, IsTransient(err), c.transient)
		}
	}
	// A network failure is transient; a context error is not asked about here (the caller checks the context first).
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, _ := NewDeviceClient(url)
	_, err := c.Poll(context.Background(), fakeDeviceCode)
	if err == nil || !IsTransient(err) || strings.Contains(err.Error(), fakeDeviceCode) {
		t.Errorf("unreachable server: %v (transient %v)", err, IsTransient(err))
	}
	if IsTransient(nil) {
		t.Error("no error is not transient")
	}
}

func TestRetryAfterIsReadFromAPollError(t *testing.T) {
	d := newDevAPI(t, func(devCall) (int, map[string]string, string) {
		return 429, map[string]string{"Retry-After": "17"}, ``
	})
	_, err := d.client(t).Poll(context.Background(), fakeDeviceCode)
	var ae *APIError
	if !errors.As(err, &ae) || ae.RetryAfter != "17" {
		t.Errorf("%+v", err)
	}
}

func TestRedirectIsNeverFollowedByTheDeviceClient(t *testing.T) {
	var landed int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { landed++ }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect) // 307 would carry the body
	}))
	defer srv.Close()
	c, _ := NewDeviceClient(srv.URL)
	if _, err := c.Start(context.Background(), goodRequest); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("start: %v", err)
	}
	if _, err := c.Poll(context.Background(), fakeDeviceCode); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("poll: %v", err)
	}
	if landed != 0 {
		t.Errorf("the redirect target received %d requests", landed)
	}
}

func TestOversizedDeviceAnswerIsRefused(t *testing.T) {
	big := `{"device_code":"` + fakeDeviceCode + `","user_code":"BCDF-2345","verification_uri":"https://c.example.test/` + strings.Repeat("v", maxDeviceAnswerBytes) + `"}`
	d := newDevAPI(t, routeAnswers(big, big))
	c := d.client(t)
	if _, err := c.Start(context.Background(), goodRequest); err == nil || strings.Contains(err.Error(), "vvvv") || !strings.Contains(err.Error(), "larger than expected") {
		t.Errorf("start: %v", err)
	}
	if _, err := c.Poll(context.Background(), fakeDeviceCode); err == nil || !strings.Contains(err.Error(), "larger than expected") {
		t.Errorf("poll: %v", err)
	}
}

func TestDeviceCallStopsWithItsContext(t *testing.T) {
	d := newDevAPI(t, routeAnswers(goodCodeAnswer, goodGrantAnswer))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.client(t).Poll(ctx, fakeDeviceCode); err == nil {
		t.Error("a cancelled context should fail the call")
	}
	if d.count() != 0 {
		t.Errorf("%d requests were sent with a cancelled context", d.count())
	}
}

// The device code and the key must not appear in anything these types print.
func TestDeviceCodeAndGrantHideTheirSecrets(t *testing.T) {
	code := &DeviceCode{DeviceCode: fakeDeviceCode, UserCode: "BCDF-2345", VerificationURI: "https://c.example.test/d", ExpiresIn: 600, Interval: 5}
	g := &DeviceGrant{Token: fakeGrantToken, ExpiresAt: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC), Scopes: []string{"secrets:fetch"}, Refs: []string{"my/*"}}
	for _, v := range []any{*code, code, *g, g, []DeviceCode{*code}, map[string]any{"x": g}} {
		for _, text := range []string{fmt.Sprint(v), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%s", v), fmt.Sprintf("%q", v)} {
			if strings.Contains(text, fakeDeviceCode) || strings.Contains(text, fakeGrantToken) {
				t.Errorf("a secret is printed: %s", text)
			}
		}
		b, err := json.Marshal(v)
		if err != nil || strings.Contains(string(b), fakeDeviceCode) || strings.Contains(string(b), fakeGrantToken) {
			t.Errorf("a secret is marshalled: %s %v", b, err)
		}
	}
	if !strings.Contains(fmt.Sprint(code), "BCDF-2345") || !strings.Contains(fmt.Sprint(g), "2026-11-16T12:00:00Z") {
		t.Error("the public parts should still print")
	}
}

func TestHeaderlessDeviceClientNeverSendsAnAuthorizationHeaderEvenWithOneInTheEnvironment(t *testing.T) {
	t.Setenv("AGENTRUNTIME_PAT", "pat_FAKE-env-key-0123456789")
	d := newDevAPI(t, routeAnswers(goodCodeAnswer, goodGrantAnswer))
	c := d.client(t)
	if _, err := c.Start(context.Background(), goodRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Poll(context.Background(), fakeDeviceCode); err != nil {
		t.Fatal(err)
	}
	for _, call := range d.calls {
		if call.Header.Get("Authorization") != "" || strings.Contains(fmt.Sprint(call.Header), "pat_FAKE") {
			t.Errorf("%s carried credentials: %v", call.Path, call.Header)
		}
	}
}

// The cap is an absolute number, not relative to the constant: a body of 100 KB is refused whatever the constant is
// set to in the future, and a small one is read.
func TestDeviceAnswerCapIsSixtyFourKilobytes(t *testing.T) {
	if maxDeviceAnswerBytes != 64*1024 {
		t.Errorf("cap is %d bytes", maxDeviceAnswerBytes)
	}
	pad := `{"device_code":"` + fakeDeviceCode + `","user_code":"BCDF-2345","verification_uri":"https://c.example.test/` + strings.Repeat("v", 100*1024) + `"}`
	d := newDevAPI(t, routeAnswers(pad, pad))
	if _, err := d.client(t).Start(context.Background(), goodRequest); err == nil || !strings.Contains(err.Error(), "larger than expected") {
		t.Errorf("a 100 KB answer was not refused: %v", err)
	}
	if _, err := d.client(t).Poll(context.Background(), fakeDeviceCode); err == nil || !strings.Contains(err.Error(), "larger than expected") {
		t.Errorf("a 100 KB poll answer was not refused: %v", err)
	}
}

// The workspace name and the masked approver are optional members of the key answer.
func TestPollGrantCarriesTheWorkspaceNameAndTheApprover(t *testing.T) {
	answer := `{"token":"` + fakeGrantToken + `","expires_at":"2026-11-16T12:00:00Z","tenant_id":"tenant-1","tenant_name":"Acme Corp","approved_by":"t***@example.com","scopes":["secrets:fetch"],"refs":["my/*"]}`
	d := newDevAPI(t, routeAnswers("", answer))
	res, err := d.client(t).Poll(context.Background(), fakeDeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if g := res.Grant; g.TenantID != "tenant-1" || g.TenantName != "Acme Corp" || g.ApprovedBy != "t***@example.com" {
		t.Errorf("grant %+v", g)
	}
	// Absent members are empty, not an error.
	bare := `{"token":"` + fakeGrantToken + `","expires_at":"2026-11-16T12:00:00Z","scopes":["secrets:fetch"]}`
	d = newDevAPI(t, routeAnswers("", bare))
	if res, err := d.client(t).Poll(context.Background(), fakeDeviceCode); err != nil || res.Grant.TenantName != "" || res.Grant.ApprovedBy != "" {
		t.Errorf("bare grant: %+v %v", res.Grant, err)
	}
	// Control characters and over-long text are cleaned, and the key stays hidden next to the new members.
	hostile := `{"token":"` + fakeGrantToken + `","expires_at":"2026-11-16T12:00:00Z","tenant_name":"Ac\nme` + strings.Repeat("x", 300) + `","approved_by":"a\u001b[2Jb"}`
	d = newDevAPI(t, routeAnswers("", hostile))
	res, err = d.client(t).Poll(context.Background(), fakeDeviceCode)
	if err != nil || strings.ContainsAny(res.Grant.TenantName, "\n\x1b") || len([]rune(res.Grant.TenantName)) > 100 || strings.ContainsRune(res.Grant.ApprovedBy, '\x1b') {
		t.Errorf("hostile grant: %+v %v", res.Grant, err)
	}
	for _, text := range []string{fmt.Sprint(res.Grant), fmt.Sprintf("%#v", res.Grant)} {
		if strings.Contains(text, fakeGrantToken) {
			t.Errorf("the key is printed: %s", text)
		}
	}
	b, _ := json.Marshal(res.Grant)
	if strings.Contains(string(b), fakeGrantToken) {
		t.Errorf("the key is marshalled: %s", b)
	}
}
