package bffclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Every key below is fake.
const fakeOneTimeToken = "pat_FAKE-one_time-0123456789abcdefghijklmnopqrstuvwxyz"

func handoverAnswer(token string) string {
	return fmt.Sprintf(`{"token":%q,"expires_at":"2026-11-16T12:00:00Z","ref":"workspace/live/stripe#API_KEY","uses":1}`, token)
}

func TestHandoverSendsTheRefAndLifetimeAndReadsTheKey(t *testing.T) {
	f := newVaultFake(t, http.StatusCreated, handoverAnswer(fakeOneTimeToken), nil)
	res, err := f.client(t).Handover(context.Background(), "workspace/live/stripe#API_KEY", 1800)
	if err != nil {
		t.Fatal(err)
	}
	if res.Token != fakeOneTimeToken || res.ExpiresAt != "2026-11-16T12:00:00Z" || res.Ref != "workspace/live/stripe#API_KEY" || res.Uses != 1 {
		t.Fatalf("result %+v", res)
	}
	r := f.last()
	if r.Method != http.MethodPost || r.Path != "/v1/secrets/handover" || r.Auth != "Bearer "+testToken || r.Query != "" {
		t.Fatalf("request %+v", r)
	}
	if len(r.Body) != 2 || r.Body["ref"] != "workspace/live/stripe#API_KEY" || r.Body["ttl_seconds"] != float64(1800) {
		t.Fatalf("body %q: want exactly ref and ttl_seconds", r.RawBody)
	}
	// 200 is accepted as well as 201.
	f.set(http.StatusOK, handoverAnswer(fakeOneTimeToken), nil)
	if _, err := f.client(t).Handover(context.Background(), "my/x", 60); err != nil {
		t.Fatalf("200: %v", err)
	}
}

// The token is shown once, by the command that asked for it. Nothing that formats the result may print it.
func TestHandoverResultNeverFormatsItsToken(t *testing.T) {
	h := HandoverResult{Token: fakeOneTimeToken, ExpiresAt: "2026-11-16T12:00:00Z", Ref: "my/x", Uses: 1}
	for _, shown := range []string{
		fmt.Sprint(h), fmt.Sprintf("%v", h), fmt.Sprintf("%+v", h), fmt.Sprintf("%#v", h), fmt.Sprintf("%s", h),
		fmt.Sprint(&h), fmt.Sprintf("%+v", &h), fmt.Sprintf("%#v", &h),
	} {
		if strings.Contains(shown, fakeOneTimeToken) || strings.Contains(shown, "FAKE-one_time") {
			t.Errorf("a formatted result carries the token: %s", shown)
		}
	}
	b, err := h.MarshalJSON()
	if err != nil || strings.Contains(string(b), "pat_") || strings.Contains(string(b), "token") {
		t.Errorf("JSON %s (err %v) must leave the token out", b, err)
	}
	if !strings.Contains(string(b), `"ref":"my/x"`) || !strings.Contains(string(b), `"uses":1`) {
		t.Errorf("JSON %s lacks the facts", b)
	}
}

func TestHandoverErrorCodesCarryTheirFixedSentence(t *testing.T) {
	cases := []struct {
		status int
		body   string
		header map[string]string
		code   string
		want   string
	}{
		{403, `{"error":"handover_not_for_ai_clients","message":"No AI clients."}`, nil, "handover_not_for_ai_clients", "No AI clients."},
		{403, `{"error":"handover_not_for_ai_clients"}`, nil, "handover_not_for_ai_clients", "cannot be made through an AI client"},
		{404, `{"error":"not_found"}`, nil, "not_found", "may not view it"},
		{403, `{"error":"fetch_disabled"}`, nil, "fetch_disabled", "turned off for this workspace"},
		{403, `{"error":"view_disabled"}`, nil, "view_disabled", "does not allow secret values to be viewed"},
		{403, `{"error":"missing_scope"}`, nil, "missing_scope", "secrets:fetch"},
		{400, `{"error":"bad_ref"}`, nil, "bad_ref", "needs the room"},
		{400, `{"error":"invalid_request"}`, nil, "invalid_request", "1 minute to 24 hours"},
		{400, `{"message":"issuance_invalid"}`, nil, "issuance_invalid", "could not make a one-time key"},
		{400, `{"message":"issuance_expiry_out_of_bounds"}`, nil, "issuance_expiry_out_of_bounds", "between 1 minute and 24 hours"},
		{429, `{"error":"rate_limited"}`, map[string]string{"Retry-After": "30"}, "rate_limited", "Too many hand-overs"},
		{503, `{"error":"audit_failed"}`, nil, "audit_failed", "no key was made"},
		{401, ``, nil, "", "HTTP 401"},
		{404, ``, nil, "", "does not offer one-time hand-over"},
		{500, `not json at all`, nil, "", "HTTP 500"},
	}
	for _, c := range cases {
		f := newVaultFake(t, c.status, c.body, c.header)
		res, err := f.client(t).Handover(context.Background(), "workspace/x#y", 3600)
		var ae *APIError
		if res != nil || !errors.As(err, &ae) {
			t.Errorf("%d %s: res=%v err=%v, want an APIError", c.status, c.body, res, err)
			continue
		}
		if ae.Status != c.status || ae.Code != c.code || !strings.Contains(ae.Error(), c.want) {
			t.Errorf("%d %s: got status=%d code=%q msg=%q, want code %q containing %q", c.status, c.body, ae.Status, ae.Code, ae.Message, c.code, c.want)
		}
		if f.count() != 1 {
			t.Errorf("%d: %d requests, want 1 (a refusal is never retried)", c.status, f.count())
		}
	}
}

func TestHandoverRefusesAnAnswerWithoutAUsableKey(t *testing.T) {
	for name, body := range map[string]string{
		"no token":       `{"expires_at":"2026-11-16T12:00:00Z","ref":"my/x","uses":1}`,
		"empty token":    handoverAnswer(""),
		"just a prefix":  handoverAnswer("pat_"),
		"wrong prefix":   handoverAnswer("tok_abc123"),
		"has a space":    handoverAnswer("pat_abc def"),
		"terminal codes": handoverAnswer("pat_abc\u001b]52;c;ZmFrZQ==\u0007"),
		"has a newline":  handoverAnswer("pat_abc\ndef"),
		"too long":       handoverAnswer("pat_" + strings.Repeat("a", 300)),
		"not json":       `<html>`,
	} {
		f := newVaultFake(t, http.StatusCreated, body, nil)
		res, err := f.client(t).Handover(context.Background(), "my/x", 3600)
		if res != nil || err == nil || !strings.Contains(err.Error(), "unexpected answer") {
			t.Errorf("%s: res=%v err=%v, want 'unexpected answer'", name, res, err)
		}
		if err != nil && strings.Contains(err.Error(), "pat_") {
			t.Errorf("%s: the error carries a key: %v", name, err)
		}
	}
}

func TestHandoverNeverFollowsARedirect(t *testing.T) {
	f := newVaultFake(t, http.StatusTemporaryRedirect, ``, map[string]string{"Location": "https://elsewhere.example.test/"})
	if res, err := f.client(t).Handover(context.Background(), "my/x", 3600); res != nil || err == nil {
		t.Fatalf("a redirect must be an error: res=%v err=%v", res, err)
	}
	if f.count() != 1 {
		t.Fatalf("%d requests", f.count())
	}
}

func TestKeyExpiryComesFromTheFetchAndCheckAnswers(t *testing.T) {
	want := time.Date(2026, 11, 16, 10, 30, 0, 0, time.UTC)
	for _, check := range []bool{false, true} {
		f := newFake(t, 200, `{"values":{"a":"x"},"items":[{"ref":"a","resolves":true}]}`)
		f.extra = map[string]string{"X-Key-Expires": want.Format(time.RFC3339)}
		c := f.client(t)
		if _, ok := c.KeyExpires(); ok {
			t.Fatal("no expiry before any call")
		}
		var err error
		if check {
			_, err = c.Check(context.Background(), []string{"a"})
		} else {
			_, err = c.Fetch(context.Background(), []string{"a"})
		}
		if err != nil {
			t.Fatal(err)
		}
		got, ok := c.KeyExpires()
		if !ok || !got.Equal(want) {
			t.Errorf("check=%v: expiry %v ok=%v, want %v", check, got, ok, want)
		}
	}
}

func TestKeyExpiryIgnoresAMissingOrUnreadableHeader(t *testing.T) {
	for name, hdr := range map[string]map[string]string{
		"missing":     nil,
		"empty":       {"X-Key-Expires": ""},
		"not a time":  {"X-Key-Expires": "tomorrow"},
		"a number":    {"X-Key-Expires": "1795000000"},
		"half a time": {"X-Key-Expires": "2026-11-16"},
	} {
		f := newFake(t, 200, `{"values":{"a":"x"}}`)
		f.extra = hdr
		c := f.client(t)
		if _, err := c.Fetch(context.Background(), []string{"a"}); err != nil {
			t.Fatal(err)
		}
		if got, ok := c.KeyExpires(); ok {
			t.Errorf("%s: expiry %v must not be reported", name, got)
		}
	}
}

func TestKeyExpiryIsNotTakenFromARefusedAnswer(t *testing.T) {
	f := newFake(t, 404, `{"error":"not_found"}`)
	f.extra = map[string]string{"X-Key-Expires": "2026-11-16T10:30:00Z"}
	c := f.client(t)
	if _, err := c.Fetch(context.Background(), []string{"a"}); err == nil {
		t.Fatal("expected an error")
	}
	if got, ok := c.KeyExpires(); ok {
		t.Errorf("a refused call reported expiry %v", got)
	}
}

func TestBaseURLHasNoTrailingSlash(t *testing.T) {
	c, err := New("https://api.example.test/prefix/", testToken)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.BaseURL(); got != "https://api.example.test/prefix" {
		t.Fatalf("BaseURL = %q", got)
	}
}

// ---- helpers on the shared vault fake ------------------------------------------------

func (f *vaultFake) last() vaultReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		return vaultReq{}
	}
	return f.reqs[len(f.reqs)-1]
}

func (f *vaultFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *vaultFake) set(status int, answer string, header map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.answer, f.header = status, answer, header
}
