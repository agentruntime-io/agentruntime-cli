package bffclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// fakeValue stands for a secret value. The API never sends one to these calls; the tests make it send one anyway
// and check that the client's types have no place for it.
const fakeValue = "FAKE-VALUE-DO-NOT-USE-0005"

// vaultFake stands in for the vault routes: it records each request and answers with a fixed status, headers and body.
type vaultFake struct {
	*httptest.Server
	mu     sync.Mutex
	reqs   []vaultReq
	status int
	header map[string]string
	answer string
}

type vaultReq struct {
	Method, Path, Query, Auth, Agent string
	Body                             map[string]any
	RawBody                          string
}

func newVaultFake(t *testing.T, status int, answer string, header map[string]string) *vaultFake {
	t.Helper()
	f := &vaultFake{status: status, answer: answer, header: header}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		req := vaultReq{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"), Agent: r.Header.Get("User-Agent"), RawBody: string(raw)}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &req.Body)
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, req)
		status, answer, header := f.status, f.answer, f.header
		f.mu.Unlock()
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *vaultFake) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(f.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *vaultFake) only(t *testing.T) vaultReq {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 1 {
		t.Fatalf("%d requests, want 1: %+v", len(f.reqs), f.reqs)
	}
	return f.reqs[0]
}

func ints(n int) *int { return &n }

const historyBody = `{"current_version":3,"keep_versions":5,"expire_after_seconds":604800,"expires_at":"2026-11-23T10:00:00Z","description":"Payments key",
	"labels":{"env":"prod","stripe":""},"value":"` + fakeValue + `","data":{"K":"` + fakeValue + `"},
	"versions":[
		{"version":3,"written_at":"2026-11-16T10:00:00Z","written_by_user_id":"u-1","written_by_name":"Jo","kind":"restore","restored_from":1,"keys_changed":["API_KEY"],"state":"current","value":"` + fakeValue + `"},
		{"version":2,"written_at":"2026-11-15T10:00:00Z","written_by_user_id":"u-2","kind":"update","keys_added":["REGION"],"keys_removed":["OLD"],"state":"available"},
		{"version":1,"kind":"unknown","state":"deleted","keys_added":null}
	],
	"rights":{"can_restore":true,"can_edit_details":true,"can_edit_limits":false}}`

func TestHistoryReadsTheRowsAndDropsAnyValue(t *testing.T) {
	f := newVaultFake(t, 200, historyBody, nil)
	h, err := f.client(t).History(context.Background(), "tenant", "live/stripe")
	if err != nil {
		t.Fatal(err)
	}
	req := f.only(t)
	if req.Method != http.MethodGet || req.Path != "/v1/vault/secret/versions" || req.Query != "path=live%2Fstripe&scope=tenant" || req.RawBody != "" {
		t.Fatalf("request %+v", req)
	}
	if req.Auth != "Bearer "+testToken || !strings.HasPrefix(req.Agent, "agentruntime-cli/") {
		t.Fatalf("headers: auth %q agent %q", req.Auth, req.Agent)
	}
	if h.CurrentVersion != 3 || h.KeepVersions == nil || *h.KeepVersions != 5 || h.ExpireAfterSeconds == nil || *h.ExpireAfterSeconds != 604800 ||
		h.ExpiresAt == nil || *h.ExpiresAt != "2026-11-23T10:00:00Z" || h.Description != "Payments key" ||
		!reflect.DeepEqual(h.Labels, map[string]string{"env": "prod", "stripe": ""}) || h.Rights == nil || !h.Rights.CanRestore || h.Rights.CanEditLimits {
		t.Fatalf("header %+v", h)
	}
	if len(h.Versions) != 3 || h.Versions[0].WrittenByName != "Jo" || h.Versions[0].RestoredFrom != 1 || h.Versions[1].KeysRemoved[0] != "OLD" || h.Versions[2].Kind != "unknown" {
		t.Fatalf("versions %+v", h.Versions)
	}
	raw, _ := json.Marshal(h)
	if strings.Contains(string(raw), fakeValue) {
		t.Fatalf("the history carries a value: %s", raw)
	}
}

func TestHistoryNullSettingsStayNil(t *testing.T) {
	f := newVaultFake(t, 200, `{"current_version":1,"keep_versions":null,"expire_after_seconds":null,"expires_at":null,"versions":[]}`, nil)
	h, err := f.client(t).History(context.Background(), "user", "a")
	if err != nil {
		t.Fatal(err)
	}
	if h.KeepVersions != nil || h.ExpireAfterSeconds != nil || h.ExpiresAt != nil {
		t.Fatalf("null settings read as %+v", h)
	}
	raw, _ := json.Marshal(h)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"keep_versions", "expire_after_seconds", "expires_at"} {
		if v, ok := m[k]; !ok || v != nil {
			t.Errorf("%s must be an explicit null in JSON, got %v (present %v)", k, v, ok)
		}
	}
}

func TestHistoryRejectsAnUnreadableAnswer(t *testing.T) {
	f := newVaultFake(t, 200, `<html>proxy</html>`, nil)
	if _, err := f.client(t).History(context.Background(), "user", "a"); err == nil || strings.Contains(err.Error(), "proxy") {
		t.Fatalf("err %v: want a fixed sentence without the body", err)
	}
}

func TestRestorePostsExactlyTheContractBody(t *testing.T) {
	f := newVaultFake(t, 200, `{"path":"live/stripe","scope":"tenant","version":4,"value":"`+fakeValue+`"}`, nil)
	res, err := f.client(t).Restore(context.Background(), "tenant", "live/stripe", 2)
	if err != nil {
		t.Fatal(err)
	}
	req := f.only(t)
	if req.Method != http.MethodPost || req.Path != "/v1/vault/secret/restore" || req.Query != "" {
		t.Fatalf("request %+v", req)
	}
	if want := map[string]any{"scope": "tenant", "path": "live/stripe", "version": float64(2)}; !reflect.DeepEqual(req.Body, want) {
		t.Fatalf("body %v want %v", req.Body, want)
	}
	if res.Version != 4 {
		t.Fatalf("restored %+v", res)
	}
	if raw, _ := json.Marshal(res); strings.Contains(string(raw), fakeValue) {
		t.Fatalf("the answer carries a value: %s", raw)
	}
}

func TestRestoreAcceptsAnEmptyAnswer(t *testing.T) {
	f := newVaultFake(t, 204, ``, nil)
	if res, err := f.client(t).Restore(context.Background(), "user", "a", 1); err != nil || res == nil || res.Version != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDeletedReadsTheListAndTheCountEitherWay(t *testing.T) {
	body := `{"items":[
		{"path":"live/stripe","deleted_at":"2026-11-16T09:00:00Z","deleted_by_user_id":"u-1","reason":"deleted","owner_user_id":"u-2","versions":3,"can_undelete":true,"can_destroy":true,"value":"` + fakeValue + `"},
		{"path":"tmp/token","reason":"expired","versions":[2,3],"can_undelete":false}]}`
	f := newVaultFake(t, 200, body, nil)
	items, supported, err := f.client(t).Deleted(context.Background(), "project")
	if err != nil || !supported {
		t.Fatalf("supported=%v err=%v", supported, err)
	}
	req := f.only(t)
	if req.Method != http.MethodGet || req.Path != "/v1/vault/secrets/deleted" || req.Query != "scope=project" {
		t.Fatalf("request %+v", req)
	}
	if len(items) != 2 || items[0].Versions != 3 || items[1].Versions != 2 || !items[0].CanUndelete || items[1].Reason != "expired" {
		t.Fatalf("items %+v", items)
	}
	if raw, _ := json.Marshal(items); strings.Contains(string(raw), fakeValue) {
		t.Fatalf("the list carries a value: %s", raw)
	}

	f2 := newVaultFake(t, 200, `[{"path":"a","can_undelete":true}]`, nil)
	items, supported, err = f2.client(t).Deleted(context.Background(), "user")
	if err != nil || !supported || len(items) != 1 || items[0].Path != "a" {
		t.Fatalf("bare array: items=%+v supported=%v err=%v", items, supported, err)
	}
}

// Only the exact "not supported" answer reads as unsupported; any other 404 is an error.
func TestDeletedUnsupportedIsNotAnError(t *testing.T) {
	f := newVaultFake(t, 404, `{"error":"feature_unavailable","message":"This workspace cannot recover deleted secrets."}`, nil)
	items, supported, err := f.client(t).Deleted(context.Background(), "tenant")
	if err != nil || supported || len(items) != 0 {
		t.Fatalf("items=%v supported=%v err=%v", items, supported, err)
	}
	f = newVaultFake(t, 404, `{"error":"not_found","message":"no"}`, nil)
	if _, _, err := f.client(t).Deleted(context.Background(), "tenant"); err == nil {
		t.Fatal("a plain 404 must stay an error")
	}
	f = newVaultFake(t, 403, `{"error":"feature_unavailable","message":"x"}`, nil)
	if _, _, err := f.client(t).Deleted(context.Background(), "tenant"); err == nil {
		t.Fatal("feature_unavailable with another status must stay an error")
	}
}

func TestUndeleteAndDestroyBodies(t *testing.T) {
	f := newVaultFake(t, 204, ``, nil)
	c := f.client(t)
	if err := c.Undelete(context.Background(), "user", "a/b"); err != nil {
		t.Fatal(err)
	}
	if err := c.Destroy(context.Background(), "tenant", "a/b", "a/b"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 2 {
		t.Fatalf("requests %+v", f.reqs)
	}
	if r := f.reqs[0]; r.Method != http.MethodPost || r.Path != "/v1/vault/secret/undelete" || !reflect.DeepEqual(r.Body, map[string]any{"scope": "user", "path": "a/b"}) {
		t.Errorf("undelete %+v", r)
	}
	if r := f.reqs[1]; r.Method != http.MethodPost || r.Path != "/v1/vault/secret/destroy" || !reflect.DeepEqual(r.Body, map[string]any{"scope": "tenant", "path": "a/b", "confirm": "a/b"}) {
		t.Errorf("destroy %+v", r)
	}
}

func TestDeleteReadsTheRecoverableHeader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header map[string]string
		want   bool
	}{
		{"true", map[string]string{"X-Recoverable": "true"}, true},
		{"True with spaces", map[string]string{"X-Recoverable": " True "}, true},
		{"false", map[string]string{"X-Recoverable": "false"}, false},
		{"absent (an older server: permanent)", nil, false},
		{"something else", map[string]string{"X-Recoverable": "yes"}, false},
	} {
		f := newVaultFake(t, 204, ``, tc.header)
		got, err := f.client(t).Delete(context.Background(), "tenant", "live/stripe")
		if err != nil || got != tc.want {
			t.Errorf("%s: recoverable=%v err=%v, want %v", tc.name, got, err, tc.want)
		}
		req := f.only(t)
		if req.Method != http.MethodDelete || req.Path != "/v1/vault/secrets" || req.Query != "path=live%2Fstripe&scope=tenant" || req.RawBody != "" {
			t.Errorf("%s: request %+v", tc.name, req)
		}
	}
}

// Only what is set is sent, and null (the default, never) is told from a left-out field.
func TestUpdateSettingsSendsOnlyWhatIsSet(t *testing.T) {
	desc, empty := "Payments key", ""
	for name, tc := range map[string]struct {
		change SettingsChange
		want   map[string]any
	}{
		"description":        {SettingsChange{Description: &desc}, map[string]any{"description": "Payments key"}},
		"clear description":  {SettingsChange{Description: &empty}, map[string]any{"description": ""}},
		"labels":             {SettingsChange{Labels: map[string]string{"env": "prod", "t": ""}}, map[string]any{"labels": map[string]any{"env": "prod", "t": ""}}},
		"remove every label": {SettingsChange{Labels: map[string]string{}}, map[string]any{"labels": map[string]any{}}},
		"keep a number":      {SettingsChange{KeepVersions: Number(5)}, map[string]any{"keep_versions": float64(5)}},
		"keep default":       {SettingsChange{KeepVersions: Reset()}, map[string]any{"keep_versions": nil}},
		"expire a number":    {SettingsChange{ExpireAfterSeconds: Number(604800)}, map[string]any{"expire_after_seconds": float64(604800)}},
		"expire never":       {SettingsChange{ExpireAfterSeconds: Reset()}, map[string]any{"expire_after_seconds": nil}},
		"all at once":        {SettingsChange{Description: &desc, Labels: map[string]string{"a": "b"}, KeepVersions: Reset(), ExpireAfterSeconds: Reset()}, map[string]any{"description": "Payments key", "labels": map[string]any{"a": "b"}, "keep_versions": nil, "expire_after_seconds": nil}},
	} {
		f := newVaultFake(t, 200, `{"current_version":5,"keep_versions":null,"expire_after_seconds":null,"expires_at":null,"value":"`+fakeValue+`"}`, nil)
		d, err := f.client(t).UpdateSettings(context.Background(), "tenant", "live/stripe", tc.change)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		req := f.only(t)
		if req.Method != http.MethodPut || req.Path != "/v1/vault/secret/settings" || req.Query != "" {
			t.Fatalf("%s: request %+v", name, req)
		}
		want := map[string]any{"scope": "tenant", "path": "live/stripe"}
		for k, v := range tc.want {
			want[k] = v
		}
		if !reflect.DeepEqual(req.Body, want) {
			t.Errorf("%s: body %v want %v", name, req.Body, want)
		}
		if d.CurrentVersion != 5 {
			t.Errorf("%s: details %+v", name, d)
		}
		if raw, _ := json.Marshal(d); strings.Contains(string(raw), fakeValue) {
			t.Errorf("%s: the answer carries a value: %s", name, raw)
		}
	}
	f := newVaultFake(t, 200, `{}`, nil)
	if _, err := f.client(t).UpdateSettings(context.Background(), "tenant", "a", SettingsChange{}); err == nil {
		t.Error("an empty change must be refused")
	}
	if len(f.reqs) != 0 {
		t.Errorf("an empty change reached the server: %+v", f.reqs)
	}
}

// The server's own sentence is shown; its fixed code picks a sentence when it sent none; a status picks one when it
// sent neither. No body text ever reaches the error.
func TestVaultErrorAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		header  map[string]string
		code    string
		contain string
		not     string
	}{
		{"server sentence wins", 409, `{"error":"conflict","message":"The secret changed. Read its history."}`, nil, "conflict", "The secret changed. Read its history.", ""},
		{"code only: already_current", 409, `{"error":"already_current"}`, nil, "already_current", "already the current one", ""},
		{"code only: version_unavailable", 404, `{"error":"version_unavailable"}`, nil, "version_unavailable", "not available any more", ""},
		{"code only: deleted_secret_exists", 409, `{"error":"deleted_secret_exists"}`, nil, "deleted_secret_exists", "Recently deleted", ""},
		{"code only: confirm_required", 400, `{"error":"confirm_required"}`, nil, "confirm_required", "send its path as confirmation", ""},
		{"code only: destroy_not_for_ai_clients", 403, `{"error":"destroy_not_for_ai_clients"}`, nil, "destroy_not_for_ai_clients", "not available to AI clients", ""},
		{"code only: feature_unavailable", 404, `{"error":"feature_unavailable"}`, nil, "feature_unavailable", "does not support this", ""},
		{"code only: audit_failed", 503, `{"error":"audit_failed"}`, nil, "audit_failed", "nothing was changed", ""},
		{"labels_invalid", 400, `{"error":"labels_invalid"}`, nil, "labels_invalid", "labels are not valid", ""},
		{"no body: 401", 401, ``, nil, "", "agentruntime login", ""},
		{"no body: 403", 403, ``, nil, "", "HTTP 403", ""},
		{"html body: 502", 502, `<html>secret_in_page ` + fakeValue + `</html>`, nil, "", "HTTP 502", fakeValue},
		{"rate limited with retry", 429, `{"error":"rate_limited"}`, map[string]string{"Retry-After": "12"}, "rate_limited", "Too many requests", ""},
		{"control characters in the server text", 400, "{\"error\":\"x\",\"message\":\"bad\\u001b[31m text\"}", nil, "x", "bad", "\x1b"},
	} {
		f := newVaultFake(t, tc.status, tc.body, tc.header)
		_, err := f.client(t).Restore(context.Background(), "user", "a", 1)
		var ae *APIError
		if err == nil || !errorsAs(err, &ae) {
			t.Fatalf("%s: err %v", tc.name, err)
		}
		if ae.Status != tc.status || ae.Code != tc.code || !strings.Contains(ae.Error(), tc.contain) {
			t.Errorf("%s: status=%d code=%q msg=%q, want status %d code %q containing %q", tc.name, ae.Status, ae.Code, ae.Error(), tc.status, tc.code, tc.contain)
		}
		if tc.not != "" && strings.Contains(err.Error(), tc.not) {
			t.Errorf("%s: the error holds %q: %v", tc.name, tc.not, err)
		}
		if tc.header != nil && ae.RetryAfter != "12" {
			t.Errorf("%s: RetryAfter %q", tc.name, ae.RetryAfter)
		}
	}
}

func errorsAs(err error, target **APIError) bool {
	ae, ok := err.(*APIError)
	if ok {
		*target = ae
	}
	return ok
}

func TestVaultRoutesNeverFollowARedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a redirect was followed to %s (auth %q)", r.URL, r.Header.Get("Authorization"))
	}))
	t.Cleanup(other.Close)
	f := newVaultFake(t, http.StatusTemporaryRedirect, ``, map[string]string{"Location": other.URL + "/v1/vault/secret/versions"})
	if _, err := f.client(t).History(context.Background(), "user", "a"); err == nil {
		t.Fatal("a redirect is an error")
	}
}

func TestVaultAnswerLargerThanTheCapIsRefused(t *testing.T) {
	f := newVaultFake(t, 200, `{"current_version":1,"description":"`+strings.Repeat("x", maxAnswerBytes+10)+`"}`, nil)
	if _, err := f.client(t).History(context.Background(), "user", "a"); err == nil || !strings.Contains(err.Error(), "larger than expected") {
		t.Fatalf("err %v", err)
	}
}

func TestVaultUnreachableServerErrorHasNoToken(t *testing.T) {
	f := newVaultFake(t, 200, `{}`, nil)
	c := f.client(t)
	f.Close()
	_, err := c.History(context.Background(), "user", "a")
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("err %v", err)
	}
}

func TestCountReadsANumberAnArrayOrNull(t *testing.T) {
	for in, want := range map[string]Count{`3`: 3, `[1,2,3,4]`: 4, `null`: 0, `[]`: 0} {
		var c Count
		if err := json.Unmarshal([]byte(in), &c); err != nil || c != want {
			t.Errorf("%s: %d %v, want %d", in, c, err, want)
		}
	}
	var c Count
	if err := json.Unmarshal([]byte(`"x"`), &c); err == nil {
		t.Error("a string must not be a count")
	}
}
