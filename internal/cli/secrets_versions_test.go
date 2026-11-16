package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Every value below is fake. The fake API sends one in every answer (the real one never does) to prove that no
// command prints it: history, restore, Recently deleted and settings show facts about a secret, never what it holds.

type vaultCall struct {
	Method, Path, Query, Auth string
	Body                      map[string]any
}

type vaultAnswer struct {
	Status int
	Header map[string]string
	Body   string
}

// vaultAPI stands in for the /v1/vault routes the version commands call.
type vaultAPI struct {
	*httptest.Server
	mu      sync.Mutex
	calls   []vaultCall
	answers map[string]vaultAnswer // "METHOD /path"
}

func newVaultAPI(t *testing.T) *vaultAPI {
	t.Helper()
	leak := `"value":"` + fakeKey + `","data":{"API_KEY":"` + fakeKey + `"},"values":{"API_KEY":"` + fakeHook + `"}`
	v := &vaultAPI{answers: map[string]vaultAnswer{
		"GET /v1/vault/secret/versions": {200, nil, `{"current_version":3,"keep_versions":5,"expire_after_seconds":604800,"expires_at":"2026-11-23T10:00:00Z",
			"description":"Payments key","labels":{"env":"prod","stripe":""},` + leak + `,
			"versions":[
				{"version":3,"written_at":"2026-11-16T10:00:00Z","written_by_user_id":"u-1","kind":"restore","restored_from":1,"keys_changed":["API_KEY"],"state":"current",` + leak + `},
				{"version":2,"written_at":"2026-11-15T10:00:00Z","written_by_user_id":"u-2","written_by_name":"Jo","kind":"update","keys_added":["REGION"],"keys_removed":["OLD"],"state":"available"},
				{"version":1,"kind":"unknown","state":"deleted"}],
			"rights":{"can_restore":true,"can_edit_details":true,"can_edit_limits":false}}`},
		"POST /v1/vault/secret/restore":  {200, nil, `{"path":"live/stripe","scope":"tenant","version":4,` + leak + `}`},
		"GET /v1/vault/secrets/deleted":  {200, nil, `{"items":[{"path":"live/old","deleted_at":"2026-11-16T09:00:00Z","deleted_by_user_id":"u-1","reason":"deleted","versions":3,"can_undelete":true,"can_destroy":true,` + leak + `},{"path":"tmp/x","reason":"expired","versions":[1,2],"can_undelete":true}]}`},
		"POST /v1/vault/secret/undelete": {204, nil, ``},
		"DELETE /v1/vault/secrets":       {204, map[string]string{"X-Recoverable": "true"}, ``},
		"POST /v1/vault/secret/destroy":  {200, nil, `{"destroyed":true,` + leak + `}`},
		"PUT /v1/vault/secret/settings":  {200, nil, `{"current_version":5,"keep_versions":null,"expire_after_seconds":null,"expires_at":null,"description":"d","labels":{"a":"b"},` + leak + `}`},
	}}
	v.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		call := vaultCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization")}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &call.Body)
		}
		v.mu.Lock()
		v.calls = append(v.calls, call)
		ans, ok := v.answers[r.Method+" "+r.URL.Path]
		v.mu.Unlock()
		if call.Auth != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		for k, val := range ans.Header {
			w.Header().Set(k, val)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ans.Status)
		_, _ = w.Write([]byte(ans.Body))
	}))
	t.Cleanup(v.Close)
	return v
}

func (v *vaultAPI) answer(route string, status int, header map[string]string, body string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.answers[route] = vaultAnswer{status, header, body}
}

func (v *vaultAPI) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.calls)
}

func (v *vaultAPI) last() vaultCall {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.calls) == 0 {
		return vaultCall{}
	}
	return v.calls[len(v.calls)-1]
}

func (v *vaultAPI) all() []vaultCall {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]vaultCall(nil), v.calls...)
}

// runV runs `agentruntime secrets <sub> --api-url <fake> <args...>` with the test access key.
func runV(t *testing.T, v *vaultAPI, stdin, sub string, args ...string) (int, string, string) {
	t.Helper()
	isolate(t)
	return run(t, stdin, append([]string{"--pat", testToken, "secrets", sub, "--api-url", v.URL}, args...)...)
}

func mustJSON(t *testing.T, what, out string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("%s: --json output is not valid JSON: %v\n%s", what, err, out)
	}
	return m
}

// ---- history ------------------------------------------------------------------------

func TestHistoryShowsWhoWhenAndWhichFieldsNeverAValue(t *testing.T) {
	v := newVaultAPI(t)
	code, out, errOut := runV(t, v, "", "history", "live/stripe", "--scope", "tenant")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	c := v.last()
	if c.Method != http.MethodGet || c.Path != "/v1/vault/secret/versions" || c.Query != "path=live%2Fstripe&scope=tenant" || c.Auth != "Bearer "+testToken {
		t.Fatalf("request %+v", c)
	}
	for _, want := range []string{
		"live/stripe (tenant)", "current version 3", "the last 5 versions", "7d after the last save", "2026-11-23T10:00:00Z",
		"Payments key", "env=prod, stripe",
		"VERSION", "STATE", "WHEN", "BY", "KIND", "WHAT",
		"restored from version 1; changed API_KEY", "added REGION; removed OLD", "saved before history was recorded",
		"Jo (u-2)", "u-1", "current", "available", "deleted", "restore", "update", "unknown",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	assertNoValue(t, "history", out, errOut)
}

func TestHistoryJSONStaysValidAndHoldsNoValue(t *testing.T) {
	v := newVaultAPI(t)
	code, out, errOut := runV(t, v, "", "history", "live/stripe", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	m := mustJSON(t, "history", out)
	if m["current_version"] != float64(3) || len(m["versions"].([]any)) != 3 {
		t.Errorf("json %v", m)
	}
	rows := m["versions"].([]any)
	if first := rows[0].(map[string]any); first["state"] != "current" || first["restored_from"] != float64(1) {
		t.Errorf("first row %v", first)
	}
	assertNoValue(t, "history --json", out, errOut)
	for _, bad := range []string{`"value"`, `"data"`, `"values"`} {
		if strings.Contains(out, bad) {
			t.Errorf("--json output carries %s: %s", bad, out)
		}
	}
	// No --scope: the workspace room is sent explicitly.
	if c := v.last(); !strings.Contains(c.Query, "scope=tenant") {
		t.Errorf("default scope: query %q", c.Query)
	}
}

func TestHistoryNullSettingsRead(t *testing.T) {
	v := newVaultAPI(t)
	v.answer("GET /v1/vault/secret/versions", 200, nil, `{"current_version":1,"keep_versions":null,"expire_after_seconds":null,"expires_at":null,"versions":[{"version":1,"kind":"create","state":"current","keys_added":["A","B"]}]}`)
	_, out, _ := runV(t, v, "", "history", "a")
	for _, want := range []string{"workspace default number of versions", "Auto-expire:  never", "create", "added A, B"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	_, jsonOut, _ := runV(t, v, "", "history", "a", "--json")
	m := mustJSON(t, "null settings", jsonOut)
	for _, k := range []string{"keep_versions", "expire_after_seconds", "expires_at"} {
		if val, ok := m[k]; !ok || val != nil {
			t.Errorf("%s = %v (present %v), want an explicit null", k, val, ok)
		}
	}
}

// Names and paths are whatever their author typed: the terminal must not act on them.
func TestHistoryEscapesWhatATerminalWouldActOn(t *testing.T) {
	v := newVaultAPI(t)
	v.answer("GET /v1/vault/secret/versions", 200, nil,
		"{\"current_version\":1,\"description\":\"hi\\u001b]0;pwned\\u0007\",\"labels\":{\"a\":\"b\\u001b[31m\"},\"versions\":[{\"version\":1,\"kind\":\"update\",\"state\":\"current\",\"written_by_user_id\":\"u\\u001b[2J\",\"keys_changed\":[\"K\\u001b[1;1H\",\"Z\\u202eevil\"]}]}")
	code, out, errOut := runV(t, v, "", "history", "bad\x1b[31mpath")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, raw := range []string{"\x1b", "\x07", "\u202e"} {
		if strings.Contains(out, raw) {
			t.Errorf("output holds %q raw:\n%q", raw, out)
		}
	}
	for _, shown := range []string{`\x1b`, `\u202e`} {
		if !strings.Contains(out, shown) {
			t.Errorf("output does not show %s:\n%s", shown, out)
		}
	}
}

func TestHistoryNeedsOnePathAndAValidScope(t *testing.T) {
	v := newVaultAPI(t)
	for name, args := range map[string][]string{
		"no path":      {},
		"two paths":    {"a", "b"},
		"shared":       {"a", "--scope", "shared"},
		"unknown room": {"a", "--scope", "workspace"},
	} {
		// a wrong number of arguments is cobra's error (exit 1), a bad --scope is ours (exit 2): both refuse.
		if code, _, _ := runV(t, v, "", "history", args...); code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if v.count() != 0 {
		t.Errorf("a usage error reached the server: %+v", v.all())
	}
	if code, _, errOut := runV(t, v, "", "history", "a", "--scope", "shared"); !strings.Contains(errOut, "read-only") {
		t.Errorf("shared: code=%d err=%q", code, errOut)
	}
}

// Both spellings of the group, and the alias `versions`, reach the same command.
func TestHistoryAliases(t *testing.T) {
	v := newVaultAPI(t)
	isolate(t)
	for _, args := range [][]string{
		{"--pat", testToken, "vault", "history", "a", "--api-url", v.URL},
		{"--pat", testToken, "secrets", "versions", "a", "--api-url", v.URL},
		{"--pat", testToken, "vault", "versions", "a", "--api-url", v.URL},
	} {
		if code, out, errOut := run(t, "", args...); code != 0 || !strings.Contains(out, "current version") {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
}

// ---- restore ------------------------------------------------------------------------

func TestRestoreSendsTheVersionAndPrintsTheNewOne(t *testing.T) {
	v := newVaultAPI(t)
	code, out, errOut := runV(t, v, "", "restore", "live/stripe", "--version", "2", "--scope", "tenant")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	c := v.last()
	if c.Method != http.MethodPost || c.Path != "/v1/vault/secret/restore" || c.Auth != "Bearer "+testToken {
		t.Fatalf("request %+v", c)
	}
	if want := map[string]any{"scope": "tenant", "path": "live/stripe", "version": float64(2)}; !reflect.DeepEqual(c.Body, want) {
		t.Errorf("body %v want %v", c.Body, want)
	}
	if !strings.Contains(out, "Restored version 2 of live/stripe as version 4.") {
		t.Errorf("output %q", out)
	}
	assertNoValue(t, "restore", out, errOut)

	code, out, _ = runV(t, v, "", "restore", "live/stripe", "--version", "2", "--json")
	m := mustJSON(t, "restore", out)
	if code != 0 || m["restored"] != true || m["version"] != float64(4) || m["restored_from"] != float64(2) || m["scope"] != "tenant" {
		t.Errorf("json %v", m)
	}
	assertNoValue(t, "restore --json", out)
}

func TestRestoreNeedsAVersion(t *testing.T) {
	v := newVaultAPI(t)
	for name, args := range map[string][]string{
		"no version":       {"a"},
		"version zero":     {"a", "--version", "0"},
		"negative version": {"a", "--version", "-2"},
		"not a number":     {"a", "--version", "x"},
		"shared":           {"a", "--version", "1", "--scope", "shared"},
	} {
		if code, _, _ := runV(t, v, "", "restore", args...); code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if code, _, _ := runV(t, v, "", "restore", "a"); code != ExitUsage {
		t.Errorf("no version: exit %d, want 2", code)
	}
	if v.count() != 0 {
		t.Errorf("a usage error reached the server: %+v", v.all())
	}
}

// Each answer of the API has its own sentence; with none, the code picks one; stdout stays empty.
func TestVersionCommandsShowTheServersFixedSentenceForEachCode(t *testing.T) {
	type tc struct {
		route, sub string
		args       []string
	}
	routes := []tc{
		{"POST /v1/vault/secret/restore", "restore", []string{"a", "--version", "1"}},
		{"POST /v1/vault/secret/undelete", "undelete", []string{"a"}},
		{"GET /v1/vault/secret/versions", "history", []string{"a"}},
	}
	codes := []struct {
		status           int
		code, withServer string
		fallbackHas      string
	}{
		{409, "already_current", "That version is already current.", "already the current one"},
		{409, "conflict", "The secret changed.", "changed in the meantime"},
		{404, "version_unavailable", "That version is gone.", "not available any more"},
		{409, "deleted_secret_exists", "A deleted secret has this name.", "Recently deleted"},
		{403, "destroy_not_for_ai_clients", "No destroy for AI clients.", "not available to AI clients"},
		{404, "not_found", "No such secret.", "was not found"},
		{503, "audit_failed", "Could not record it.", "nothing was changed"},
	}
	for _, r := range routes {
		for _, c := range codes {
			v := newVaultAPI(t)
			// the server's own sentence
			v.answer(r.route, c.status, nil, `{"error":"`+c.code+`","message":"`+c.withServer+`"}`)
			code, out, errOut := runV(t, v, "", r.sub, r.args...)
			if code != ExitError || !strings.Contains(errOut, c.withServer) || !strings.Contains(errOut, c.code) || out != "" {
				t.Errorf("%s %s: code=%d out=%q err=%q", r.sub, c.code, code, out, errOut)
			}
			// the code alone
			v.answer(r.route, c.status, nil, `{"error":"`+c.code+`"}`)
			code, out, errOut = runV(t, v, "", r.sub, r.args...)
			if code != ExitError || !strings.Contains(errOut, c.fallbackHas) || out != "" {
				t.Errorf("%s %s (no sentence): code=%d out=%q err=%q", r.sub, c.code, code, out, errOut)
			}
			assertNoValue(t, r.sub+" "+c.code, out, errOut)
		}
	}
}

func TestVersionCommandsExplainUnauthorizedAndUnreachable(t *testing.T) {
	v := newVaultAPI(t)
	isolate(t)
	code, out, errOut := run(t, "", "--pat", "wrong-token", "secrets", "history", "a", "--api-url", v.URL)
	if code != ExitError || out != "" || !strings.Contains(errOut, "agentruntime login") {
		t.Errorf("401: code=%d out=%q err=%q", code, out, errOut)
	}
	if strings.Contains(errOut, "wrong-token") {
		t.Errorf("the access key is in the error: %q", errOut)
	}
	gone := newVaultAPI(t)
	gone.Close()
	code, _, errOut = runV(t, gone, "", "history", "a")
	if code != ExitError || !strings.Contains(errOut, "cannot reach the API") || strings.Contains(errOut, testToken) {
		t.Errorf("unreachable: code=%d err=%q", code, errOut)
	}
}

// ---- Recently deleted ---------------------------------------------------------------

func TestDeletedListsWhatWasDeletedAndWhatExpired(t *testing.T) {
	v := newVaultAPI(t)
	code, out, errOut := runV(t, v, "", "deleted", "--scope", "project")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if c := v.last(); c.Method != http.MethodGet || c.Path != "/v1/vault/secrets/deleted" || c.Query != "scope=project" {
		t.Fatalf("request %+v", c)
	}
	for _, want := range []string{"PATH", "DELETED", "BY", "WHY", "VERSIONS", "live/old", "u-1", "deleted", "tmp/x", "expired"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	assertNoValue(t, "deleted", out, errOut)

	code, out, _ = runV(t, v, "", "deleted", "--json")
	m := mustJSON(t, "deleted", out)
	items, _ := m["items"].([]any)
	if code != 0 || m["supported"] != true || len(items) != 2 || items[1].(map[string]any)["versions"] != float64(2) {
		t.Errorf("json %v", m)
	}
	assertNoValue(t, "deleted --json", out)
}

func TestDeletedSaysWhenTheWorkspaceCannotRecover(t *testing.T) {
	v := newVaultAPI(t)
	v.answer("GET /v1/vault/secrets/deleted", 404, nil, `{"error":"feature_unavailable","message":"This workspace cannot recover deleted secrets."}`)
	code, out, errOut := runV(t, v, "", "deleted")
	if code != 0 || !strings.Contains(out, "does not support Recently deleted") || errOut != "" {
		t.Errorf("code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, _ = runV(t, v, "", "deleted", "--json")
	m := mustJSON(t, "unsupported", out)
	if items, _ := m["items"].([]any); code != 0 || m["supported"] != false || items == nil || len(items) != 0 {
		t.Errorf("json %v (items must be an empty array, not null)", m)
	}
}

func TestDeletedEmptyAndErrors(t *testing.T) {
	v := newVaultAPI(t)
	v.answer("GET /v1/vault/secrets/deleted", 200, nil, `{"items":[]}`)
	if code, out, _ := runV(t, v, "", "deleted"); code != 0 || !strings.Contains(out, "Nothing in Recently deleted") {
		t.Errorf("empty: code=%d out=%q", code, out)
	}
	if code, out, _ := runV(t, v, "", "deleted", "--json"); code != 0 {
		t.Errorf("empty json: code=%d", code)
	} else if m := mustJSON(t, "empty", out); m["supported"] != true {
		t.Errorf("empty json %v", m)
	}
	v.answer("GET /v1/vault/secrets/deleted", 403, nil, `{"error":"forbidden","message":"You may not delete in this room."}`)
	if code, out, errOut := runV(t, v, "", "deleted"); code != ExitError || out != "" || !strings.Contains(errOut, "You may not delete in this room.") {
		t.Errorf("403: code=%d out=%q err=%q", code, out, errOut)
	}
	if code, _, _ := runV(t, v, "", "deleted", "extra"); code == 0 {
		t.Errorf("an argument was accepted")
	}
}

func TestUndeleteSendsScopeAndPath(t *testing.T) {
	v := newVaultAPI(t)
	code, out, errOut := runV(t, v, "", "undelete", "live/old", "--scope", "user")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	c := v.last()
	if c.Method != http.MethodPost || c.Path != "/v1/vault/secret/undelete" || !reflect.DeepEqual(c.Body, map[string]any{"scope": "user", "path": "live/old"}) {
		t.Fatalf("request %+v", c)
	}
	if !strings.Contains(out, "Restored live/old from Recently deleted.") {
		t.Errorf("output %q", out)
	}
	_, jsonOut, _ := runV(t, v, "", "undelete", "live/old", "--json")
	if m := mustJSON(t, "undelete", jsonOut); m["undeleted"] != true || m["scope"] != "tenant" {
		t.Errorf("json %v", m)
	}
	if code, _, _ := runV(t, v, "", "undelete"); code == 0 {
		t.Errorf("no path was accepted")
	}
	assertNoValue(t, "undelete", out, errOut, jsonOut)
}

// ---- delete -------------------------------------------------------------------------

func TestDeleteSaysItMovedToRecentlyDeletedWhenTheAnswerSaysSo(t *testing.T) {
	v := newVaultAPI(t)
	code, out, errOut := runV(t, v, "", "delete", "live/stripe", "--scope", "tenant", "--yes")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	c := v.last()
	if c.Method != http.MethodDelete || c.Path != "/v1/vault/secrets" || c.Query != "path=live%2Fstripe&scope=tenant" || c.Body != nil {
		t.Fatalf("request %+v", c)
	}
	for _, want := range []string{"Moved live/stripe to Recently deleted", "agentruntime secrets undelete live/stripe --scope tenant"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	_, jsonOut, _ := runV(t, v, "", "delete", "live/stripe", "--yes", "--json")
	if m := mustJSON(t, "delete", jsonOut); m["deleted"] != true || m["recoverable"] != true || m["scope"] != "tenant" {
		t.Errorf("json %v", m)
	}
}

func TestDeleteSaysPermanentWhenTheAnswerDoesNot(t *testing.T) {
	for name, header := range map[string]map[string]string{
		"false":                  {"X-Recoverable": "false"},
		"no header (old server)": nil,
	} {
		v := newVaultAPI(t)
		v.answer("DELETE /v1/vault/secrets", 204, header, ``)
		code, out, _ := runV(t, v, "", "delete", "live/stripe", "--yes")
		if code != 0 || !strings.Contains(out, "Deleted live/stripe permanently.") || strings.Contains(out, "Recently deleted") {
			t.Errorf("%s: code=%d out=%q", name, code, out)
		}
		_, jsonOut, _ := runV(t, v, "", "delete", "live/stripe", "--yes", "--json")
		if m := mustJSON(t, name, jsonOut); m["recoverable"] != false {
			t.Errorf("%s: json %v", name, m)
		}
	}
}

func TestDeleteAsksFirstUnlessYes(t *testing.T) {
	v := newVaultAPI(t)
	code, _, errOut := runV(t, v, "n\n", "delete", "live/stripe")
	if code != ExitError || !strings.Contains(errOut, "Aborted") || v.count() != 0 {
		t.Errorf("no: code=%d err=%q calls=%d", code, errOut, v.count())
	}
	if code, out, _ := runV(t, v, "y\n", "rm", "live/stripe"); code != 0 || !strings.Contains(out, "Moved live/stripe") || v.count() != 1 {
		t.Errorf("yes: code=%d out=%q calls=%d", code, out, v.count())
	}
}

func TestDeleteErrorsAndScope(t *testing.T) {
	v := newVaultAPI(t)
	v.answer("DELETE /v1/vault/secrets", 403, nil, `{"error":"forbidden","message":"Only a workspace admin can delete here."}`)
	if code, out, errOut := runV(t, v, "", "delete", "a", "--yes"); code != ExitError || out != "" || !strings.Contains(errOut, "Only a workspace admin can delete here.") {
		t.Errorf("403: code=%d out=%q err=%q", code, out, errOut)
	}
	n := v.count()
	if code, _, _ := runV(t, v, "", "delete", "a", "--yes", "--scope", "shared"); code != ExitUsage || v.count() != n {
		t.Errorf("shared: code=%d", code)
	}
}

// ---- delete --destroy ---------------------------------------------------------------

func TestDestroyNeedsTheFlagsTheConfirmationAndTheScope(t *testing.T) {
	v := newVaultAPI(t)
	for name, args := range map[string][]string{
		"destroy alone":                {"live/stripe", "--destroy", "--scope", "tenant"},
		"confirm alone":                {"live/stripe", "--confirm", "live/stripe", "--scope", "tenant"},
		"confirm differs":              {"live/stripe", "--destroy", "--confirm", "live/other", "--scope", "tenant"},
		"confirm differs in case":      {"live/stripe", "--destroy", "--confirm", "Live/Stripe", "--scope", "tenant"},
		"confirm has a trailing space": {"live/stripe", "--destroy", "--confirm", "live/stripe ", "--scope", "tenant"},
		"no scope":                     {"live/stripe", "--destroy", "--confirm", "live/stripe"},
		"shared":                       {"live/stripe", "--destroy", "--confirm", "live/stripe", "--scope", "shared"},
		"yes is not a confirmation":    {"live/stripe", "--destroy", "--yes", "--scope", "tenant"},
	} {
		// "y" on stdin: a command that wrongly fell back to a plain delete would be answered "yes" and reach the API.
		if code, out, errOut := runV(t, v, "y\ny\n", "delete", args...); code != ExitUsage || out != "" || errOut == "" {
			t.Errorf("%s: code=%d out=%q err=%q, want a usage error", name, code, out, errOut)
		}
	}
	if v.count() != 0 {
		t.Fatalf("a refused destroy reached the server: %+v", v.all())
	}
	// Each refusal says what is missing.
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"destroy alone":     {[]string{"live/stripe", "--destroy", "--scope", "tenant"}, "--confirm live/stripe"},
		"yes is not enough": {[]string{"live/stripe", "--destroy", "--yes", "--scope", "tenant"}, "--confirm"},
		"confirm alone":     {[]string{"live/stripe", "--confirm", "live/stripe"}, "belongs to --destroy"},
		"confirm differs":   {[]string{"live/stripe", "--destroy", "--confirm", "x", "--scope", "tenant"}, "repeat the path exactly"},
		"no scope":          {[]string{"live/stripe", "--destroy", "--confirm", "live/stripe"}, "--destroy needs --scope"},
	} {
		if _, _, errOut := runV(t, v, "", "delete", tc.args...); !strings.Contains(errOut, tc.want) {
			t.Errorf("%s: error %q lacks %q", name, errOut, tc.want)
		}
	}
}

func TestDestroySendsTheExactBodyAndNeverAsks(t *testing.T) {
	v := newVaultAPI(t)
	// No stdin at all: --confirm is the confirmation, there is no prompt.
	code, out, errOut := runV(t, v, "", "delete", "live/stripe", "--destroy", "--confirm", "live/stripe", "--scope", "tenant")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	c := v.last()
	if c.Method != http.MethodPost || c.Path != "/v1/vault/secret/destroy" || c.Auth != "Bearer "+testToken {
		t.Fatalf("request %+v", c)
	}
	if want := map[string]any{"scope": "tenant", "path": "live/stripe", "confirm": "live/stripe"}; !reflect.DeepEqual(c.Body, want) {
		t.Errorf("body %v want %v", c.Body, want)
	}
	if v.count() != 1 {
		t.Errorf("%d requests, want 1 (no plain delete first)", v.count())
	}
	if !strings.Contains(out, "Permanently deleted live/stripe, every version.") {
		t.Errorf("output %q", out)
	}
	assertNoValue(t, "destroy", out, errOut)

	_, jsonOut, _ := runV(t, v, "", "delete", "live/stripe", "--destroy", "--confirm", "live/stripe", "--scope", "user", "--json")
	if m := mustJSON(t, "destroy", jsonOut); m["destroyed"] != true || m["scope"] != "user" {
		t.Errorf("json %v", m)
	}
	assertNoValue(t, "destroy --json", jsonOut)
}

func TestDestroyRefusedForAnAIClientAndForAWrongConfirmation(t *testing.T) {
	v := newVaultAPI(t)
	v.answer("POST /v1/vault/secret/destroy", 403, nil, `{"error":"destroy_not_for_ai_clients","message":"Permanent deletion is not available to AI clients."}`)
	code, out, errOut := runV(t, v, "", "delete", "a", "--destroy", "--confirm", "a", "--scope", "user")
	if code != ExitError || out != "" || !strings.Contains(errOut, "not available to AI clients") {
		t.Errorf("403: code=%d out=%q err=%q", code, out, errOut)
	}
	v.answer("POST /v1/vault/secret/destroy", 400, nil, `{"error":"confirm_required"}`)
	code, _, errOut = runV(t, v, "", "delete", "a", "--destroy", "--confirm", "a", "--scope", "user")
	if code != ExitError || !strings.Contains(errOut, "send its path as confirmation") {
		t.Errorf("400: code=%d err=%q", code, errOut)
	}
}

// ---- set: the settings flags --------------------------------------------------------

// setEnv runs `secrets set` against a fake Platform MCP (the save) and the fake API (the settings).
func setEnv(t *testing.T) (*fakeServer, *vaultAPI) {
	t.Helper()
	isolate(t)
	return newFakeServer(t), newVaultAPI(t)
}

func runSet(t *testing.T, srv *fakeServer, v *vaultAPI, stdin string, args ...string) (int, string, string) {
	t.Helper()
	full := append([]string{"--url", srv.URL, "--pat", testToken, "secrets", "set", "live/stripe", "--api-url", v.URL}, args...)
	return run(t, stdin, full...)
}

func TestSetAppliesTheSettingsAfterTheSave(t *testing.T) {
	srv, v := setEnv(t)
	code, out, errOut := runSet(t, srv, v, "", "-d", "api_key=sk_fake_1", "--create", "--scope", "tenant",
		"--description", "Payments key", "--label", "team=pay", "--label", "stripe", "--remove-label", "env",
		"--keep-versions", "default", "--expire-after", "7d")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	up := srv.last("vault_secrets_upsert")
	if up["mode"] != "create" || up["scope"] != "tenant" || up["path"] != "live/stripe" {
		t.Errorf("save request %v", up)
	}
	calls := v.all()
	if len(calls) != 2 {
		t.Fatalf("%d API calls, want 2 (read the labels, then the settings): %+v", len(calls), calls)
	}
	if calls[0].Method != http.MethodGet || calls[0].Path != "/v1/vault/secret/versions" || calls[0].Query != "path=live%2Fstripe&scope=tenant" {
		t.Errorf("first call %+v", calls[0])
	}
	// Existing labels env=prod and stripe=(tag): env is removed, team is added, stripe is set as a tag again.
	want := map[string]any{
		"scope": "tenant", "path": "live/stripe", "description": "Payments key",
		"labels":        map[string]any{"stripe": "", "team": "pay"},
		"keep_versions": nil, "expire_after_seconds": float64(604800),
	}
	if calls[1].Method != http.MethodPut || calls[1].Path != "/v1/vault/secret/settings" || !reflect.DeepEqual(calls[1].Body, want) {
		t.Errorf("settings call %+v\nwant body %v", calls[1], want)
	}
	for _, text := range []string{"Updated settings of live/stripe: description, labels, keep-versions, expire-after.", "one more version", "live/stripe"} {
		if !strings.Contains(out, text) {
			t.Errorf("output lacks %q:\n%s", text, out)
		}
	}
	assertNoValue(t, "set", out, errOut)
}

func TestSetSettingsKeepLabelsYouDoNotName(t *testing.T) {
	srv, v := setEnv(t)
	if code, _, errOut := runSet(t, srv, v, "", "-d", "k=v", "--label", "team=pay"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	body := v.last().Body
	if !reflect.DeepEqual(body["labels"], map[string]any{"env": "prod", "stripe": "", "team": "pay"}) {
		t.Errorf("labels %v: the existing env and stripe labels must be kept", body["labels"])
	}
	// no scope given: the workspace room, in both steps
	if up := srv.last("vault_secrets_upsert"); up["scope"] != "tenant" || body["scope"] != "tenant" {
		t.Errorf("rooms: save %v, settings %v", up["scope"], body["scope"])
	}
}

func TestSetDescriptionAloneDoesNotReadLabels(t *testing.T) {
	srv, v := setEnv(t)
	for _, args := range [][]string{
		{"-d", "k=v", "--description", "d"},
		{"-d", "k=v", "--description", ""}, // clears it
	} {
		before := v.count()
		if code, _, errOut := runSet(t, srv, v, "", args...); code != 0 {
			t.Fatalf("%v: %s", args, errOut)
		}
		calls := v.all()[before:]
		if len(calls) != 1 || calls[0].Method != http.MethodPut {
			t.Errorf("%v: calls %+v, want only the settings call", args, calls)
		}
		if _, hasLabels := calls[0].Body["labels"]; hasLabels {
			t.Errorf("%v: labels sent without being asked: %v", args, calls[0].Body)
		}
		if got, ok := calls[0].Body["description"]; !ok || got != args[len(args)-1] {
			t.Errorf("%v: description %v (present %v)", args, got, ok)
		}
	}
}

func TestSetKeepAndExpireValues(t *testing.T) {
	for _, tc := range []struct {
		flag, value string
		key         string
		want        any
	}{
		{"--keep-versions", "20", "keep_versions", float64(20)},
		{"--keep-versions", "1", "keep_versions", float64(1)},
		{"--keep-versions", "100", "keep_versions", float64(100)},
		{"--keep-versions", "default", "keep_versions", nil},
		{"--keep-versions", "Default", "keep_versions", nil},
		{"--expire-after", "1h", "expire_after_seconds", float64(3600)},
		{"--expire-after", "90m", "expire_after_seconds", float64(5400)},
		{"--expire-after", "36h", "expire_after_seconds", float64(129600)},
		{"--expire-after", "7d", "expire_after_seconds", float64(604800)},
		{"--expire-after", "90d", "expire_after_seconds", float64(7776000)},
		{"--expire-after", "365d", "expire_after_seconds", float64(31536000)},
		{"--expire-after", "2w", "expire_after_seconds", float64(1209600)},
		{"--expire-after", "3600s", "expire_after_seconds", float64(3600)},
		{"--expire-after", "never", "expire_after_seconds", nil},
		{"--expire-after", "NEVER", "expire_after_seconds", nil},
	} {
		srv, v := setEnv(t)
		if code, _, errOut := runSet(t, srv, v, "", "-d", "k=v", "--scope", "user", tc.flag, tc.value); code != 0 {
			t.Fatalf("%s %s: exit %d: %s", tc.flag, tc.value, code, errOut)
		}
		body := v.last().Body
		if got, present := body[tc.key]; !present || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %s: %s = %v (present %v), want %v", tc.flag, tc.value, tc.key, got, present, tc.want)
		}
		if len(body) != 3 { // scope, path and the one setting
			t.Errorf("%s %s: body %v has more than the one setting", tc.flag, tc.value, body)
		}
	}
}

// With settings flags and no data, nothing is saved: only the settings change.
func TestSetSettingsOnlySavesNothing(t *testing.T) {
	srv, v := setEnv(t)
	code, out, errOut := runSet(t, srv, v, "", "--scope", "tenant", "--keep-versions", "5")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if srv.last("vault_secrets_upsert") != nil {
		t.Error("the secret was saved although no data was given")
	}
	if c := v.last(); c.Method != http.MethodPut || c.Body["keep_versions"] != float64(5) {
		t.Errorf("settings call %+v", c)
	}
	if !strings.Contains(out, "Updated settings of live/stripe: keep-versions.") {
		t.Errorf("output %q", out)
	}
	assertNoValue(t, "set settings only", out, errOut)
}

func TestSetWithoutSettingsFlagsIsUnchanged(t *testing.T) {
	srv, v := setEnv(t)
	code, _, errOut := runSet(t, srv, v, "", "-d", "k=v", "--create")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if v.count() != 0 {
		t.Errorf("the API was called without settings flags: %+v", v.all())
	}
	if up := srv.last("vault_secrets_upsert"); up["scope"] != nil {
		t.Errorf("a left-out scope must stay left out when there are no settings: %v", up)
	}
}

func TestSetSettingsFlagsAreCheckedBeforeAnythingIsSaved(t *testing.T) {
	srv, v := setEnv(t)
	base := []string{"-d", "k=v"}
	long := strings.Repeat("x", 501)
	for name, args := range map[string][]string{
		"label key upper-case":    {"--label", "Env=prod"},
		"label key empty":         {"--label", "=prod"},
		"label key with a space":  {"--label", "a b=c"},
		"label key too long":      {"--label", strings.Repeat("a", 41) + "=x"},
		"label value too long":    {"--label", "a=" + strings.Repeat("v", 101)},
		"label value has control": {"--label", "a=b\x07c"},
		"label twice":             {"--label", "a=1", "--label", "a=2"},
		"set and removed":         {"--label", "a=1", "--remove-label", "a"},
		"remove-label invalid":    {"--remove-label", "A_B"},
		"eleven labels":           {"--label", "a=1", "--label", "b=1", "--label", "c=1", "--label", "d=1", "--label", "e=1", "--label", "f=1", "--label", "g=1", "--label", "h=1", "--label", "i=1", "--label", "j=1", "--label", "k=1"},
		"keep zero":               {"--keep-versions", "0"},
		"keep 101":                {"--keep-versions", "101"},
		"keep negative":           {"--keep-versions", "-1"},
		"keep word":               {"--keep-versions", "many"},
		"keep empty":              {"--keep-versions", ""},
		"expire 59m":              {"--expire-after", "59m"},
		"expire 366d":             {"--expire-after", "366d"},
		"expire no unit":          {"--expire-after", "7"},
		"expire bad unit":         {"--expire-after", "7y"},
		"expire fraction":         {"--expire-after", "1.5d"},
		"expire negative":         {"--expire-after", "-1d"},
		"expire zero":             {"--expire-after", "0h"},
		"expire empty":            {"--expire-after", ""},
		"expire compound":         {"--expire-after", "1d12h"},
		"description too long":    {"--description", long},
		"description control":     {"--description", "a\nb"},
		"shared room":             {"--description", "d", "--scope", "shared"},
		"unknown room":            {"--description", "d", "--scope", "workspace"},
	} {
		code, out, errOut := runSet(t, srv, v, "", append(append([]string{}, base...), args...)...)
		if code != ExitUsage || out != "" || errOut == "" {
			t.Errorf("%s: code=%d out=%q err=%q, want a usage error", name, code, out, errOut)
		}
	}
	if srv.last("vault_secrets_upsert") != nil {
		t.Error("a settings flag that was refused still let the secret be saved")
	}
	if v.count() != 0 {
		t.Errorf("a refused flag reached the API: %+v", v.all())
	}
	// Settings flags with --create or --update and no data: nothing to save, and nothing is sent.
	for _, flag := range []string{"--create", "--update"} {
		if code, _, _ := runSet(t, srv, v, "", flag, "--description", "d"); code != ExitUsage {
			t.Errorf("%s with no data: code=%d, want 2", flag, code)
		}
	}
	if srv.last("vault_secrets_upsert") != nil || v.count() != 0 {
		t.Error("--create/--update without data sent something")
	}
}

// The save worked and the settings step failed: the command says both, exits 1, and JSON stays one valid object.
func TestSetSaveWorkedSettingsFailed(t *testing.T) {
	srv, v := setEnv(t)
	v.answer("PUT /v1/vault/secret/settings", 403, nil, `{"error":"forbidden","message":"Only the owner or a room manager can change this."}`)
	code, out, errOut := runSet(t, srv, v, "", "-d", "k=v", "--description", "d")
	if code != ExitError || !strings.Contains(errOut, "the secret was saved, but its settings were not changed") || !strings.Contains(errOut, "Only the owner or a room manager can change this.") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if !strings.Contains(out, "live/stripe") { // the save result was printed
		t.Errorf("stdout %q should show the saved secret", out)
	}
	code, out, errOut = runSet(t, srv, v, "", "-d", "k=v", "--description", "d", "--json")
	m := mustJSON(t, "set failed json", out)
	if code != ExitError || m["settings"] != nil || m["saved"] == nil || !strings.Contains(errOut, "was saved") {
		t.Errorf("json: code=%d m=%v err=%q", code, m, errOut)
	}
	// settings only: no "saved" claim
	code, _, errOut = runSet(t, srv, v, "", "--description", "d")
	if code != ExitError || strings.Contains(errOut, "was saved") || !strings.Contains(errOut, "the settings were not changed") {
		t.Errorf("settings only: code=%d err=%q", code, errOut)
	}
}

func TestSetCannotReadLabelsSoNoLabelChanges(t *testing.T) {
	srv, v := setEnv(t)
	v.answer("GET /v1/vault/secret/versions", 404, nil, `{"error":"not_found"}`)
	code, _, errOut := runSet(t, srv, v, "", "-d", "k=v", "--label", "a=b")
	if code != ExitError || !strings.Contains(errOut, "could not read the current labels, so no label was changed") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	for _, c := range v.all() {
		if c.Method == http.MethodPut {
			t.Errorf("settings were sent although the labels could not be read: %+v", c)
		}
	}
}

func TestSetMoreThanTenLabelsAfterTheMergeIsRefusedBeforeTheCall(t *testing.T) {
	srv, v := setEnv(t)
	labels := map[string]string{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		labels[k] = "1"
	}
	raw, _ := json.Marshal(labels)
	v.answer("GET /v1/vault/secret/versions", 200, nil, `{"current_version":1,"labels":`+string(raw)+`,"versions":[]}`)
	code, _, errOut := runSet(t, srv, v, "", "--label", "k=1")
	if code != ExitError || !strings.Contains(errOut, "at most 10 labels") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	for _, c := range v.all() {
		if c.Method == http.MethodPut {
			t.Errorf("settings were sent: %+v", c)
		}
	}
}

func TestSetJSONIsOneValidObject(t *testing.T) {
	srv, v := setEnv(t)
	code, out, errOut := runSet(t, srv, v, "", "-d", "k=v", "--keep-versions", "5", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	m := mustJSON(t, "set json", out)
	if m["saved"] == nil || m["settings"] == nil {
		t.Errorf("json %v", m)
	}
	assertNoValue(t, "set --json", out, errOut)
	for _, bad := range []string{`"value"`, `"values"`} {
		if strings.Contains(out, bad) {
			t.Errorf("--json output carries %s: %s", bad, out)
		}
	}
	// settings only
	_, out, _ = runSet(t, srv, v, "", "--keep-versions", "5", "--json")
	if m := mustJSON(t, "set json settings only", out); m["saved"] != nil || m["settings"] == nil {
		t.Errorf("settings only json %v", m)
	}
}

// ---- help, parsing ------------------------------------------------------------------

func TestHelpNamesTheNewCommandsAndFlags(t *testing.T) {
	isolate(t)
	_, out, _ := run(t, "", "secrets", "--help")
	for _, want := range []string{"history", "restore", "deleted", "undelete", "delete", "Recently deleted"} {
		if !strings.Contains(out, want) {
			t.Errorf("secrets --help lacks %q", want)
		}
	}
	for sub, wants := range map[string][]string{
		"set":     {"--description", "--label", "--remove-label", "--keep-versions", "--expire-after", "Recently deleted", "never"},
		"delete":  {"--destroy", "--confirm", "Recently deleted", "permanent"},
		"history": {"never shows a", "NAMES"},
		"restore": {"--version", "NEW current version"},
		"deleted": {"--scope", "expired"},
	} {
		_, out, _ := run(t, "", "secrets", sub, "--help")
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("secrets %s --help lacks %q:\n%s", sub, want, out)
			}
		}
	}
}

func TestParseExpireAfterAndKeepVersions(t *testing.T) {
	for in, want := range map[string]int{"1h": 3600, " 7D ": 604800, "60m": 3600, "3600s": 3600, "1w": 604800, "365d": 31536000, "8760h": 31536000} {
		got, err := parseExpireAfter(in)
		if err != nil || !got.Set || got.Null || got.Value != want {
			t.Errorf("parseExpireAfter(%q) = %+v, %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "h", "7", "d7", "7y", "1.5d", "-1d", "0d", "59m", "3599s", "366d", "8761h", "1d1h", "99999999999999999999d", "forever"} {
		if got, err := parseExpireAfter(in); err == nil {
			t.Errorf("parseExpireAfter(%q) accepted: %+v", in, got)
		}
	}
	if got, err := parseExpireAfter("Never"); err != nil || !got.Null || !got.Set {
		t.Errorf("never: %+v %v", got, err)
	}
	for in, want := range map[string]int{"1": 1, "5": 5, " 100 ": 100} {
		if got, err := parseKeepVersions(in); err != nil || got.Value != want || got.Null {
			t.Errorf("parseKeepVersions(%q) = %+v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0", "101", "-1", "1.5", "x", "5 6"} {
		if _, err := parseKeepVersions(in); err == nil {
			t.Errorf("parseKeepVersions(%q) accepted", in)
		}
	}
	if got, err := parseKeepVersions("DEFAULT"); err != nil || !got.Null {
		t.Errorf("default: %+v %v", got, err)
	}
}

func TestParseLabelHumanDurationScopeAndSafeLine(t *testing.T) {
	for in, want := range map[string][2]string{"env=prod": {"env", "prod"}, "stripe": {"stripe", ""}, "a.b_c-d=x=y": {"a.b_c-d", "x=y"}, "k=": {"k", ""}, " k =v": {"k", "v"}} {
		k, v, err := parseLabel(in)
		if err != nil || k != want[0] || v != want[1] {
			t.Errorf("parseLabel(%q) = %q, %q, %v", in, k, v, err)
		}
	}
	for _, in := range []string{"", "=x", "Env=x", "-a=x", ".a=x", "a b=x", "é=x", strings.Repeat("a", 41), "a=\x00"} {
		if _, _, err := parseLabel(in); err == nil {
			t.Errorf("parseLabel(%q) accepted", in)
		}
	}
	for in, want := range map[int]string{3600: "1h", 5400: "90m", 86400: "1d", 604800: "7d", 90: "90s", 129600: "36h", 31536000: "365d"} {
		if got := humanDuration(in); got != want {
			t.Errorf("humanDuration(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"": "tenant", " User ": "user", "PROJECT": "project", "tenant": "tenant"} {
		if got, err := vaultScope(in); err != nil || got != want {
			t.Errorf("vaultScope(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"shared", "workspace", "my", "x"} {
		if _, err := vaultScope(in); err == nil {
			t.Errorf("vaultScope(%q) accepted", in)
		}
	}
	for in, want := range map[string]string{
		"plain":            "plain",
		"a\tb\n c":         "a b c",
		"esc\x1b[31m":      `esc\x1b[31m`,
		"bidi\u202eevil":   `bidi\u202eevil`,
		"zero\u200bwidth":  `zero\u200bwidth`,
		"bell\x07":         `bell\x07`,
		"c1\u009bcsi":      `c1\x9bcsi`,
		"  spaced   out  ": "spaced out",
		"ünï":              "ünï",
	} {
		if got := safeLine(in); got != want {
			t.Errorf("safeLine(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"live/stripe": "live/stripe", "a b": "'a b'", "it's": `'it'\''s'`, "$x": "'$x'", "": "''", "a\x1bb": `'a\x1bb'`} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
