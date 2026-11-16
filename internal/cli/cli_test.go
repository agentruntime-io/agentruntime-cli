package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const testToken = "pat_test_token_1234567890"

// fakeServer is an in-process Platform MCP server that records tool calls.
type fakeServer struct {
	*httptest.Server
	mu    sync.Mutex
	calls map[string]map[string]any
}

func (f *fakeServer) last(tool string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[tool]
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{calls: map[string]map[string]any{}}
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake-platform", Version: "test"}, nil)

	add := func(name, desc string, schema map[string]any, respond func(args map[string]any) (any, bool)) {
		srv.AddTool(&mcp.Tool{Name: name, Description: desc, InputSchema: schema},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args := map[string]any{}
				if len(req.Params.Arguments) > 0 {
					_ = json.Unmarshal(req.Params.Arguments, &args)
				}
				f.mu.Lock()
				f.calls[name] = args
				f.mu.Unlock()
				out, isErr := respond(args)
				b, _ := json.Marshal(out)
				res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}, IsError: isErr}
				if !isErr {
					res.StructuredContent = out
				}
				return res, nil
			})
	}
	obj := func(props map[string]any, required ...string) map[string]any {
		s := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			s["required"] = required
		}
		return s
	}

	add("ar_get_started", "Call first.", obj(map[string]any{"project_id": map[string]any{"type": "string"}}),
		func(map[string]any) (any, bool) {
			return map[string]any{
				"authenticated":   true,
				"tenant":          map[string]any{"id": "t-1", "code": "acme", "name": "Acme Corp"},
				"user":            map[string]any{"email": "jo@acme.test"},
				"default_project": map[string]any{"id": "p-1", "name": "Main"},
				"projects":        []any{map[string]any{"id": "p-1", "name": "Main", "is_default": true}},
				"platform_mcp":    map[string]any{"publishable_tool_count": 9},
			}, false
		})
	add("workflows_list", "GET /v1/workflows.", obj(map[string]any{"limit": map[string]any{"type": "integer", "description": "page size"}}),
		func(map[string]any) (any, bool) {
			return map[string]any{
				"items": []any{
					map[string]any{"id": "wf-1", "name": "Weekly digest", "status": "active"},
					map[string]any{"id": "wf-2", "name": "Onboarding", "status": "draft"},
				},
				"next_cursor": "abc",
			}, false
		})
	add("workflow_run", "Start a run.", obj(map[string]any{"workflow_id": map[string]any{"type": "string"}}),
		func(args map[string]any) (any, bool) {
			if args["wait"] == true {
				return map[string]any{
					"outcome": "awaiting_input", "workflow_id": "wf-1", "run_id": "run-1",
					"blocked_on": []any{map[string]any{
						"type": "human_task", "task_id": "task-1", "step_id": "s2", "step_name": "Approve send",
						"summary": "Send to jo@acme.test", "task_payload": map[string]any{"subject": "Hello"},
					}},
				}, false
			}
			return map[string]any{"outcome": "running", "workflow_id": "wf-1", "run_id": "run-1"}, false
		})
	add("workflow_inspect", "Inspect.", obj(map[string]any{}), func(args map[string]any) (any, bool) {
		return map[string]any{
			"outcome": "awaiting_input", "workflow_id": "wf-1", "run_id": "run-1",
			"blocked_on": []any{map[string]any{
				"type": "human_task", "task_id": "task-1", "step_id": "s2", "step_name": "Approve send",
				"summary": "Send to jo@acme.test",
			}},
		}, false
	})
	add("workflow_approve", "Approve.", obj(map[string]any{}), func(args map[string]any) (any, bool) {
		outcome := "completed"
		if args["approved"] == false {
			outcome = "stopped"
		}
		return map[string]any{"outcome": outcome, "workflow_id": "wf-1", "run_id": "run-1",
			"outputs": map[string]any{"send": map[string]any{"status": "queued"}}}, false
	})
	add("workflow_await", "Await.", obj(map[string]any{}), func(map[string]any) (any, bool) {
		return map[string]any{"outcome": "failed", "workflow_id": "wf-1", "run_id": "run-1",
			"error": map[string]any{"message": "boom", "failure_code": "E_STEP", "failed_step_id": "s1"}}, false
	})
	add("vault_secrets_delete", "Delete.", obj(map[string]any{}), func(map[string]any) (any, bool) {
		return map[string]any{"error": "risk group disabled"}, true
	})
	add("vault_secrets_list", "List.", obj(map[string]any{}), func(map[string]any) (any, bool) {
		return map[string]any{"items": []any{map[string]any{"path": "live/stripe", "scope": "tenant", "keys": []any{"API_KEY"}}}}, false
	})
	add("vault_secrets_upsert", "Upsert.", obj(map[string]any{}), func(args map[string]any) (any, bool) {
		return map[string]any{"path": args["path"], "version": 2}, false
	})
	add("pats_create", "Create.", obj(map[string]any{}), func(map[string]any) (any, bool) {
		return map[string]any{"id": "pat-9", "token": "pat_new"}, false
	})

	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mcpHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

// run executes the CLI in isolation and returns exit code, stdout and stderr.
func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	app := NewApp(strings.NewReader(stdin), &out, &errb)
	code := app.Run(append([]string{"--no-color"}, args...))
	return code, out.String(), errb.String()
}

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("AGENTRUNTIME_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	for _, k := range []string{"AGENTRUNTIME_PAT", "AGENTRUNTIME_MCP_URL", "PLATFORM_MCP_URL", "AGENTRUNTIME_PROFILE", "NO_COLOR"} {
		t.Setenv(k, "")
	}
}

func TestLoginSavesProfileThenWhoamiUsesIt(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)

	code, out, errOut := run(t, "", "login", "--token", testToken, "--url", srv.URL)
	if code != 0 {
		t.Fatalf("login exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if !strings.Contains(out, "Acme Corp") {
		t.Errorf("login output missing workspace name: %q", out)
	}

	cfg, err := os.ReadFile(os.Getenv("AGENTRUNTIME_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), testToken) {
		t.Errorf("token not persisted: %s", cfg)
	}

	// No flags this time: URL and token must come from the saved profile.
	code, out, errOut = run(t, "", "whoami")
	if code != 0 {
		t.Fatalf("whoami exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	for _, want := range []string{"Acme Corp", "jo@acme.test", "Main"} {
		if !strings.Contains(out, want) {
			t.Errorf("whoami output missing %q:\n%s", want, out)
		}
	}
}

func TestLoginRejectsBadToken(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, _, errOut := run(t, "", "login", "--token", "pat_wrong", "--url", srv.URL)
	if code == 0 {
		t.Fatal("login with a bad token should fail")
	}
	if !strings.Contains(errOut, "401") {
		t.Errorf("expected a 401 hint, got %q", errOut)
	}
	if _, err := os.Stat(os.Getenv("AGENTRUNTIME_CONFIG")); err == nil {
		t.Error("config must not be written when verification fails")
	}
}

func TestNotLoggedInGivesHelpfulError(t *testing.T) {
	isolate(t)
	code, _, errOut := run(t, "", "whoami", "--url", "https://mcp.example.invalid/mcp")
	if code != 1 || !strings.Contains(errOut, "agentruntime login") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

func TestEnvTokenWorksWithoutLogin(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	t.Setenv("AGENTRUNTIME_PAT", testToken)
	t.Setenv("AGENTRUNTIME_MCP_URL", srv.URL)
	if code, out, errOut := run(t, "", "workflows", "list"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestWorkflowsListRendersTableAndJSON(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}

	code, out, errOut := run(t, "", append(base, "workflows", "list", "--limit", "2")...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"ID", "NAME", "wf-1", "Weekly digest", "next_cursor"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	if got := srv.last("workflows_list")["limit"]; got != float64(2) {
		t.Errorf("limit forwarded as %v (%T)", got, got)
	}

	code, out, _ = run(t, "", append(base, "--json", "workflows", "list")...)
	if code != 0 {
		t.Fatal("json exit", code)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", err, out)
	}
}

func TestToolsListDescribeAndCall(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}

	_, out, _ := run(t, "", append(base, "tools", "list", "workflow")...)
	if !strings.Contains(out, "workflow_run") || strings.Contains(out, "vault_secrets_delete") {
		t.Errorf("filter not applied:\n%s", out)
	}

	_, out, _ = run(t, "", append(base, "tools", "describe", "workflows_list")...)
	if !strings.Contains(out, "limit") || !strings.Contains(out, "integer") {
		t.Errorf("describe missing params:\n%s", out)
	}

	code, _, errOut := run(t, "", append(base, "tools", "describe", "workflow_rn")...)
	if code == 0 || !strings.Contains(errOut, "no tool named") {
		t.Errorf("unknown tool should fail: code=%d err=%q", code, errOut)
	}

	code, _, _ = run(t, "", append(base, "call", "workflows_list",
		"--args", `{"limit":1}`, "--arg", "include_templates=true", "-a", `tools=["a","b"]`)...)
	if code != 0 {
		t.Fatal("call failed")
	}
	got := srv.last("workflows_list")
	if got["limit"] != float64(1) || got["include_templates"] != true {
		t.Errorf("args not merged/typed: %v", got)
	}
	if arr, ok := got["tools"].([]any); !ok || len(arr) != 2 {
		t.Errorf("JSON array arg lost: %v", got["tools"])
	}
}

func TestToolErrorsSurfaceMessage(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	// (`secrets delete` calls the API directly now, see secrets_versions_test.go; the generic call still goes through Platform MCP.)
	code, _, errOut := run(t, "", "--url", srv.URL, "--pat", testToken, "call", "vault_secrets_delete", "--arg", "path=a/b")
	if code != 1 || !strings.Contains(errOut, "risk group disabled") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

func TestRunWaitAwaitingInputExitCode3(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}

	code, out, _ := run(t, "", append(base, "run", "wf-1", "--wait", "-i", "recipient=jo@acme.test", "-i", "count=3")...)
	if code != ExitAwaiting {
		t.Errorf("exit code = %d, want %d", code, ExitAwaiting)
	}
	for _, want := range []string{"awaiting_input", "Approval required", "task-1", "agentruntime approve wf-1 run-1 task-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("outcome missing %q:\n%s", want, out)
		}
	}
	args := srv.last("workflow_run")
	params, _ := args["params"].(map[string]any)
	payload, _ := params["trigger_payload"].(map[string]any)
	if payload["recipient"] != "jo@acme.test" || payload["count"] != float64(3) {
		t.Errorf("trigger_payload wrong: %v", args)
	}
	if args["wait"] != true || args["workflow_id"] != "wf-1" {
		t.Errorf("run args wrong: %v", args)
	}
}

func TestRunWithoutWaitReturnsRunningExit0(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, out, _ := run(t, "", "--url", srv.URL, "--pat", testToken, "run", "wf-1")
	if code != 0 || !strings.Contains(out, "agentruntime await wf-1 run-1") {
		t.Errorf("code=%d out=%s", code, out)
	}
}

func TestRunUsageErrors(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}
	if code, _, _ := run(t, "", append(base, "run")...); code != ExitUsage {
		t.Errorf("no workflow: code %d", code)
	}
	if code, _, _ := run(t, "", append(base, "run", "wf-1", "--graph-file", "g.json")...); code != ExitUsage {
		t.Errorf("both id and graph: code %d", code)
	}
}

func TestAwaitFailedExitsNonZero(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, out, _ := run(t, "", "--url", srv.URL, "--pat", testToken, "await", "wf-1", "run-1")
	if code != 1 || !strings.Contains(out, "boom") || !strings.Contains(out, "E_STEP") {
		t.Errorf("code=%d out=%s", code, out)
	}
}

func TestApproveShowsGateAndRequiresConfirmation(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	base := []string{"--url", srv.URL, "--pat", testToken}

	// Answer "y": gate is displayed, then approval is sent with edits.
	code, out, errOut := run(t, "y\n", append(base, "approve", "wf-1", "run-1", "task-1",
		"--edit", "s1.recipient=new@acme.test", "--comment", "looks good")...)
	if code != 0 {
		t.Fatalf("approve exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "Send to jo@acme.test") {
		t.Errorf("gate summary not shown before confirmation:\n%s", out)
	}
	if !strings.Contains(out, "completed") {
		t.Errorf("final outcome missing:\n%s", out)
	}
	got := srv.last("workflow_approve")
	edits, _ := got["context_edits"].(map[string]any)
	if got["approved"] != true || got["comment"] != "looks good" || edits["s1.recipient"] != "new@acme.test" || got["wait"] != true {
		t.Errorf("approve args wrong: %v", got)
	}
}

func TestApproveAbortedOnNoDoesNotCallServer(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, _, errOut := run(t, "n\n", "--url", srv.URL, "--pat", testToken, "approve", "wf-1", "run-1", "task-1")
	if code == 0 || !strings.Contains(errOut, "Aborted") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	if srv.last("workflow_approve") != nil {
		t.Error("workflow_approve must not be called after declining")
	}
}

func TestRejectYesSkipsPromptAndSendsApprovedFalse(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, out, _ := run(t, "", "--url", srv.URL, "--pat", testToken, "reject", "wf-1", "run-1", "task-1", "--yes", "--comment", "no")
	if code != 1 { // stopped => non-zero
		t.Errorf("reject exit = %d, want 1 (run stopped)", code)
	}
	if !strings.Contains(out, "stopped") {
		t.Errorf("out=%s", out)
	}
	if got := srv.last("workflow_approve"); got["approved"] != false {
		t.Errorf("approved should be false: %v", got)
	}
}

func TestRejectCannotTakeEdits(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, _, _ := run(t, "", "--url", srv.URL, "--pat", testToken, "reject", "wf-1", "run-1", "task-1", "--edit", "a.b=c")
	if code == 0 {
		t.Error("--edit on reject must be rejected by flag parsing")
	}
}

func TestInspectDoesNotMapExitCode(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, out, _ := run(t, "", "--url", srv.URL, "--pat", testToken, "inspect", "wf-1", "run-1", "--full", "--step", "s1")
	if code != 0 {
		t.Errorf("inspect is read-only and must exit 0, got %d", code)
	}
	if !strings.Contains(out, "Approval required") {
		t.Errorf("out=%s", out)
	}
	if got := srv.last("workflow_inspect"); got["full"] != true {
		t.Errorf("full not forwarded: %v", got)
	}
}

func TestPATCreateWarnsAndParsesExpiry(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	code, out, errOut := run(t, "", "--url", srv.URL, "--pat", testToken, "pats", "create", "ci", "--expires-in", "30d")
	if code != 0 || !strings.Contains(out, "pat_new") || !strings.Contains(errOut, "Copy the token") {
		t.Errorf("code=%d out=%s err=%s", code, out, errOut)
	}
	if got := srv.last("pats_create")["expires_in_seconds"]; got != float64(30*24*3600) {
		t.Errorf("expires_in_seconds = %v", got)
	}
}

func TestProfilesListUseRemove(t *testing.T) {
	isolate(t)
	srv := newFakeServer(t)
	run(t, "", "login", "--token", testToken, "--url", srv.URL, "--profile", "dev")
	run(t, "", "login", "--token", testToken, "--url", srv.URL, "--profile", "prod")

	_, out, _ := run(t, "", "profile", "list")
	if !strings.Contains(out, "dev") || !strings.Contains(out, "prod") {
		t.Fatalf("list:\n%s", out)
	}
	if strings.Contains(out, testToken) {
		t.Error("profile list must mask tokens")
	}
	if code, _, _ := run(t, "", "profile", "use", "dev"); code != 0 {
		t.Fatal("use failed")
	}
	if code, _, _ := run(t, "", "profile", "use", "nope"); code == 0 {
		t.Fatal("use of unknown profile should fail")
	}
	if code, _, _ := run(t, "", "profile", "rm", "prod"); code != 0 {
		t.Fatal("rm failed")
	}
}

func TestParseKVInference(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "body.txt")
	_ = os.WriteFile(file, []byte("hello\r\n"), 0o600)

	got, err := parseKV([]string{
		"n=5", "f=1.5", "b=true", "s=hello", "id=007", `j={"a":1}`, `arr=[1,2]`,
		"empty=", "neg=-3", "eq=a=b", "file=@" + file, "quoted=\"5\"",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"n": int64(5), "f": 1.5, "b": true, "s": "hello", "id": "007",
		"empty": "", "neg": int64(-3), "eq": "a=b", "file": "hello", "quoted": "5",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %#v (%T), want %#v", k, got[k], got[k], w)
		}
	}
	// Nested numbers stay json.Number; what matters is the wire form (unquoted numbers).
	wire, _ := json.Marshal(map[string]any{"j": got["j"], "arr": got["arr"]})
	if string(wire) != `{"arr":[1,2],"j":{"a":1}}` {
		t.Errorf("object/array not sent as JSON numbers: %s", wire)
	}
	if _, err := parseKV([]string{"novalue"}); err == nil {
		t.Error("missing '=' should error")
	}
	if _, err := parseKV([]string{"=x"}); err == nil {
		t.Error("empty key should error")
	}
}

func TestReadJSONFileStripsBOM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.json")
	_ = os.WriteFile(p, append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"x":1}`)...), 0o600)
	m, err := readJSONObject(p, strings.NewReader(""))
	if err != nil || m["x"] != float64(1) {
		t.Fatalf("m=%v err=%v", m, err)
	}
	m, err = readJSONObject("-", strings.NewReader(`{"y":2}`))
	if err != nil || m["y"] != float64(2) {
		t.Fatalf("stdin: m=%v err=%v", m, err)
	}
	if _, err := readJSONObject("-", strings.NewReader(`[1]`)); err == nil {
		t.Error("array should be rejected as object")
	}
}

func TestParseExpiry(t *testing.T) {
	for in, want := range map[string]int64{"": 0, "30d": 30 * 86400, "12h": 12 * 3600, "1.5d": 129600} {
		got, err := parseExpiry(in)
		if err != nil || got != want {
			t.Errorf("%q => %d, %v (want %d)", in, got, err, want)
		}
	}
	for _, bad := range []string{"abc", "-1d", "0h"} {
		if _, err := parseExpiry(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestFindGraphNested(t *testing.T) {
	g := map[string]any{"steps": []any{}}
	if findGraph(map[string]any{"graph": g}) == nil {
		t.Error("top-level graph")
	}
	if findGraph(map[string]any{"workflow": map[string]any{"graph": g}}) == nil {
		t.Error("nested graph")
	}
	if findGraph(map[string]any{"nothing": 1}) != nil {
		t.Error("should be nil")
	}
}
