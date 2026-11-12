package config

import (
	"os"
	"path/filepath"
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"AGENTRUNTIME_PAT", "AGENTRUNTIME_MCP_URL", "PLATFORM_MCP_URL", "AGENTRUNTIME_PROFILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("AGENTRUNTIME_CONFIG", filepath.Join(t.TempDir(), "agentruntime", "config.json"))
}

func TestResolvePrecedence(t *testing.T) {
	clearEnv(t)
	f := &File{Current: "dev", Profiles: map[string]*Profile{
		"dev":  {URL: "http://dev/mcp", Token: "pat_dev"},
		"prod": {URL: "http://prod/mcp", Token: "pat_prod"},
	}}

	r := f.Resolve(Overrides{})
	if r.Profile != "dev" || r.URL != "http://dev/mcp" || r.Token != "pat_dev" {
		t.Fatalf("profile defaults: %+v", r)
	}

	t.Setenv("AGENTRUNTIME_PROFILE", "prod")
	if r := f.Resolve(Overrides{}); r.Token != "pat_prod" {
		t.Fatalf("env profile: %+v", r)
	}

	t.Setenv("AGENTRUNTIME_PAT", "pat_env")
	t.Setenv("PLATFORM_MCP_URL", "http://legacy/mcp")
	r = f.Resolve(Overrides{})
	if r.Token != "pat_env" || r.URL != "http://legacy/mcp" {
		t.Fatalf("env beats profile: %+v", r)
	}

	t.Setenv("AGENTRUNTIME_MCP_URL", "http://new/mcp")
	if r := f.Resolve(Overrides{}); r.URL != "http://new/mcp" {
		t.Fatalf("AGENTRUNTIME_MCP_URL beats PLATFORM_MCP_URL: %+v", r)
	}

	r = f.Resolve(Overrides{Profile: "dev", URL: "http://flag/mcp", Token: "pat_flag"})
	if r.Profile != "dev" || r.URL != "http://flag/mcp" || r.Token != "pat_flag" {
		t.Fatalf("flags beat env: %+v", r)
	}
}

func TestResolveDefaults(t *testing.T) {
	clearEnv(t)
	r := (&File{}).Resolve(Overrides{})
	if r.URL != DefaultURL || r.Profile != DefaultProfile || r.Token != "" || r.URLSource != "default" {
		t.Fatalf("%+v", r)
	}
}

func TestSaveLoadRoundTripAndPermissions(t *testing.T) {
	clearEnv(t)
	f := &File{Current: "a", Profiles: map[string]*Profile{"a": {URL: "u", Token: "t"}}}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	p, _ := Path()
	if info, err := os.Stat(p); err != nil {
		t.Fatal(err)
	} else if perm := info.Mode().Perm(); perm&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("config must be owner-only, got %v", perm)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Current != "a" || got.Profiles["a"].Token != "t" {
		t.Fatalf("%+v", got)
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Error("temp file left behind")
	}
}

func TestLoadMissingAndCorrupt(t *testing.T) {
	clearEnv(t)
	f, err := Load()
	if err != nil || len(f.Profiles) != 0 {
		t.Fatalf("missing file should be empty: %v %v", f, err)
	}
	p, _ := Path()
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte("{not json"), 0o600)
	if _, err := Load(); err == nil {
		t.Fatal("corrupt config should error")
	}
}

func TestMaskToken(t *testing.T) {
	if got := MaskToken("pat_abcdefghijklmnop"); got != "pat_ab…mnop" {
		t.Errorf("got %q", got)
	}
	if got := MaskToken("short"); got != "*****" {
		t.Errorf("got %q", got)
	}
	if MaskToken("") != "" {
		t.Error("empty")
	}
}
