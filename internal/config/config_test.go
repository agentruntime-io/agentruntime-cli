package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

// A short-lived key saved in a profile carries its expiry; the expiry belongs to that key only, so it is reported
// only while the key in use is the profile's own.
func TestResolveReportsTheStoredExpiryOnlyForTheProfilesKey(t *testing.T) {
	clearEnv(t)
	f := &File{Current: "dev", Profiles: map[string]*Profile{
		"dev":     {URL: "http://dev/mcp", Token: "pat_dev", ExpiresAt: "2026-11-16T10:00:00Z"},
		"forever": {URL: "http://dev/mcp", Token: "pat_forever"},
		"broken":  {URL: "http://dev/mcp", Token: "pat_broken", ExpiresAt: "not a time"},
	}}
	want := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	if r := f.Resolve(Overrides{}); !r.TokenExpiresAt.Equal(want) {
		t.Fatalf("profile key: expiry %v, want %v", r.TokenExpiresAt, want)
	}
	if r := f.Resolve(Overrides{Profile: "forever"}); !r.TokenExpiresAt.IsZero() {
		t.Fatalf("a key with no stored expiry reported %v", r.TokenExpiresAt)
	}
	if r := f.Resolve(Overrides{Profile: "broken"}); !r.TokenExpiresAt.IsZero() {
		t.Fatalf("an unreadable stored expiry must be ignored, got %v", r.TokenExpiresAt)
	}
	// A key from a flag or from the environment is not the key the profile's expiry was stored for.
	if r := f.Resolve(Overrides{Token: "pat_flag"}); r.Token != "pat_flag" || !r.TokenExpiresAt.IsZero() {
		t.Fatalf("flag key: %+v", r)
	}
	t.Setenv("AGENTRUNTIME_PAT", "pat_env")
	if r := f.Resolve(Overrides{}); r.Token != "pat_env" || !r.TokenExpiresAt.IsZero() {
		t.Fatalf("env key: %+v", r)
	}
}

func TestExpiryIsSavedAndLoadedWithTheProfile(t *testing.T) {
	clearEnv(t)
	f := &File{Current: "dev", Profiles: map[string]*Profile{"dev": {Token: "pat_dev", ExpiresAt: "2026-11-16T10:00:00Z"}}}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got.Profiles["dev"].ExpiresAt != "2026-11-16T10:00:00Z" {
		t.Fatalf("round trip: %+v err=%v", got, err)
	}
}

// A temp file left behind by a crash may have been created with wider permissions. Saving must not write the key
// into it and keep those permissions: the new file is owner-only whatever was there before.
func TestSaveIsOwnerOnlyEvenWhenAStaleTempFileExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no owner-only mode bits")
	}
	clearEnv(t)
	p, _ := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := p + ".tmp"
	if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stale, 0o644); err != nil {
		t.Fatal(err)
	}
	f := &File{Current: "a", Profiles: map[string]*Profile{"a": {Token: "pat_k", ExpiresAt: "2026-11-16T10:00:00Z"}}}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode %v, want 0600", perm)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the temp file is still there")
	}
}

// A config file that already exists with wide permissions is replaced by an owner-only one.
func TestSaveReplacesAWideConfigWithAnOwnerOnlyOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no owner-only mode bits")
	}
	clearEnv(t)
	p, _ := Path()
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte(`{"current":"a"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (&File{Current: "a", Profiles: map[string]*Profile{"a": {Token: "pat_k"}}}).Save(); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v, want 0600", info.Mode().Perm())
	}
}

// A save that fails leaves the old config exactly as it was, and no temp file behind.
func TestFailedSaveLeavesTheOldConfigAndNoTempFile(t *testing.T) {
	clearEnv(t)
	if err := (&File{Current: "a", Profiles: map[string]*Profile{"a": {Token: "pat_old"}}}).Save(); err != nil {
		t.Fatal(err)
	}
	p, _ := Path()
	// Make the rename fail: the config path becomes a folder with something in it.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(p, "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := (&File{Current: "a", Profiles: map[string]*Profile{"a": {Token: "pat_new_key_value"}}}).Save()
	if err == nil {
		t.Fatal("saving over a folder should fail")
	}
	if strings.Contains(err.Error(), "pat_new_key_value") {
		t.Errorf("the error carries the key: %v", err)
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Error("a failed save left its temp file (and the key in it)")
	}
}

func TestCheckWritable(t *testing.T) {
	clearEnv(t)
	p, _ := Path()
	if err := CheckWritable(); err != nil {
		t.Fatalf("a fresh config folder should be writable: %v", err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("the check made the config file")
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 0 {
		t.Errorf("the check left %d file(s) behind", len(entries))
	}
	// The folder cannot be made: its parent is a file.
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTRUNTIME_CONFIG", filepath.Join(file, "sub", "config.json"))
	if err := CheckWritable(); err == nil {
		t.Error("a config folder that cannot be made must be reported")
	}
}

// The host that issued a short-lived key is stored with it and reported only while that key is the one in use.
func TestIssuingHostIsSavedAndReportedOnlyForTheProfilesKey(t *testing.T) {
	clearEnv(t)
	f := &File{Current: "dev", Profiles: map[string]*Profile{
		"dev":    {Token: "pat_dev", ExpiresAt: "2026-11-16T10:00:00Z", IssuedByHost: "API.Example.Test:8443"},
		"pasted": {Token: "pat_pasted"},
		"no-key": {IssuedByHost: "api.example.test"},
	}}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got.Profiles["dev"].IssuedByHost != "API.Example.Test:8443" {
		t.Fatalf("round trip: %+v %v", got.Profiles["dev"], err)
	}
	p, _ := Path()
	if raw, _ := os.ReadFile(p); !strings.Contains(string(raw), `"issued_by_host": "API.Example.Test:8443"`) {
		t.Errorf("the field name in the file:\n%s", raw)
	}
	if r := f.Resolve(Overrides{}); r.TokenIssuedByHost != "api.example.test:8443" {
		t.Errorf("profile key: %q (lower case expected)", r.TokenIssuedByHost)
	}
	if r := f.Resolve(Overrides{Profile: "pasted"}); r.TokenIssuedByHost != "" {
		t.Errorf("a key with no recorded host reported %q", r.TokenIssuedByHost)
	}
	if r := f.Resolve(Overrides{Profile: "no-key"}); r.TokenIssuedByHost != "" {
		t.Errorf("a profile with no key reported %q", r.TokenIssuedByHost)
	}
	if r := f.Resolve(Overrides{Token: "pat_flag"}); r.TokenIssuedByHost != "" {
		t.Errorf("a key from a flag reported %q", r.TokenIssuedByHost)
	}
	t.Setenv("AGENTRUNTIME_PAT", "pat_env")
	if r := f.Resolve(Overrides{}); r.TokenIssuedByHost != "" {
		t.Errorf("a key from the environment reported %q", r.TokenIssuedByHost)
	}
}
