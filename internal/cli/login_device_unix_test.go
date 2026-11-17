//go:build !windows

package cli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

// The saved key is in the config file, and the config file is owner-only whatever was on disk before.
func TestDeviceLoginWritesAnOwnerOnlyConfigFile(t *testing.T) {
	isolate(t)
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	info, err := os.Stat(configPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode %v, want 0600", perm)
	}
	if !strings.Contains(mustRead(t, configPath()), devKey) {
		t.Error("the key is not in the config")
	}
}

func TestDeviceLoginReplacesAWideConfigAndIgnoresAStaleTempFileWithWidePermissions(t *testing.T) {
	isolate(t)
	// A config someone made with wide permissions, holding an old key that came from a sign-in, and a temp file left
	// by a crash with wide permissions too.
	old := map[string]*config.Profile{"default": {Token: "pat_FAKE-old-signed-in-key", ExpiresAt: clockNow.Add(-time.Hour).Format(time.RFC3339)}}
	writeConfig(t, "default", old)
	if err := os.Chmod(configPath(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath()+".tmp", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath()+".tmp", 0o644); err != nil {
		t.Fatal(err)
	}
	d := newDeviceAPI(t)
	d.poll = pollScript(goodGrant())
	if code, out, errOut := runDevice(t, newDevEnv(), deviceArgs(d)...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	info, err := os.Stat(configPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode %v after the sign-in, want 0600", perm)
	}
	if _, err := os.Stat(configPath() + ".tmp"); err == nil {
		t.Error("the temp file is still there")
	}
	if savedProfile(t, "default").Token != devKey {
		t.Error("the key was not saved")
	}
}
