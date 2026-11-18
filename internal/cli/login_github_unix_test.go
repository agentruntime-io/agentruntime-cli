//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A GITHUB_ENV file that does not exist is created owner-only, and an existing file keeps the permissions it has.
func TestGitHubActionsExportEnvFileModes(t *testing.T) {
	t.Run("a new file is created 0600", func(t *testing.T) {
		e := newGHEnv(t)
		path := filepath.Join(t.TempDir(), "set_env_0001")
		t.Setenv("GITHUB_ENV", path)
		if code, out, errOut := runGH(t, e.args("--export-env")...); code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("GITHUB_ENV created with mode %v, want 0600", perm)
		}
	})
	for _, mode := range []os.FileMode{0o600, 0o644, 0o664} {
		t.Run("an existing file keeps its mode "+mode.String(), func(t *testing.T) {
			e := newGHEnv(t)
			path := useEnvFile(t, "FOO=bar\n")
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if code, out, errOut := runGH(t, e.args("--export-env")...); code != 0 {
				t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != mode {
				t.Errorf("GITHUB_ENV has mode %v after, want the %v it had", perm, mode)
			}
		})
	}
}

// The key saved in the profile is in an owner-only config file.
func TestGitHubActionsLoginWritesAnOwnerOnlyConfigFile(t *testing.T) {
	e := newGHEnv(t)
	if code, out, errOut := runGH(t, e.args()...); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	info, err := os.Stat(configPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode %v, want 0600", perm)
	}
	if !strings.Contains(mustRead(t, configPath()), ghKey) {
		t.Error("the key is not in the config")
	}
}

// A device file or a pipe is not a regular file: it is refused, and never opened (opening a pipe with no reader would
// wait for ever).
func TestGitHubActionsExportEnvRefusesAPipeWithoutOpeningIt(t *testing.T) {
	e := newGHEnv(t)
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot make a pipe here: %v", err)
	}
	t.Setenv("GITHUB_ENV", path)
	done := make(chan struct{})
	var code int
	var out, errOut string
	go func() {
		code, out, errOut = runGH(t, e.args("--export-env")...)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the command waited on the pipe")
	}
	if code != 1 || e.hits() != 0 || out != "" || !strings.Contains(errOut, "does not name a regular file") {
		t.Fatalf("exit %d, %d requests\n%s\n%s", code, e.hits(), out, errOut)
	}
}

// After the checks and before the key arrives, the file is replaced by a link to another file. The key must not be
// written through the link.
func TestGitHubActionsExportEnvDoesNotWriteThroughALinkSwappedInMeanwhile(t *testing.T) {
	e := newGHEnv(t)
	path := useEnvFile(t, "FOO=bar\n")
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.api.onCall = func(int) {
		_ = os.Remove(path)
		_ = os.Symlink(victim, path)
	}
	code, out, errOut := runGH(t, e.args("--export-env")...)
	if code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if got := mustRead(t, victim); got != "untouched\n" {
		t.Errorf("the key was written through the link: %q", got)
	}
	if !strings.Contains(errOut, "the key could not be written") {
		t.Errorf("stderr:\n%s", errOut)
	}
	noGHSecrets(t, "swapped link", true, out, errOut)
}
