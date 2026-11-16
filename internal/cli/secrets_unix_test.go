//go:build !windows

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// On Unix the first signal is forwarded to the command, so a command that does
// not ignore it ends at once, and the run reports the shell-style 128+signal code.
func TestSecretsRunForwardsTheFirstSignal(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dir := t.TempDir()
	file, ready := filepath.Join(dir, "app.env"), filepath.Join(dir, "ready")

	sigs := make(chan os.Signal, 4)
	var out, errb bytes.Buffer
	app := NewApp(strings.NewReader(""), &out, &errb)
	app.signalSource = sigs
	done := make(chan int, 1)
	args := append([]string{"--no-color", "--pat", testToken, "secrets", "run", "--api-url", f.URL,
		"--secret-file", file + "=workspace/app#db_pass", "--"}, helper("wait", ready)...)
	go func() { done <- app.Run(args) }()

	waitFor(t, ready)
	sigs <- syscall.SIGTERM
	select {
	case code := <-done:
		if code != 128+int(syscall.SIGTERM) {
			t.Errorf("exit code %d, want %d", code, 128+int(syscall.SIGTERM))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the forwarded signal did not end the command")
	}
	if exists(file) {
		t.Error("the secret file must be removed")
	}
	assertNoValue(t, "forward", out.String(), errb.String())
}

// The same through the real operating-system signal path (no injected channel).
func TestSecretsRunHandlesARealSignal(t *testing.T) {
	withHelper(t)
	f := newFakeBFF(t)
	dir := t.TempDir()
	file, ready := filepath.Join(dir, "app.env"), filepath.Join(dir, "ready")

	var out, errb bytes.Buffer
	app := NewApp(strings.NewReader(""), &out, &errb)
	done := make(chan int, 1)
	args := append([]string{"--no-color", "--pat", testToken, "secrets", "run", "--api-url", f.URL,
		"--secret-file", file + "=workspace/app#db_pass", "--"}, helper("wait", ready)...)
	go func() { done <- app.Run(args) }()

	// The handler is installed before the file is written, so once the command is
	// ready this signal is caught by the CLI and cannot kill the test process.
	waitFor(t, ready)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 128+int(syscall.SIGTERM) {
			t.Errorf("exit code %d, want %d", code, 128+int(syscall.SIGTERM))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after SIGTERM")
	}
	if exists(file) {
		t.Error("the secret file must be removed after SIGTERM")
	}
}
