package cli

import (
	"errors"
	"net/url"
	"os/exec"
	"runtime"
	"strings"

	"github.com/agentruntime-io/agentruntime-cli/internal/apihost"
)

// unsafeInAddress are the characters an address may not contain before it is handed to the system opener. On
// Windows the opener (rundll32) re-reads its command line, and a quote, a caret, a pipe, a percent sign or a bracket
// has a meaning there; a space ends an argument; none of them belongs in the plain address the server sends.
const unsafeInAddress = "\"<>^|`{}%\\ "

// openableAddress says whether address is a plain https address that may be given to the system opener: printable
// ASCII without any character in unsafeInAddress, an https address with a host and no user name, that survives a
// parse and write-back unchanged and whose host is the one written in it.
func openableAddress(address string) error {
	bad := errors.New("the address is not a plain https address")
	if !strings.HasPrefix(address, "https://") {
		return errors.New("only https addresses are opened")
	}
	for _, r := range address {
		if r < 0x21 || r > 0x7e || strings.ContainsRune(unsafeInAddress, r) {
			return bad
		}
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Hostname() == "" || u.String() != address {
		return bad
	}
	authority, _, _ := strings.Cut(strings.TrimPrefix(address, "https://"), "/")
	authority, _, _ = strings.Cut(authority, "?")
	authority, _, _ = strings.Cut(authority, "#")
	if !apihost.Same(authority, u.Host) {
		return bad
	}
	return nil
}

// launch starts a program and does not wait for it. It is a seam: tests replace it, so no test ever starts a real
// opener.
var launch = func(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap the opener; its result does not matter
	return nil
}

// openInBrowser asks the operating system to open an https address in the default browser. It starts the system's
// own opener directly, with the address as one argument and no shell, so nothing in the address can run as a
// command. It refuses anything openableAddress does not accept, so no caller can hand it a path, an option or a
// script.
func openInBrowser(address string) error {
	if err := openableAddress(address); err != nil {
		return err
	}
	switch runtime.GOOS {
	case "windows":
		return launch("rundll32", "url.dll,FileProtocolHandler", address)
	case "darwin":
		return launch("open", address)
	}
	return launch("xdg-open", address)
}
