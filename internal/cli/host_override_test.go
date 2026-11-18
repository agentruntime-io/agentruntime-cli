package cli

import (
	"strings"
	"testing"
)

// --yes answers prompts. Lifting the refusal to send a saved key to a host that did not issue it is a decision of its own:
// the flag is --allow-other-host, and neither --yes (the global one, or the --yes and -y that approve, delete and the
// workflow commands have for their confirmations) nor the environment does it.

func TestYesDoesNotLiftTheRefusalToSendTheSavedKeyToAnotherHost(t *testing.T) {
	cases := []struct {
		name string
		args func(apiURL string) []string
	}{
		{"global --yes before the command", func(u string) []string {
			return []string{"--yes", "secrets", "check", "--api-url", u, "workspace/live/stripe#API_KEY"}
		}},
		{"global --yes after the command", func(u string) []string {
			return []string{"secrets", "check", "--api-url", u, "workspace/live/stripe#API_KEY", "--yes"}
		}},
		{"the --yes of secrets delete", func(u string) []string {
			return []string{"secrets", "delete", "live/stripe", "--scope", "tenant", "--yes", "--api-url", u}
		}},
		{"the -y of secrets delete", func(u string) []string {
			return []string{"secrets", "delete", "live/stripe", "--scope", "tenant", "-y", "--api-url", u}
		}},
	}
	for _, c := range cases {
		isolate(t)
		storeKey(t, "other.example")
		api := newVaultAPI(t)
		code, out, errOut := runApp(t, false, atClock, c.args(api.URL)...)
		if code != 1 || api.count() != 0 || !strings.Contains(errOut, "refusing to send the access key saved in profile") || !strings.Contains(errOut, "add --allow-other-host") {
			t.Errorf("%s: exit %d, %d requests\n%s\n%s", c.name, code, api.count(), out, errOut)
		}
		if strings.Contains(errOut, "add --yes") {
			t.Errorf("%s: the message still points at --yes:\n%s", c.name, errOut)
		}
	}
}

func TestAllowOtherHostLiftsTheRefusalAndAConfirmationFlagStillConfirms(t *testing.T) {
	// secrets delete needs its own --yes for its prompt and --allow-other-host for the host: both are needed, each does one thing.
	isolate(t)
	storeKey(t, "other.example")
	api := newVaultAPI(t)
	code, _, errOut := runApp(t, false, atClock, "secrets", "delete", "live/stripe", "--scope", "tenant", "--yes", "--allow-other-host", "--api-url", api.URL)
	if code != 0 || api.count() != 1 || !strings.Contains(errOut, "(sent because of --allow-other-host)") {
		t.Errorf("exit %d, %d requests\n%s", code, api.count(), errOut)
	}
	// --allow-other-host alone is not a confirmation: the command still asks (and with no terminal it refuses).
	isolate(t)
	storeKey(t, "other.example")
	api = newVaultAPI(t)
	code, _, errOut = runApp(t, false, atClock, "secrets", "delete", "live/stripe", "--scope", "tenant", "--allow-other-host", "--api-url", api.URL)
	if code == 0 || api.count() != 0 {
		t.Errorf("a delete went through without its own confirmation: exit %d, %d requests\n%s", code, api.count(), errOut)
	}
}

func TestTheEnvironmentDoesNotLiftTheRefusal(t *testing.T) {
	for _, name := range []string{"AGENTRUNTIME_ALLOW_OTHER_HOST", "AGENTRUNTIME_YES", "ALLOW_OTHER_HOST", "AGENTRUNTIME_ASSUME_YES"} {
		isolate(t)
		t.Setenv(name, "1")
		storeKey(t, "other.example")
		api := newVaultAPI(t)
		code, _, errOut := runApp(t, false, atClock, "secrets", "check", "--api-url", api.URL, "workspace/live/stripe#API_KEY")
		if code != 1 || api.count() != 0 || !strings.Contains(errOut, "refusing to send the access key saved in profile") {
			t.Errorf("%s=1: exit %d, %d requests\n%s", name, code, api.count(), errOut)
		}
	}
}

func TestAllowOtherHostDoesNotConfirmAnUnofficialAPIHostForLoginDevice(t *testing.T) {
	// login --device asks a person to confirm an API host outside agentruntime.io: that is a confirmation, so --yes does it
	// (login_device_review_test.go) and --allow-other-host does not.
	isolate(t)
	d := newDeviceAPI(t)
	code, out, errOut := runApp(t, false, func(a *App) { newDevEnv().tweak(a); foreign(a); noTerminal(t)(a) }, deviceArgs(d, "--allow-other-host")...)
	if code != 2 || !strings.Contains(errOut, "add --yes if you mean it") || d.hits() != 0 {
		t.Errorf("exit %d, %d requests\n%s\n%s", code, d.hits(), out, errOut)
	}
	nothingSaved(t)
}

func TestTheGlobalFlagsAreDocumentedApart(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "--help")
	help = flat(help)
	if !strings.Contains(help, "--allow-other-host send a saved short-lived key to a host other than the one that issued it (refused without this; --yes does not do it)") {
		t.Errorf("--allow-other-host is not described in the help:\n%s", help)
	}
	if !strings.Contains(help, "--yes say yes to what a command would ask (login --device: an API host outside agentruntime.io)") {
		t.Errorf("--yes is not described in the help:\n%s", help)
	}
	if strings.Contains(help, "--yes say yes to what a command would ask, and send") {
		t.Error("--yes still says it sends a key to another host")
	}
	text := flat(readme(t))
	for _, want := range []string{
		"unless you pass `--allow-other-host` (a flag of its own: `--yes` only answers prompts and never lifts this, and there is no environment variable for it)",
		"unless you pass `--allow-other-host`, as for `login --device`",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
	for _, bad := range []string{"unless you pass `--yes`, and then it prints a warning", "it unless you pass `--yes`, as for `login --device`"} {
		if strings.Contains(text, bad) {
			t.Errorf("README still says %q", bad)
		}
	}
}

func TestTheHelpsNameAllowOtherHostForTheSavedKeyRule(t *testing.T) {
	isolate(t)
	_, devHelp, _ := run(t, "", "login", "--help")
	devHelp = flat(devHelp)
	if !strings.Contains(devHelp, "refuse to send it to a different host unless you pass --allow-other-host") {
		t.Error("login --help does not name --allow-other-host")
	}
	if strings.Contains(devHelp, "different host unless you pass --yes") || strings.Contains(devHelp, "another host unless you pass --yes") {
		t.Error("login --help still names --yes for the saved key rule")
	}
}
