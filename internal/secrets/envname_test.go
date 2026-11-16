package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestValidEnvName(t *testing.T) {
	for _, ok := range []string{"A", "_A", "STRIPE_KEY", "a1", "_1"} {
		if !ValidEnvName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "1A", "A-B", "A.B", "A B", "A=B", "\U000000e9"} {
		if ValidEnvName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

// Any plain name is fine, whatever it is called: the person named the field, so
// what the variable is called is their decision. Only the reserved prefix is not
// available.
func TestEnvFromNameAcceptsAnyPlainName(t *testing.T) {
	for in, want := range map[string]string{
		"DB_PASS": "DB_PASS", "db_pass": "DB_PASS", "API_KEY": "API_KEY", "Host": "HOST", "token": "TOKEN",
		"_x": "_X", "a1": "A1", "WEBHOOK_SECRET": "WEBHOOK_SECRET",
		// Names that change how programs start are the person's call when they name them.
		"PATH": "PATH", "node_options": "NODE_OPTIONS", "GOFLAGS": "GOFLAGS", "pip_index_url": "PIP_INDEX_URL",
		"LD_PRELOAD": "LD_PRELOAD", "https_proxy": "HTTPS_PROXY",
		// The reserved prefix needs the underscore.
		"AGENTRUNTIME": "AGENTRUNTIME", "AGENTRUNTIMEX": "AGENTRUNTIMEX", "MY_AGENTRUNTIME_PAT": "MY_AGENTRUNTIME_PAT",
	} {
		name, err := EnvFromName(in)
		if err != nil || name != want {
			t.Errorf("%s: %q, %v (want %q)", in, name, err, want)
		}
	}
}

func TestEnvFromNameRefusesTheReservedPrefixInAnyCase(t *testing.T) {
	for _, f := range []string{
		"AGENTRUNTIME_PAT", "agentruntime_pat", "AgentRuntime_Api_Url", "AGENTRUNTIME_MCP_URL", "agentruntime_x", "AGENTRUNTIME_",
	} {
		name, err := EnvFromName(f)
		if !errors.Is(err, ErrEnvNameReserved) {
			t.Errorf("%s: err = %v, want ErrEnvNameReserved", f, err)
		}
		if name != strings.ToUpper(f) {
			t.Errorf("%s: the refused name should be reported upper-cased, got %q", f, name)
		}
		if err := DotenvKey(f); !errors.Is(err, ErrEnvNameReserved) {
			t.Errorf("%s as a dotenv key: err = %v, want ErrEnvNameReserved", f, err)
		}
	}
}

// strings.ToUpper maps some non-ASCII letters to ASCII ones. The check on the
// raw field name has to come first.
func TestEnvFromNameRefusesNonASCIIBeforeUpperCasing(t *testing.T) {
	// What the dotless i would have turned into really is ASCII.
	if strings.ToUpper("\U00000131d_token") != "ID_TOKEN" {
		t.Log("this Go version does not upper-case the dotless i to I; the rule is still correct")
	}
	for _, f := range []string{
		"\U00000131d_token",          // dotless i (U+0131) upper-cases to I: would become ID_TOKEN
		"dbpass\U00000131\U00000131", // the same inside a longer name
		"agentruntim\U00000131e_pat", // would become AGENTRUNTIME_PAT and slip past the reserved prefix
		"\U0000017fecret_key",        // long s (U+017F) upper-cases to S: would become SECRET_KEY
		"\U0000212aey",               // Kelvin sign (U+212A): case-folds to k
		"\U0000039aEY",               // Greek capital kappa next to ASCII
		"caf\U000000e9",              // plain accent
		"\U0000540d\U0000524d",       // not Latin at all
		"a\x00b", "a b",              // control and space
		"api-key", "1abc", "", "a.b", "a,b", "*",
	} {
		name, err := EnvFromName(f)
		if !errors.Is(err, ErrEnvNameNotPlain) {
			t.Errorf("%q: err = %v, want ErrEnvNameNotPlain", f, err)
		}
		if name != "" {
			t.Errorf("%q: no name should come back, got %q", f, name)
		}
		if err := DotenvKey(f); !errors.Is(err, ErrEnvNameNotPlain) {
			t.Errorf("%q as a dotenv key: err = %v, want ErrEnvNameNotPlain", f, err)
		}
	}
}

// bash reads a.b=1 as a command, not an assignment, so a key with '.' or '-' is
// not written to a dotenv file.
func TestDotenvKeyRefusesWhatIsNotAShellAssignment(t *testing.T) {
	for _, k := range []string{"a.b", "a-b", "A.B", "db-password", "x.", "x-"} {
		if err := DotenvKey(k); !errors.Is(err, ErrEnvNameNotPlain) {
			t.Errorf("%q: err = %v, want ErrEnvNameNotPlain", k, err)
		}
	}
	for _, k := range []string{"A", "db_pass", "Host", "_x", "A1"} {
		if err := DotenvKey(k); err != nil {
			t.Errorf("%q: %v", k, err)
		}
	}
}
