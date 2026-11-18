package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
)

// A host with an empty label (.agentruntime.io, a..agentruntime.io) ends with the official name, and a proxy that is handed
// it may read it as something else. It is refused wherever an address is read, before anything is printed or sent.

func TestAnAddressWithAnEmptyLabelIsRefusedBeforeAnythingIsPrintedOrSent(t *testing.T) {
	for _, host := range []string{".agentruntime.io", "a..agentruntime.io", "api..agentruntime.io", "..agentruntime.io"} {
		isolate(t)
		net := recordNetwork(t)
		code, out, errOut := runApp(t, false, newDevEnv().tweak, "login", "--device", "--api-url", "https://"+host, "--ref", "my/*")
		if code != 1 || !strings.Contains(errOut, "empty part in its host name") || out != "" || len(net.requests()) != 0 {
			t.Errorf("login --device, %s: exit %d, %d requests\n%s\n%s", host, code, len(net.requests()), out, errOut)
		}
		nothingSaved(t)

		isolate(t)
		net = recordNetwork(t)
		code, out, errOut = runApp(t, false, nil, "--pat", testToken, "secrets", "check", "--api-url", "https://"+host, "workspace/live/stripe#API_KEY")
		if code != 1 || !strings.Contains(errOut, "empty part in its host name") || len(net.requests()) != 0 {
			t.Errorf("secrets check, %s: exit %d, %d requests\n%s\n%s", host, code, len(net.requests()), out, errOut)
		}

		isolate(t)
		net = recordNetwork(t)
		writeConfig(t, "default", map[string]*config.Profile{"default": {URL: "https://mcp." + host + "/mcp", Token: testToken, ExpiresAt: clockNow.Add(time.Hour).Format(time.RFC3339)}})
		code, out, errOut = runApp(t, false, atClock, "workflows", "list")
		if code != 1 || !strings.Contains(errOut, "empty part in its host name") || len(net.requests()) != 0 {
			t.Errorf("workflows list, mcp.%s: exit %d, %d requests\n%s\n%s", host, code, len(net.requests()), out, errOut)
		}
	}
}
