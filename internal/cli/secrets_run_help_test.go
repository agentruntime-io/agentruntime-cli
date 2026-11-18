package cli

import (
	"strings"
	"testing"
)

// The examples in the help use neutral commands: the program after "--" in each example is one of a short list.
func TestSecretsRunHelpExamplesRunNeutralCommands(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "secrets", "run", "--help")
	allowed := map[string]bool{"python job.py": true, "./deploy.sh": true, "docker compose up": true}
	seen := 0
	for _, line := range strings.Split(help, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "agentruntime secrets run ") || !strings.Contains(line, " -- ") || strings.Contains(line, "[flags]") {
			continue
		}
		_, program, _ := strings.Cut(line, " -- ")
		seen++
		if !allowed[strings.TrimSpace(program)] {
			t.Errorf("the example %q runs %q: use one of the neutral commands", line, program)
		}
	}
	if seen < 4 {
		t.Errorf("only %d examples with a command were found in the help:\n%s", seen, help)
	}
	if !strings.Contains(flat(help), "agentruntime secrets run --secret-file creds.json=my/cloud -- ./deploy.sh") {
		t.Errorf("the credentials-file example is not the neutral one:\n%s", help)
	}
}
