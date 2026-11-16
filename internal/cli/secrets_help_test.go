package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// flat collapses every run of whitespace, so a phrase that help text wraps
// over two lines can still be found.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

func readme(t *testing.T) string {
	t.Helper()
	return mustRead(t, filepath.Join("..", "..", "README.md"))
}

func TestRunHelpIsHonestAboutWindowsTheKeyAndMaskingLimits(t *testing.T) {
	isolate(t)
	code, out, _ := run(t, "", "secrets", "run", "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	out = flat(out)
	for _, want := range []string{
		"on Windows it keeps the permissions of its folder", "Owner-only on macOS and Linux",
		"accident prevention", "/proc/$PPID/environ",
		"hex", "changed case", "base64 broken over several lines", `base64 of "user:value"`,
		"whitespace-trimmed", "each line of a multi-line value",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("run --help lacks %q", want)
		}
	}
	for _, bad := range []string{"Created owner-only", "cannot use it to fetch", "a script\ncannot use"} {
		if strings.Contains(out, bad) {
			t.Errorf("run --help still says %q", bad)
		}
	}
	// The README says the same.
	text := flat(readme(t))
	for _, want := range []string{"**on Windows it is not**", "accident prevention", "/proc/$PPID/environ", "base64 of `user:value`", "**Not masked:**"} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
	for _, bad := range []string{"cannot use it to", "so a script cannot"} {
		if strings.Contains(text, bad) {
			t.Errorf("README still says %q", bad)
		}
	}
}

// The help and the README must say that the person names the fields, how many
// lines of a value are masked individually, and nothing that is no longer true.
func TestRunHelpAndReadmeDescribeNamedFieldsAndTheLineCap(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "secrets", "run", "--help")
	help = flat(help)
	for _, want := range []string{
		"--env NAME=REF#FIELD", "--env-from REF#F1,F2", "REF alone, or REF#*, is refused", "AGENTRUNTIME_",
		"--env NAME=REF#FIELD", "never becomes a variable",
		"dotenv: name the fields, REF#F1,F2", "REF writes the whole secret, REF#F1,F2 only those fields",
		"at most 256 distinct lines", "not masked individually", "the value as a whole still is",
		"one reference, and one call carries at most 20",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("run --help lacks %q", want)
		}
	}
	// The old behaviour (every field of a secret, and a list of refused names) is gone.
	for _, bad := range []string{"one variable per field of a whole secret", "PATH, LD_*", "NODE_*", "GIT_*", "*_PROXY", "a whole secret as a file"} {
		if strings.Contains(help, bad) {
			t.Errorf("run --help still says %q", bad)
		}
	}

	text := flat(readme(t))
	for _, want := range []string{
		"`--env-from REF#F1,F2`", "REF alone, or `REF#*`, is refused", "`AGENTRUNTIME_`", "`--env NAME=REF#FIELD`",
		"256 distinct lines", "not masked individually", "dotenv", "the whole secret",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README lacks %q", want)
		}
	}
	for _, bad := range []string{"`PATHEXT`", "`LD_*`", "`NODE_*`", "backstop", "one variable per field of a whole secret"} {
		if strings.Contains(text, bad) {
			t.Errorf("README still says %q", bad)
		}
	}
}

// Every example of --env-from, and of a .env file, must name its fields: a
// whole secret is refused for both.
func TestExamplesNameTheirFields(t *testing.T) {
	isolate(t)
	_, help, _ := run(t, "", "secrets", "run", "--help")
	_, group, _ := run(t, "", "secrets", "--help")
	_, root, _ := run(t, "", "--help")
	docs := map[string]string{"run --help": help, "secrets --help": group, "--help": root, "README": readme(t)}

	envFrom := regexp.MustCompile(`--env-from\s+(\S+)`)
	dotenv := regexp.MustCompile(`--secret-file\s+\S*\.env=(\S+)`)
	checked := 0
	for name, text := range docs {
		for _, line := range strings.Split(text, "\n") {
			if !strings.Contains(line, "agentruntime secrets run") && !strings.Contains(line, "agent secrets run") {
				continue
			}
			for _, re := range []*regexp.Regexp{envFrom, dotenv} {
				for _, m := range re.FindAllStringSubmatch(line, -1) {
					checked++
					if !strings.Contains(m[1], "#") || strings.Contains(m[1], "#*") {
						t.Errorf("%s: an example does not name its fields: %q", name, strings.TrimSpace(line))
					}
				}
			}
		}
	}
	if checked < 3 {
		t.Errorf("only %d examples checked: the pattern no longer finds them", checked)
	}
}

// inlineValue matches `-d name=value` with a real value (a blank value and key=@file are fine).
var inlineValue = regexp.MustCompile(`-d \w+=[^@\s]`)

func TestSetExamplesKeepValuesOutOfTheCommandLine(t *testing.T) {
	isolate(t)
	_, setHelp, _ := run(t, "", "secrets", "set", "--help")
	_, groupHelp, _ := run(t, "", "secrets", "--help")
	i, j := strings.Index(setHelp, "Examples:"), strings.Index(setHelp, "Flags:")
	if i < 0 || j < i {
		t.Fatalf("cannot find the examples in:\n%s", setHelp)
	}
	examples := setHelp[i:j]
	for _, want := range []string{"--data-file stripe.json", "--data-file - --create < stripe.json", "-d api_key=@api_key.txt"} {
		if !strings.Contains(examples, want) {
			t.Errorf("set examples lack %q:\n%s", want, examples)
		}
	}
	if m := inlineValue.FindString(examples); m != "" {
		t.Errorf("a set example puts a value on the command line: %q", m)
	}
	for _, line := range strings.Split(groupHelp, "\n") {
		if strings.Contains(line, "secrets set") && inlineValue.MatchString(line) {
			t.Errorf("secrets --help puts a value on the command line: %q", line)
		}
	}
	for _, want := range []string{"shell history", "process list"} {
		if !strings.Contains(flat(setHelp), want) {
			t.Errorf("set --help lacks the warning (%q)", want)
		}
	}

	readme := readme(t)
	for _, line := range strings.Split(readme, "\n") {
		if strings.Contains(line, "secrets set") && inlineValue.MatchString(line) {
			t.Errorf("README example puts a value on the command line: %q", line)
		}
	}
	if !strings.Contains(readme, "Keep values off the command line") {
		t.Error("README lacks the warning about values on the command line")
	}
}
