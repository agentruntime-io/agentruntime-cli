package secrets

import (
	"errors"
	"strings"
)

// ReservedPrefix starts the names of this tool's own settings, AGENTRUNTIME_PAT
// among them. A secret field may not become a variable or a dotenv key with such
// a name, so a secret can never change how the CLI itself behaves.
const ReservedPrefix = "AGENTRUNTIME_"

var (
	// ErrEnvNameNotPlain means a field name is not plain ASCII letters, digits
	// and underscores (not starting with a digit).
	ErrEnvNameNotPlain = errors.New("not a plain ASCII name")
	// ErrEnvNameReserved means the upper-cased name starts with ReservedPrefix.
	ErrEnvNameReserved = errors.New("the name is reserved for this tool's own settings")
)

// ValidEnvName reports whether s is a portable environment variable name:
// ASCII letters, digits and '_', not starting with a digit.
func ValidEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// EnvFromName returns the variable `--env-from` sets for a field the person
// named: the field name, upper-cased. The field name must be plain ASCII
// [A-Za-z_][A-Za-z0-9_]* BEFORE it is upper-cased, because upper-casing maps some
// non-ASCII letters to ASCII ones (the dotless i becomes I, the long s becomes S)
// and case folding turns the Kelvin sign into k: a name that looks harmless in
// one alphabet must not turn into another name. The upper-cased name must not start
// with ReservedPrefix. The errors are ErrEnvNameNotPlain and ErrEnvNameReserved
// (with the upper-cased name); neither carries a value.
func EnvFromName(field string) (string, error) {
	if !ValidEnvName(field) { // ASCII only, so this is a check on the raw bytes
		return "", ErrEnvNameNotPlain
	}
	name := strings.ToUpper(field)
	if strings.HasPrefix(name, ReservedPrefix) {
		return name, ErrEnvNameReserved
	}
	return name, nil
}

// DotenvKey checks a field name that is about to be written as a dotenv key (it
// is written as it is, not upper-cased). The rules are those of EnvFromName. In
// addition a '.' or '-' is refused, which ValidEnvName already does: bash reads
// a line such as a.b=1 as a command to run, not as an assignment, so sourcing
// the file would try to run it.
func DotenvKey(field string) error {
	_, err := EnvFromName(field)
	return err
}
