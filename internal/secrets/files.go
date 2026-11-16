package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FileFormat is the on-disk format of a --secret-file.
type FileFormat int

const (
	// FormatDotenv is KEY=value lines (for .env and *.env paths).
	FormatDotenv FileFormat = iota + 1
	// FormatJSON is one JSON object (for *.json paths).
	FormatJSON
)

// FormatForPath picks the format from the file name: .json is JSON, .env and
// *.env are dotenv. Anything else is refused rather than guessed.
func FormatForPath(path string) (FileFormat, error) {
	switch strings.ToLower(filepath.Ext(filepath.Base(path))) {
	case ".json":
		return FormatJSON, nil
	case ".env":
		return FormatDotenv, nil
	}
	return 0, errors.New("cannot tell the file format: name the file .env or *.env (dotenv) or *.json (JSON)")
}

// Render writes fields in the given format. Keys are sorted so the output is
// stable.
func Render(f FileFormat, fields map[string]string) ([]byte, error) {
	switch f {
	case FormatDotenv:
		return RenderDotenv(fields)
	case FormatJSON:
		return RenderJSON(fields)
	}
	return nil, errors.New("unknown file format")
}

// RenderJSON returns the fields as an indented JSON object with a trailing newline.
func RenderJSON(fields map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if fields == nil {
		fields = map[string]string{}
	}
	if err := enc.Encode(fields); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RenderDotenv returns KEY=value lines that bash (`source`), docker compose and
// python-dotenv all read back as the same value. The three disagree about most
// quoting (checked against bash 5.2, docker compose 5.6 and python-dotenv 1.2 on
// 2026-11-16), so only the forms they agree on are written:
//
//   - a value made only of safe characters is written bare;
//   - otherwise it is single-quoted (literal everywhere, a line break included)
//     when it holds no ', no run of two backslashes, does not end in a backslash
//     (docker compose and python-dotenv misread both) and holds no ${ (python-dotenv
//     expands ${NAME} in every quoting style);
//   - otherwise it is double-quoted, with only \ and " escaped and a line break
//     written as a real line break, when it holds no $ and no backtick (bash
//     expands them, and no escape for them is read the same by all three);
//   - otherwise the value is refused, naming the field and never the value.
//
// A NUL or a carriage return is always refused. Field names are written as they
// are and must pass DotenvKey: plain ASCII letters, digits and _, and not
// starting with AGENTRUNTIME_. A program that loads a dotenv file turns each key
// into an environment variable, so the caller chooses which fields are written
// and never passes the whole content of a secret. A .json file has none of these
// limits.
func RenderDotenv(fields map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		switch err := DotenvKey(k); {
		case errors.Is(err, ErrEnvNameReserved):
			return nil, fmt.Errorf("field name %q cannot be a dotenv key: names starting with %s are reserved for this tool's own settings", k, ReservedPrefix)
		case err != nil:
			return nil, fmt.Errorf("field name %q cannot be a dotenv key (use plain ASCII letters, digits and _, not starting with a digit)", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	for _, k := range keys {
		val, why := dotenvValue(fields[k])
		if why != "" {
			return nil, fmt.Errorf("field %q cannot be written to a dotenv file: its value %s; use a .json file for this secret", k, why)
		}
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(val)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// dotenvValue returns v quoted for a dotenv file. When it cannot be written
// safely it returns a short reason that says nothing about the value beyond the
// kind of problem.
func dotenvValue(v string) (quoted, refusal string) {
	if v == "" {
		return `""`, ""
	}
	if strings.ContainsAny(v, "\x00\r") {
		return "", "has a NUL or a carriage return"
	}
	safe := true
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_-.,:/@%+=", r):
		default:
			safe = false
		}
	}
	if safe {
		return v, ""
	}
	if !strings.ContainsAny(v, "'") && !strings.Contains(v, `\\`) && !strings.HasSuffix(v, `\`) && !strings.Contains(v, "${") {
		return "'" + v + "'", ""
	}
	if !strings.ContainsAny(v, "$`") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`, ""
	}
	return "", "mixes quotes, backslashes, $ or backticks in a way that bash, docker compose and python-dotenv read differently"
}

// WriteOwnerOnly creates path with owner-only permissions (0600; on Windows the
// file keeps the inherited ACL, because Go cannot express more) and writes
// data. It refuses to touch a file that already exists, so a real .env is never
// overwritten and then deleted. A partly written file is removed.
func WriteOwnerOnly(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite it (remove it first)", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// Files tracks the secret files a run has written so they can all be removed
// when the command ends.
type Files struct {
	paths []string
}

// Write creates one owner-only file and remembers it for RemoveAll.
func (f *Files) Write(path string, data []byte) error {
	if err := WriteOwnerOnly(path, data); err != nil {
		return err
	}
	f.paths = append(f.paths, path)
	return nil
}

// Paths returns the files written so far.
func (f *Files) Paths() []string { return append([]string(nil), f.paths...) }

// RemoveAll deletes every file written, newest first. A file that cannot be
// removed (on Windows a descendant of the command may still hold it open) is
// retried briefly, then emptied, and reported in the returned error.
func (f *Files) RemoveAll() error {
	var errs []error
	for i := len(f.paths) - 1; i >= 0; i-- {
		p := f.paths[i]
		var err error
		for try := 0; try < 10; try++ {
			err = os.Remove(p)
			if err == nil || errors.Is(err, os.ErrNotExist) {
				err = nil
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil {
			_ = os.Truncate(p, 0) // at least do not leave the content behind
			errs = append(errs, fmt.Errorf("could not remove %s (emptied it instead): %w", p, err))
		}
	}
	f.paths = nil
	return errors.Join(errs...)
}
