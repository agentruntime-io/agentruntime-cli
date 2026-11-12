package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// readJSONFile loads a JSON document from a file path or "-" (stdin).
func readJSONFile(path string, stdin io.Reader) (any, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // PowerShell often writes a BOM
	var v any
	if err := json.Unmarshal(bytes.TrimSpace(data), &v); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", path, err)
	}
	return v, nil
}

// readJSONObject is readJSONFile restricted to a JSON object.
func readJSONObject(path string, stdin io.Reader) (map[string]any, error) {
	v, err := readJSONFile(path, stdin)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a JSON object", path)
	}
	return m, nil
}

// parseKV turns "key=value" pairs into a map. Values that parse as JSON
// (numbers, booleans, objects, arrays, quoted strings) are decoded; anything
// else stays a string. "key=@path" reads the value from a file as a string.
func parseKV(pairs []string) (map[string]any, error) {
	out := map[string]any{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid key=value %q", p)
		}
		if strings.HasPrefix(v, "@") && len(v) > 1 {
			b, err := os.ReadFile(v[1:])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = strings.TrimRight(string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})), "\r\n")
			continue
		}
		out[k] = inferValue(v)
	}
	return out, nil
}

// parseKVStrings is like parseKV but keeps every value a string.
func parseKVStrings(pairs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid key=value %q", p)
		}
		if strings.HasPrefix(v, "@") && len(v) > 1 {
			b, err := os.ReadFile(v[1:])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			v = strings.TrimRight(string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})), "\r\n")
		}
		out[k] = v
	}
	return out, nil
}

func inferValue(v string) any {
	t := strings.TrimSpace(v)
	if t == "" {
		return v
	}
	switch t[0] {
	case '{', '[', '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
	default:
		if t != "true" && t != "false" && t != "null" {
			return v
		}
	}
	var x any
	dec := json.NewDecoder(strings.NewReader(t))
	dec.UseNumber()
	if err := dec.Decode(&x); err != nil || dec.More() {
		return v
	}
	if n, ok := x.(json.Number); ok {
		// Keep identifiers like "007" or "1e5-ish" ids as strings; only plain numbers become numbers.
		if strings.HasPrefix(t, "0") && len(t) > 1 && !strings.HasPrefix(t, "0.") {
			return v
		}
		if i, err := n.Int64(); err == nil {
			return i
		}
		if f, err := n.Float64(); err == nil {
			return f
		}
		return v
	}
	return x
}

// mergeArgs builds tool arguments from --args JSON, --args-file and repeated --arg k=v
// (later sources win).
func mergeArgs(argsJSON, argsFile string, kv []string, stdin io.Reader) (map[string]any, error) {
	args := map[string]any{}
	if strings.TrimSpace(argsFile) != "" {
		m, err := readJSONObject(argsFile, stdin)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			args[k] = v
		}
	}
	if strings.TrimSpace(argsJSON) != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(argsJSON), &m); err != nil {
			return nil, fmt.Errorf("--args: invalid JSON object: %w", err)
		}
		for k, v := range m {
			args[k] = v
		}
	}
	extra, err := parseKV(kv)
	if err != nil {
		return nil, err
	}
	for k, v := range extra {
		args[k] = v
	}
	return args, nil
}

// setIf stores v under key when it is non-zero.
func setIf(m map[string]any, key string, v any) {
	switch x := v.(type) {
	case string:
		if x == "" {
			return
		}
	case int:
		if x == 0 {
			return
		}
	case bool:
		if !x {
			return
		}
	case []string:
		if len(x) == 0 {
			return
		}
	}
	m[key] = v
}

var errNeedTTY = errors.New("confirmation required but stdin is not a terminal; pass --yes to proceed")
