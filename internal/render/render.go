// Package render formats tool results for humans (tables, key/value, workflow outcomes) or as JSON.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// Style controls ANSI colouring.
type Style struct{ Color bool }

// NewStyle enables colour when w is a terminal, NO_COLOR is unset and the
// terminal supports ANSI (Windows consoles are switched to VT mode).
func NewStyle(w io.Writer, forceOff bool) Style {
	f, ok := w.(*os.File)
	if forceOff || !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return Style{}
	}
	if !term.IsTerminal(int(f.Fd())) {
		return Style{}
	}
	return Style{Color: enableANSI(f)}
}

func (s Style) wrap(code, text string) string {
	if !s.Color || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Style) Bold(t string) string   { return s.wrap("1", t) }
func (s Style) Dim(t string) string    { return s.wrap("2", t) }
func (s Style) Red(t string) string    { return s.wrap("31", t) }
func (s Style) Green(t string) string  { return s.wrap("32", t) }
func (s Style) Yellow(t string) string { return s.wrap("33", t) }
func (s Style) Cyan(t string) string   { return s.wrap("36", t) }

// JSON pretty-prints v. HTML escaping is disabled so payloads stay readable.
func JSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// Compact renders v as one-line JSON, truncated to max runes (0 = no limit).
func Compact(v any, max int) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprint(v)
	}
	return Truncate(strings.TrimSpace(buf.String()), max)
}

// Truncate shortens s to max runes with an ellipsis. max <= 0 disables.
func Truncate(s string, max int) string {
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}

// Scalar formats a leaf value as a table cell.
func Scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case string:
		x = strings.Join(strings.Fields(strings.ReplaceAll(x, "\n", " ")), " ")
		if x == "" {
			return "-"
		}
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case json.Number:
		return x.String()
	case map[string]any, []any:
		return Compact(x, 0)
	}
	return fmt.Sprint(v)
}

func isScalar(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return false
	}
	return true
}

// Table writes an aligned table. Cells are truncated to maxCell runes.
func Table(w io.Writer, st Style, headers []string, rows [][]string, maxCell int) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i := range headers {
			if i < len(r) {
				r[i] = Truncate(r[i], maxCell)
				if n := utf8.RuneCountInString(r[i]); n > widths[i] {
					widths[i] = n
				}
			}
		}
	}
	line := func(cells []string, style func(string) string) {
		var sb strings.Builder
		for i := range headers {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			pad := widths[i] - utf8.RuneCountInString(c)
			if i == len(headers)-1 {
				sb.WriteString(style(c))
			} else {
				sb.WriteString(style(c) + strings.Repeat(" ", pad+2))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(sb.String(), " "))
	}
	upper := make([]string, len(headers))
	for i, h := range headers {
		upper[i] = strings.ToUpper(h)
	}
	line(upper, st.Bold)
	for _, r := range rows {
		line(r, func(s string) string { return s })
	}
}

var preferredColumns = []string{
	"id", "name", "title", "status", "state", "outcome", "type", "slug",
	"workflow_id", "run_id", "workflow_name", "description", "created_at", "updated_at",
}

var preferredListKeys = []string{
	"items", "results", "data", "workflows", "runs", "tasks", "pending", "databases",
	"connections", "instances", "servers", "secrets", "pats", "tokens", "tools",
	"connectors", "projects", "events", "templates", "versions",
}

// findList locates the primary array-of-objects in a result.
func findList(m map[string]any) (string, []map[string]any, bool) {
	toRows := func(v any) ([]map[string]any, bool) {
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			return nil, false
		}
		out := make([]map[string]any, 0, len(arr))
		for _, e := range arr {
			obj, ok := e.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, obj)
		}
		return out, true
	}
	for _, k := range preferredListKeys {
		if rows, ok := toRows(m[k]); ok {
			return k, rows, true
		}
	}
	var found string
	var foundRows []map[string]any
	count := 0
	for k, v := range m {
		if rows, ok := toRows(v); ok {
			found, foundRows = k, rows
			count++
		}
	}
	if count == 1 {
		return found, foundRows, true
	}
	return "", nil, false
}

func pickColumns(rows []map[string]any, maxCols int) []string {
	freq := map[string]int{}
	for _, r := range rows {
		for k, v := range r {
			if isScalar(v) {
				freq[k]++
			}
		}
	}
	var cols []string
	used := map[string]bool{}
	for _, k := range preferredColumns {
		if freq[k]*2 >= len(rows) && freq[k] > 0 && len(cols) < maxCols {
			cols = append(cols, k)
			used[k] = true
		}
	}
	var rest []string
	for k := range freq {
		if !used[k] {
			rest = append(rest, k)
		}
	}
	sort.Slice(rest, func(i, j int) bool {
		if freq[rest[i]] != freq[rest[j]] {
			return freq[rest[i]] > freq[rest[j]]
		}
		return rest[i] < rest[j]
	})
	for _, k := range rest {
		if len(cols) >= maxCols {
			break
		}
		cols = append(cols, k)
	}
	return cols
}

func rowsTable(w io.Writer, st Style, rows []map[string]any) {
	cols := pickColumns(rows, 6)
	if len(cols) == 0 {
		_ = JSON(w, rows)
		return
	}
	cells := make([][]string, len(rows))
	for i, r := range rows {
		cells[i] = make([]string, len(cols))
		for j, c := range cols {
			cells[i][j] = Scalar(r[c])
		}
	}
	Table(w, st, cols, cells, 44)
}

// KeyValue prints an object as aligned "key  value" lines; nested values as indented JSON.
func KeyValue(w io.Writer, st Style, m map[string]any) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	rank := func(k string) int {
		for i, p := range preferredColumns {
			if p == k {
				return i
			}
		}
		return len(preferredColumns)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := rank(keys[i]), rank(keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	width := 0
	for _, k := range keys {
		if len(k) > width {
			width = len(k)
		}
	}
	for _, k := range keys {
		v := m[k]
		label := st.Bold(k) + strings.Repeat(" ", width-len(k)+2)
		if isScalar(v) {
			fmt.Fprintf(w, "%s%s\n", label, Scalar(v))
			continue
		}
		var buf bytes.Buffer
		_ = JSON(&buf, v)
		body := strings.TrimRight(buf.String(), "\n")
		if !strings.Contains(body, "\n") {
			fmt.Fprintf(w, "%s%s\n", label, body)
			continue
		}
		fmt.Fprintf(w, "%s\n%s\n", st.Bold(k), indent(body, "  "))
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// Auto renders any tool result in the most readable form.
func Auto(w io.Writer, st Style, v any) {
	switch x := v.(type) {
	case []any:
		var rows []map[string]any
		for _, e := range x {
			obj, ok := e.(map[string]any)
			if !ok {
				_ = JSON(w, v)
				return
			}
			rows = append(rows, obj)
		}
		if len(rows) == 0 {
			fmt.Fprintln(w, st.Dim("(no results)"))
			return
		}
		rowsTable(w, st, rows)
	case map[string]any:
		if key, rows, ok := findList(x); ok {
			rowsTable(w, st, rows)
			rest := map[string]any{}
			for k, val := range x {
				if k != key && isScalar(val) && val != nil && Scalar(val) != "-" {
					rest[k] = val
				}
			}
			if len(rest) > 0 {
				fmt.Fprintln(w)
				KeyValue(w, st, rest)
			}
			return
		}
		if len(x) == 0 {
			fmt.Fprintln(w, st.Dim("(empty)"))
			return
		}
		KeyValue(w, st, x)
	default:
		_ = JSON(w, v)
	}
}
