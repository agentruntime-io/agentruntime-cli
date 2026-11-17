package secrets

// The limits on a template that runs after the fetch has spent a one-use key, and the fixed sentences its errors are
// made of. They bound what the template builds and how long it runs; they are not a promise about its memory or time
// as a whole. See the header of template.go.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"text/template"
	"text/template/parse"
	"time"
)

const (
	// ExecTimeout is how long a template may run.
	ExecTimeout = 10 * time.Second

	// MaxValueBytes is the most any one value a template builds may hold. The values of a call are capped at 64 KB, so
	// this is room, and what stops a loop that doubles a string.
	MaxValueBytes = 1 << 20

	// MaxIntLiteral is the largest number that may be written in a template action. A larger one can only be a loop
	// or a width that would not finish. Text outside {{ }} is not a number to the template.
	MaxIntLiteral = 1_000_000

	// MaxLoopProduct is the most iterations that loops over written-out numbers may add up to when nested
	// ({{ range 1000 }}{{ range 1000 }} is 1000000).
	MaxLoopProduct = 1_000_000

	// MaxTotalBytes is the most text that all the functions of a template may build in one render, added up (every
	// result of printf, print, println, html, js, urlquery, json, b64enc and quote counts). MaxValueBytes limits one
	// value, so without this a template could hold a great many values of that size.
	MaxTotalBytes = 16 << 20

	// MaxNesting is how deep if, range and with may be nested in one template body, and MaxCallDepth how many
	// templates may call one another in a row ({{ template }}). Neither is a limit people reach: they keep the stack
	// of a run small, because a run that overflows its stack is not an error the program can catch.
	MaxNesting   = 50
	MaxCallDepth = 100

	maxFormatWidth = 4096 // the largest width or precision in a printf format
	maxFormatVerbs = 256  // the most verbs in one printf format
)

// execTimeout is ExecTimeout; a test shortens it.
var execTimeout = ExecTimeout

// funcError is an error a template function returns. Its text is fixed: it never holds a value, a name taken from
// a value, or anything the template engine wrote.
type funcError struct{ msg string }

func (e *funcError) Error() string { return e.msg }

func fixed(msg string) error { return &funcError{msg: msg} }

var errRunPanicked = errors.New("the template could not be run")

// tooBig reports whether a number written in a template is above MaxIntLiteral.
func tooBig(n *parse.NumberNode) bool {
	switch {
	case n.IsInt:
		return n.Int64 > MaxIntLiteral || n.Int64 < -MaxIntLiteral
	case n.IsUint:
		return n.Uint64 > MaxIntLiteral
	}
	return false
}

// literalRange is how many times a loop runs when it ranges over a number written out in the template (range 5), and 0
// when it is anything else.
func literalRange(p *parse.PipeNode) int64 {
	if p == nil || len(p.Cmds) != 1 || len(p.Cmds[0].Args) != 1 {
		return 0
	}
	n, ok := p.Cmds[0].Args[0].(*parse.NumberNode)
	if !ok || !n.IsInt || n.Int64 < 1 {
		return 0
	}
	if n.Int64 > MaxIntLiteral {
		return MaxIntLiteral
	}
	return n.Int64
}

// checkFormat refuses a printf format that could build a huge string. It reads a format the way fmt does, verb by
// verb, and takes only this shape for a verb: a percent sign, flags (+ - # space 0), a width, a dot and a precision,
// and then a letter. A width or precision above maxFormatWidth, a * or a [n] (a width or an argument taken from
// elsewhere), more than maxFormatVerbs verbs, and anything but an ASCII letter in the place of the verb are refused.
// The last rule is what keeps this reading in step with fmt: a verb that is not a letter ("%1+") ends there, and
// the percent sign after it opens a new verb with its own width, which the check must see, so it is refused.
// "%%" is the only literal percent sign, and a percent sign that ends the format builds nothing.
//
// Every printf the template calls goes through it, so a format built at run time (from a secret, say) is held to it
// as well.
func checkFormat(format string) error {
	verbs := 0
	i := 0
	for i < len(format) {
		if format[i] != '%' {
			i++
			continue
		}
		i++
		if i >= len(format) {
			break // a lone % at the end writes a note, not a width
		}
		if format[i] == '%' {
			i++
			continue
		}
		verbs++
		for i < len(format) && strings.IndexByte("+-# 0", format[i]) >= 0 {
			i++
		}
		var err error
		if i, err = formatNumber(format, i); err != nil {
			return err
		}
		if i < len(format) && format[i] == '.' {
			i++
			if i, err = formatNumber(format, i); err != nil {
				return err
			}
		}
		if i >= len(format) {
			break // the format ends inside the verb
		}
		if c := format[i]; c == '*' || c == '[' {
			return errors.New("a format may not take a width or an argument from elsewhere (* or [n])")
		} else if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return errors.New("a verb in a format must end in a letter (a % after flags or a width is not allowed; write a literal % as %%)")
		}
		i++
	}
	if verbs > maxFormatVerbs {
		return fmt.Errorf("a format may have at most %d verbs", maxFormatVerbs)
	}
	return nil
}

// formatNumber reads the digits of a width or precision at format[i:] and returns where they end. A * or [ in that
// place is refused, and so is a number above maxFormatWidth.
func formatNumber(format string, i int) (int, error) {
	if i < len(format) && (format[i] == '*' || format[i] == '[') {
		return i, errors.New("a format may not take a width or an argument from elsewhere (* or [n])")
	}
	n := 0
	for i < len(format) && format[i] >= '0' && format[i] <= '9' {
		if n = n*10 + int(format[i]-'0'); n > maxFormatWidth {
			return i, fmt.Errorf("a width or precision in a format may not be larger than %d", maxFormatWidth)
		}
		i++
	}
	return i, nil
}

// budget counts what the functions of one render have built. One is made for each run.
type budget struct{ used atomic.Int64 }

// bound returns s if it fits in one value and in what the run has left, and counts it.
func (b *budget) bound(s string) (string, error) {
	if len(s) > MaxValueBytes {
		return "", fixed(fmt.Sprintf("a value in the template grew larger than %d MiB", MaxValueBytes>>20))
	}
	if b.used.Add(int64(len(s))) > MaxTotalBytes {
		return "", fixed(fmt.Sprintf("the template has built more than %d MiB of text in all", MaxTotalBytes>>20))
	}
	return s, nil
}

// sized refuses a value longer than MaxValueBytes without counting it (a value the server sent, not one built here).
func sized(s string) (string, error) {
	if len(s) > MaxValueBytes {
		return "", fixed(fmt.Sprintf("a value in the template grew larger than %d MiB", MaxValueBytes>>20))
	}
	return s, nil
}

// plainArgs refuses an argument that is not text, a number or a truth value. A map of fields given to printf with a
// width ("%4096v") is written out with that width for every key and every value, which is many times its size, and
// there is nothing a template needs that for: json writes a map, and range walks it.
func plainArgs(args []any) error {
	for _, a := range args {
		if a == nil {
			continue
		}
		switch reflect.TypeOf(a).Kind() {
		case reflect.String, reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
		default:
			return fixed("a map of fields cannot be given to printf, print, println, html, js or urlquery (it may be written out in full many times over): use json, or range over the fields")
		}
	}
	return nil
}

// boundArgs refuses arguments that together are longer than MaxValueBytes, before a function writes them out.
func boundArgs(args []any) error {
	total := 0
	for _, a := range args {
		switch v := a.(type) {
		case string:
			total += len(v)
		case []byte:
			total += len(v)
		case map[string]string:
			for k, s := range v {
				total += len(k) + len(s)
			}
		}
		if total > MaxValueBytes {
			return fixed(fmt.Sprintf("the values given to a function are larger than %d MiB together", MaxValueBytes>>20))
		}
	}
	return nil
}

// boundedFuncs replace the built-in functions and the helpers that can make a string longer than their input, so
// that a loop which feeds a result back in cannot double it without end ({{ $s = printf "%s%s" $s $s }}), and so
// that all of them together stop at MaxTotalBytes. printf, print, println, html, js and urlquery take text and
// numbers only (see plainArgs).
func boundedFuncs(b *budget) template.FuncMap {
	escaper := func(f func(...any) string) func(...any) (string, error) {
		return func(args ...any) (string, error) {
			if err := plainArgs(args); err != nil {
				return "", err
			}
			if err := boundArgs(args); err != nil {
				return "", err
			}
			return b.bound(f(args...))
		}
	}
	return template.FuncMap{
		"printf": func(format string, args ...any) (string, error) {
			if err := checkFormat(format); err != nil {
				return "", fixed("printf: " + err.Error())
			}
			if err := plainArgs(args); err != nil {
				return "", err
			}
			if err := boundArgs(args); err != nil {
				return "", err
			}
			return b.bound(fmt.Sprintf(format, args...))
		},
		"print": func(args ...any) (string, error) {
			if err := plainArgs(args); err != nil {
				return "", err
			}
			if err := boundArgs(args); err != nil {
				return "", err
			}
			return b.bound(fmt.Sprint(args...))
		},
		"println": func(args ...any) (string, error) {
			if err := plainArgs(args); err != nil {
				return "", err
			}
			if err := boundArgs(args); err != nil {
				return "", err
			}
			return b.bound(fmt.Sprintln(args...))
		},
		"html":     escaper(template.HTMLEscaper),
		"js":       escaper(template.JSEscaper),
		"urlquery": escaper(template.URLQueryEscaper),
		// json writes a value as JSON: a string with its quotes, a fields map as an object.
		"json": func(v any) (string, error) {
			if err := boundArgs([]any{v}); err != nil {
				return "", err
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(v); err != nil {
				return "", fixed("json: that value cannot be written as JSON")
			}
			return b.bound(strings.TrimSuffix(buf.String(), "\n"))
		},
		// b64enc writes a string as standard base64.
		"b64enc": func(s string) (string, error) {
			if err := boundArgs([]any{s}); err != nil {
				return "", err
			}
			return b.bound(base64.StdEncoding.EncodeToString([]byte(s)))
		},
		// quote wraps a string in double quotes with Go escapes (the same as Helm's quote).
		"quote": func(s string) (string, error) {
			if err := boundArgs([]any{s}); err != nil {
				return "", err
			}
			return b.bound(strconv.Quote(s))
		},
	}
}

// ---- errors ---------------------------------------------------------------------------------------------------

// where is the "line:column: executing" the template engine puts in front of an error from a run.
var where = regexp.MustCompile(`(\d+):(\d+): executing "`)

// execError turns the error of a run into one that cannot hold a value. A function of ours returns a fixed sentence
// and that is kept. Anything else came from the template engine, whose messages can quote a value ("range can't
// iterate over <the value>"), so its text is not used at all: the error says what kind of mistake it was, from a
// fixed list, and the line.
func execError(err error) error {
	if errors.Is(err, errTooLarge) {
		return tmplErrf("the template produces more than %d MiB; nothing was written", MaxRenderedBytes>>20)
	}
	var detail string
	var fe *funcError
	switch {
	case errors.As(err, &fe):
		detail = fe.msg
	case errors.Is(err, errRunPanicked):
		detail = errRunPanicked.Error()
	default:
		detail = engineMistake(err.Error())
	}
	if m := where.FindStringSubmatch(err.Error()); m != nil {
		return tmplErrf("the template failed at line %s: %s", m[1], detail)
	}
	return tmplErrf("the template failed: %s", detail)
}

// engineMistake names the kind of mistake behind a message of the template engine, using only sentences of ours.
func engineMistake(msg string) string {
	switch {
	case strings.Contains(msg, "no entry for key"):
		return "a name that is not in the secret was used (fields and missing names are errors, never empty)"
	case strings.Contains(msg, "range can't iterate over"):
		return "range was used on text; to loop over the fields of a secret, range over fields \"REF\""
	case strings.Contains(msg, "can't evaluate field"):
		return "a field was asked of a value that has none; use (fields \"REF\").NAME, or secret for one text value"
	case strings.Contains(msg, "wrong type for value"), strings.Contains(msg, "incompatible types"), strings.Contains(msg, "invalid value"):
		return "a function was given a value of the wrong type"
	case strings.Contains(msg, "wrong number of args"):
		return "a function was given the wrong number of arguments"
	case strings.Contains(msg, "maximum template depth"):
		return "templates call each other too deeply"
	case strings.Contains(msg, "error calling"):
		return "a function refused its arguments"
	}
	return "the template engine could not run it"
}
