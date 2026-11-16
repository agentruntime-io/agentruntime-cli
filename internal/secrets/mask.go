package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MinMaskLen is the shortest value (in characters) that is masked. Shorter
// values would match too much ordinary output.
const MinMaskLen = 8

// MaxLineNeedles is how many lines of ONE multi-line value are masked on their
// own, in addition to the value as a whole. Every line is matched in about a dozen
// encodings, and every needle slows down the scan of everything the command
// prints, so a value of thousands of lines (a certificate bundle, a pasted file)
// would make the output crawl. The longest lines are taken first (the longest
// are the most specific, and the least likely to match ordinary output); among
// lines of equal length the earlier ones. Lines beyond the cap are not masked
// individually, but the whole value, and the value without surrounding
// whitespace, always are.
const MaxLineNeedles = 256

// Mask is what replaces a fetched value in the command's output.
const Mask = "***"

// Masker replaces fetched values in a byte stream: the value as stored, its
// whitespace-trimmed form (a value stored with a trailing newline is usually
// printed without it), and the lines of a multi-line value (a PEM file printed
// one line at a time; at most MaxLineNeedles lines per value), each in its plain,
// base64, URL-encoded and JSON-escaped forms. Every needle must have at least
// MinMaskLen characters.
//
// It stops accidents (a script that echoes its environment); it does not stop a
// program that wants to leak a value it holds. Not masked: hex, a changed case,
// base64 broken over several lines, base64 of "user:value", and anything else
// the command transforms.
//
// A Masker is read-only after NewMasker and safe to share between writers.
type Masker struct {
	// Short counts non-empty values whose trimmed form is shorter than
	// MinMaskLen, so that what a program usually prints is not masked.
	Short int

	byFirst [256][][]byte // needles by first byte, longest first
	count   int
}

// NewMasker builds a Masker for the given values. A value whose trimmed form is
// shorter than MinMaskLen characters is counted in Short (its trimmed form is
// never masked; the exact stored value still is, when it has MinMaskLen
// characters). Empty values are ignored.
func NewMasker(values []string) *Masker {
	m := &Masker{}
	seen := map[string]struct{}{}
	var needles []string
	for _, v := range values {
		if v == "" {
			continue
		}
		if utf8.RuneCountInString(strings.TrimSpace(v)) < MinMaskLen {
			m.Short++
		}
		for _, src := range needleSources(v) {
			if utf8.RuneCountInString(src) < MinMaskLen {
				continue
			}
			for _, f := range forms(src) {
				if _, dup := seen[f]; dup {
					continue
				}
				seen[f] = struct{}{}
				needles = append(needles, f)
			}
		}
	}
	// Longest first, so the leftmost-longest match wins at every position.
	sort.SliceStable(needles, func(i, j int) bool { return len(needles[i]) > len(needles[j]) })
	for _, n := range needles {
		b := []byte(n)
		m.byFirst[b[0]] = append(m.byFirst[b[0]], b)
	}
	m.count = len(needles)
	return m
}

// Empty reports whether nothing would be masked.
func (m *Masker) Empty() bool { return m == nil || m.count == 0 }

// Apply masks a complete buffer in one go.
func (m *Masker) Apply(p []byte) []byte {
	var out bytes.Buffer
	w := m.NewWriter(&out)
	_, _ = w.Write(p)
	_ = w.Close()
	return out.Bytes()
}

// needleSources returns the strings to look for in the output: the value as
// stored, the value without surrounding whitespace, and the lines of a
// multi-line value without surrounding whitespace (which also drops a carriage
// return), at most MaxLineNeedles of them. Pieces that are too short are
// filtered by the caller.
func needleSources(v string) []string {
	out := []string{v}
	if t := strings.TrimSpace(v); t != v {
		out = append(out, t)
	}
	if strings.ContainsAny(v, "\r\n") {
		out = append(out, longestLines(v)...)
	}
	return out
}

// longestLines returns the distinct trimmed lines of v that have at least
// MinMaskLen characters: the longest MaxLineNeedles of them, longest first and in
// the order they appear among equals.
func longestLines(v string) []string {
	seen := map[string]struct{}{}
	var lines []string
	for _, line := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' }) {
		t := strings.TrimSpace(line)
		if utf8.RuneCountInString(t) < MinMaskLen {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		lines = append(lines, t)
	}
	sort.SliceStable(lines, func(i, j int) bool { return len(lines[i]) > len(lines[j]) })
	if len(lines) > MaxLineNeedles {
		lines = lines[:MaxLineNeedles]
	}
	return lines
}

// forms returns the value and the encodings a program is likely to print it in.
func forms(v string) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	add(v)
	b := []byte(v)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		add(enc.EncodeToString(b))
	}
	add(url.QueryEscape(v))
	add(url.PathEscape(v))

	plain := jsonInner(v, false)
	add(jsonInner(v, true)) // Go's default: <, > and & escaped
	add(plain)
	add(strings.ReplaceAll(plain, "/", `\/`)) // PHP's default
	add(jsonASCII(plain))                     // Python's default: non-ASCII as \uXXXX
	return out
}

// jsonInner returns v as it appears inside a JSON string literal.
func jsonInner(v string, escapeHTML bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	s := strings.TrimSuffix(buf.String(), "\n")
	return s[1 : len(s)-1]
}

// jsonASCII rewrites every non-ASCII rune in an already JSON-escaped string as
// \uXXXX (with surrogate pairs above U+FFFF).
func jsonASCII(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r < 0x80:
			sb.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&sb, `\u%04x\u%04x`, r1, r2)
		}
	}
	return sb.String()
}

// Writer is a streaming filter. Matches that straddle two writes are caught:
// the tail of the stream is held back only while it could still become a match.
type Writer struct {
	m   *Masker
	dst io.Writer
	buf []byte
}

// NewWriter returns a filter that writes the masked stream to dst. Call Close
// when the stream ends to release anything held back.
func (m *Masker) NewWriter(dst io.Writer) *Writer {
	return &Writer{m: m, dst: dst}
}

// Write implements io.Writer. It reports len(p) once p is accepted, even if
// part of it is held back until the next write.
func (w *Writer) Write(p []byte) (int, error) {
	if w.m.Empty() {
		return w.dst.Write(p)
	}
	w.buf = append(w.buf, p...)
	if err := w.process(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes whatever is still held back. It does not close dst.
func (w *Writer) Close() error {
	if w.m.Empty() {
		return nil
	}
	return w.process(true)
}

func (w *Writer) process(final bool) error {
	b := w.buf
	out := make([]byte, 0, len(b))
	i := 0
scan:
	for i < len(b) {
		cands := w.m.byFirst[b[i]]
		if len(cands) == 0 {
			out = append(out, b[i])
			i++
			continue
		}
		rest := b[i:]
		for _, n := range cands { // longest first
			if len(rest) >= len(n) {
				if bytes.HasPrefix(rest, n) {
					out = append(out, Mask...)
					i += len(n)
					continue scan
				}
			} else if !final && bytes.HasPrefix(n, rest) {
				break scan // could still become this match: wait for more
			}
		}
		out = append(out, b[i])
		i++
	}
	w.buf = append(w.buf[:0], b[i:]...)
	if len(out) == 0 {
		return nil
	}
	_, err := w.dst.Write(out)
	return err
}
