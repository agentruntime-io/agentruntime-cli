package secrets

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"
)

const fakeValue = "s3cr3t/Value+ok=ünï<&>"

func maskStream(m *Masker, chunks ...string) string {
	var out bytes.Buffer
	w := m.NewWriter(&out)
	for _, c := range chunks {
		if n, err := w.Write([]byte(c)); err != nil || n != len(c) {
			panic("write failed")
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return out.String()
}

func TestMaskReplacesEveryForm(t *testing.T) {
	m := NewMasker([]string{fakeValue})
	b := []byte(fakeValue)
	forms := map[string]string{
		"raw":            fakeValue,
		"base64 std":     base64.StdEncoding.EncodeToString(b),
		"base64 raw std": base64.RawStdEncoding.EncodeToString(b),
		"base64 url":     base64.URLEncoding.EncodeToString(b),
		"base64 raw url": base64.RawURLEncoding.EncodeToString(b),
		"url query":      url.QueryEscape(fakeValue),
		"url path":       url.PathEscape(fakeValue),
		"json go":        jsonInner(fakeValue, true),
		"json no html":   jsonInner(fakeValue, false),
		"json php":       strings.ReplaceAll(jsonInner(fakeValue, false), "/", `\/`),
		"json python":    jsonASCII(jsonInner(fakeValue, false)),
	}
	// The JSON forms really differ from the raw value for this fixture.
	if jsonInner(fakeValue, true) == fakeValue || jsonASCII(jsonInner(fakeValue, false)) == jsonInner(fakeValue, false) {
		t.Fatal("fixture does not exercise the JSON escapes")
	}
	for name, form := range forms {
		in := "before " + form + " after"
		got := maskStream(m, in)
		if got != "before *** after" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestMaskLeavesOtherTextAlone(t *testing.T) {
	m := NewMasker([]string{"abcdefgh"})
	for _, s := range []string{"", "nothing here", "abcdefg", "bcdefgh", "ABCDEFGH", "line1\nline2\n"} {
		if got := maskStream(m, s); got != s {
			t.Errorf("%q changed to %q", s, got)
		}
	}
	if got := maskStream(m, "x abcdefgh y abcdefgh z"); got != "x *** y *** z" {
		t.Errorf("got %q", got)
	}
}

func TestMaskShortValuesAreCountedNotMasked(t *testing.T) {
	m := NewMasker([]string{"abc", "1234567", "", "12345678", "ünïcödé"})
	if m.Short != 3 { // abc, 1234567, and the 7-character ünïcödé; the empty value is ignored
		t.Errorf("Short = %d, want 3", m.Short)
	}
	if got := maskStream(m, "abc 1234567 ünïcödé 12345678"); got != "abc 1234567 ünïcödé ***" {
		t.Errorf("got %q", got)
	}
	none := NewMasker([]string{"abc"})
	if !none.Empty() || none.Short != 1 {
		t.Errorf("Empty=%v Short=%d", none.Empty(), none.Short)
	}
	if got := maskStream(none, "abc stays"); got != "abc stays" {
		t.Errorf("got %q", got)
	}
	if got := maskStream(NewMasker(nil), "x"); got != "x" {
		t.Errorf("nil values: %q", got)
	}
}

func TestMaskLeftmostLongestWins(t *testing.T) {
	m := NewMasker([]string{"abcdefgh", "abcdefghij"})
	if got := maskStream(m, "..abcdefghij.."); got != "..***.." {
		t.Errorf("got %q", got)
	}
	if got := maskStream(m, "..abcdefghi.."); got != "..***i.." {
		t.Errorf("got %q", got)
	}
}

// A value that arrives split over two writes must still be caught, at every split.
func TestMaskAcrossWrites(t *testing.T) {
	m := NewMasker([]string{fakeValue})
	text := "head " + fakeValue + " mid " + base64.StdEncoding.EncodeToString([]byte(fakeValue)) + " tail"
	want := maskStream(m, text)
	if want != "head *** mid *** tail" {
		t.Fatalf("single write: %q", want)
	}
	for k := 0; k <= len(text); k++ {
		if got := maskStream(m, text[:k], text[k:]); got != want {
			t.Fatalf("split at %d: got %q", k, got)
		}
	}
	var one []string
	for i := 0; i < len(text); i++ {
		one = append(one, text[i:i+1])
	}
	if got := maskStream(m, one...); got != want {
		t.Fatalf("byte by byte: got %q", got)
	}
}

// What is held back for a possible match is released at Close.
func TestMaskCloseReleasesHeldTail(t *testing.T) {
	m := NewMasker([]string{"abcdefgh"})
	var out bytes.Buffer
	w := m.NewWriter(&out)
	_, _ = w.Write([]byte("xx abcdef"))
	if got := out.String(); got != "xx " {
		t.Errorf("before Close: %q (the partial match should be held)", got)
	}
	_ = w.Close()
	if got := out.String(); got != "xx abcdef" {
		t.Errorf("after Close: %q", got)
	}
}

func TestMaskApply(t *testing.T) {
	m := NewMasker([]string{"abcdefgh"})
	if got := string(m.Apply([]byte("a abcdefgh b"))); got != "a *** b" {
		t.Errorf("got %q", got)
	}
}

// Compare the streaming filter with a plain leftmost-longest replace, on random
// text and random splits.
func TestMaskStreamingMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	m := NewMasker([]string{"abababab", "aabbaabbab", "bbbbbbbb", "abab" + "baba"})
	var all [][]byte
	for _, l := range m.byFirst {
		all = append(all, l...)
	}
	reference := func(s []byte) string {
		var out []byte
		for i := 0; i < len(s); {
			best := 0
			for _, n := range all {
				if len(n) > best && bytes.HasPrefix(s[i:], n) {
					best = len(n)
				}
			}
			if best > 0 {
				out = append(out, Mask...)
				i += best
				continue
			}
			out = append(out, s[i])
			i++
		}
		return string(out)
	}
	for iter := 0; iter < 2000; iter++ {
		n := rng.Intn(60)
		text := make([]byte, n)
		for i := range text {
			text[i] = "ab \n"[rng.Intn(4)]
		}
		want := reference(text)
		var chunks []string
		for rest := text; len(rest) > 0; {
			k := 1 + rng.Intn(len(rest))
			chunks = append(chunks, string(rest[:k]))
			rest = rest[k:]
		}
		if got := maskStream(m, chunks...); got != want {
			t.Fatalf("text %q chunks %q: got %q want %q", text, chunks, got, want)
		}
	}
}

func TestMaskWriterPropagatesDestinationError(t *testing.T) {
	m := NewMasker([]string{"abcdefgh"})
	w := m.NewWriter(failWriter{})
	if _, err := w.Write([]byte("hello")); err == nil {
		t.Error("a failing destination must surface from Write")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, bytes.ErrTooLarge }

// checkAtEverySplit asserts that masking text gives want in one write, split in
// two at every position, and one byte at a time.
func checkAtEverySplit(t *testing.T, m *Masker, text, want string) {
	t.Helper()
	if got := maskStream(m, text); got != want {
		t.Fatalf("one write: got %q want %q", got, want)
	}
	for k := 0; k <= len(text); k++ {
		if got := maskStream(m, text[:k], text[k:]); got != want {
			t.Fatalf("split at %d: got %q want %q", k, got, want)
		}
	}
	var one []string
	for i := 0; i < len(text); i++ {
		one = append(one, text[i:i+1])
	}
	if got := maskStream(m, one...); got != want {
		t.Fatalf("byte by byte: got %q want %q", got, want)
	}
}

// A value stored with a trailing newline (or spaces) is usually printed without
// it, for example inside an Authorization header.
func TestMaskTrimmedValue(t *testing.T) {
	for _, stored := range []string{"tok_FAKE0123456789\n", "tok_FAKE0123456789\r\n", "  tok_FAKE0123456789  ", "\ttok_FAKE0123456789\n\n"} {
		m := NewMasker([]string{stored})
		// No newline after the token, so only the trimmed form can match.
		checkAtEverySplit(t, m, "Authorization: Bearer tok_FAKE0123456789 end", "Authorization: Bearer *** end")
		// Its encodings are masked too.
		b64 := base64.StdEncoding.EncodeToString([]byte("tok_FAKE0123456789"))
		checkAtEverySplit(t, m, "x "+b64+" y "+url.QueryEscape("tok_FAKE0123456789")+" z", "x *** y *** z")
		// The value exactly as stored is still masked.
		checkAtEverySplit(t, m, "a "+stored+"b", "a ***b")
	}
}

// A PEM file printed one line at a time is masked line by line, even when the
// output arrives in pieces.
func TestMaskEachLineOfAMultiLineValue(t *testing.T) {
	const (
		begin = "-----BEGIN FAKE PRIVATE KEY-----"
		l1    = "MIIFAKEFAKEFAKE0123456789abcdefGHIJKLMNOP"
		l2    = "qrstuvwxyzFAKEFAKE+/0123456789ABCDEFGH=="
		short = "ab12" // under 8 characters: never a needle
		end   = "-----END FAKE PRIVATE KEY-----"
	)
	pem := begin + "\n" + l1 + "\n" + l2 + "\n" + short + "\n" + end + "\n"
	m := NewMasker([]string{pem})
	if m.Short != 0 {
		t.Errorf("Short = %d: the whole value is long enough", m.Short)
	}

	text := "key: " + begin + "\nkey: " + l1 + "\nkey: " + l2 + "\nkey: " + short + "\nkey: " + end + "\n"
	want := "key: ***\nkey: ***\nkey: ***\nkey: ab12\nkey: ***\n"
	checkAtEverySplit(t, m, text, want)

	// A line on its own, in the other forms.
	checkAtEverySplit(t, m, "<"+base64.StdEncoding.EncodeToString([]byte(l1))+">", "<***>")
	checkAtEverySplit(t, m, "<"+url.QueryEscape(l2)+">", "<***>")
	// The value printed whole, and inside a JSON string, is still masked.
	checkAtEverySplit(t, m, "["+pem+"]", "[***]")
	checkAtEverySplit(t, m, `{"key":"`+jsonInner(pem, true)+`"}`, `{"key":"***"}`)
	// Text that merely resembles a line is left alone.
	checkAtEverySplit(t, m, "MIIFAKE ab12 -----BEGIN-----", "MIIFAKE ab12 -----BEGIN-----")
}

func TestMaskMultiLineWithWindowsLineEndingsAndBlankLines(t *testing.T) {
	m := NewMasker([]string{"first_FAKE_line_001\r\n\r\nsecond_FAKE_line_002\r\nx\r\n"})
	checkAtEverySplit(t, m, "a first_FAKE_line_001 b second_FAKE_line_002\r\n", "a *** b ***\r\n")
	checkAtEverySplit(t, m, "just x here", "just x here")
}

// Every needle keeps the 8-character minimum, and the note still counts values
// whose trimmed form is too short.
func TestMaskKeepsTheMinimumForEveryNeedle(t *testing.T) {
	// 7 characters once trimmed: the trimmed form is not masked and is counted.
	m := NewMasker([]string{"abcdefg\n"})
	if m.Short != 1 {
		t.Errorf("Short = %d, want 1", m.Short)
	}
	if got := maskStream(m, "abcdefg ok"); got != "abcdefg ok" {
		t.Errorf("a 7-character trimmed value must not be masked: %q", got)
	}
	// Lines under 8 characters are not needles, so a value made of such lines is
	// masked only when printed whole.
	m = NewMasker([]string{"abc\ndefg\nhijk\nlmno"})
	if m.Short != 0 {
		t.Errorf("Short = %d: the trimmed value has 18 characters", m.Short)
	}
	if got := maskStream(m, "abc defg hijk lmno"); got != "abc defg hijk lmno" {
		t.Errorf("short lines must not be masked: %q", got)
	}
	if got := maskStream(m, "[abc\ndefg\nhijk\nlmno]"); got != "[***]" {
		t.Errorf("the whole value is masked: %q", got)
	}
	// A value of only whitespace has an empty trimmed form.
	if m = NewMasker([]string{"          "}); m.Short != 1 {
		t.Errorf("whitespace-only value: Short = %d, want 1", m.Short)
	}
	// One long line and one short line: only the long one is a needle.
	m = NewMasker([]string{"longenough_FAKE_line\nshort"})
	checkAtEverySplit(t, m, "longenough_FAKE_line short", "*** short")
}

// Lines are trimmed too: an indented line (YAML, a key file with leading spaces)
// is printed without its indentation.
func TestMaskTrimsEachLineOfAMultiLineValue(t *testing.T) {
	m := NewMasker([]string{"  indented_FAKE_line_1  \n\tindented_FAKE_line_2\t\nx"})
	checkAtEverySplit(t, m, "a indented_FAKE_line_1 b indented_FAKE_line_2 c", "a *** b *** c")
}

// bigValue is a 64 KB value of 7,000 distinct eight-character lines, the shape
// that used to produce about 21,000 needles and scan about 300 times slower.
func bigValue() (value string, lines []string) {
	var sb strings.Builder
	for i := 0; i < 7000; i++ {
		line := fmt.Sprintf("ln%06d", i) // exactly 8 characters
		lines = append(lines, line)
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String(), lines
}

// How many needles one value can produce, at most: the whole value, the trimmed
// value and MaxLineNeedles lines, each in at most this many encodings.
const maxFormsPerSource = 12

// The cost of the scan grows with the number of needles, so the number of lines
// that get a needle of their own is capped. This asserts the count, not the time,
// so it cannot be flaky.
func TestMaskCapsTheNeedlesOfAHugeMultiLineValue(t *testing.T) {
	value, _ := bigValue()
	if len(value) < 60*1024 {
		t.Fatalf("the fixture should be about 64 KB, it is %d bytes", len(value))
	}
	m := NewMasker([]string{value})
	if limit := (2 + MaxLineNeedles) * maxFormsPerSource; m.count > limit {
		t.Errorf("%d needles, want at most %d: the per-line needles are not capped", m.count, limit)
	}
	// Without a cap there would be one needle per line and encoding, more than ten times this.
	if m.count == 0 || m.count > 4000 {
		t.Errorf("%d needles for a 7,000-line value", m.count)
	}
	// Two such values (two fields of a secret) give at most twice as many.
	other := strings.ReplaceAll(value, "ln", "xy")
	if two := NewMasker([]string{value, other}); two.count > 2*(2+MaxLineNeedles)*maxFormsPerSource {
		t.Errorf("%d needles for two huge values", two.count)
	}
	if got := len(longestLines(value)); got != MaxLineNeedles {
		t.Errorf("longestLines returned %d lines, want %d", got, MaxLineNeedles)
	}
}

// The first lines are still masked on their own, so the cap loses only the tail.
// Lines of equal length are taken in the order they appear.
func TestMaskStillMasksTheFirstLinesOfAHugeValue(t *testing.T) {
	value, lines := bigValue()
	m := NewMasker([]string{value})
	for _, i := range []int{0, 1, 100, MaxLineNeedles - 1} {
		if got := maskStream(m, "x "+lines[i]+" y"); got != "x *** y" {
			t.Errorf("line %d should be masked, got %q", i, got)
		}
	}
	// A line past the cap is not masked individually...
	last := lines[len(lines)-1]
	if got := maskStream(m, "x "+last+" y"); got != "x "+last+" y" {
		t.Errorf("line %d is beyond the cap and should not be masked on its own, got %q", len(lines)-1, got)
	}
	// ... but the value as a whole, and without its final line break, still is.
	if got := maskStream(m, "["+value+"]"); got != "[***]" {
		t.Errorf("the whole value must still be masked: %q", got[:min(len(got), 40)])
	}
	if got := maskStream(m, "["+strings.TrimSpace(value)+"]"); got != "[***]" {
		t.Errorf("the trimmed value must still be masked: %q", got[:min(len(got), 40)])
	}
}

// When a value has more than the cap, the longest lines are the ones kept.
func TestMaskKeepsTheLongestLinesWhenOverTheCap(t *testing.T) {
	var sb strings.Builder
	var long []string
	for i := 0; i < MaxLineNeedles+50; i++ {
		sb.WriteString(fmt.Sprintf("short%04d\n", i)) // 9 characters
	}
	for i := 0; i < 10; i++ {
		l := fmt.Sprintf("a_much_longer_line_number_%02d", i)
		long = append(long, l)
		sb.WriteString(l + "\n")
	}
	m := NewMasker([]string{sb.String()})
	for _, l := range long {
		if got := maskStream(m, "<"+l+">"); got != "<***>" {
			t.Errorf("the long line %q should be masked: %q", l, got)
		}
	}
	// 316 lines in all: the 10 long ones and the first 246 short ones are kept.
	if got := maskStream(m, "<short0000>"); got != "<***>" {
		t.Errorf("an early short line should be masked: %q", got)
	}
	if got := maskStream(m, fmt.Sprintf("<short%04d>", MaxLineNeedles+49)); got == "<***>" {
		t.Errorf("a late short line is past the cap and should not be masked on its own")
	}
}

// Repeated lines count once, so a value that repeats one line does not use up the cap.
func TestMaskCountsRepeatedLinesOnce(t *testing.T) {
	v := strings.Repeat("same_repeated_line\n", 1000) + "other_distinct_line\n"
	if got := len(longestLines(v)); got != 2 {
		t.Errorf("longestLines = %d lines, want 2", got)
	}
}
