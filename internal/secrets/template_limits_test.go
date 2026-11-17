package secrets

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A template runs after the fetch, when a one-use key is already spent. These tests hold it to three things: what
// can be refused without any value is refused when the template is read, a function cannot grow a string without
// end, and the run itself has a deadline and an output cap.

func TestTemplateRefusesExplosiveConstructsWhenItIsRead(t *testing.T) {
	for name, src := range map[string]string{
		"range over 3 billion":             `{{ range 3000000000 }}{{ end }}`,
		"range over the largest uint":      `{{ range 18446744073709551615 }}{{ end }}`,
		"range over 1000001":               `{{ range 1000001 }}x{{ end }}`,
		"big number in a variable":         `{{ $n := 3000000000 }}{{ range $n }}{{ end }}`,
		"big number as a printf argument":  `{{ printf "%d" 1000001 }}`,
		"big negative number":              `{{ printf "%d" -1000001 }}`,
		"big number in a define":           `{{ define "x" }}{{ range 5000000 }}{{ end }}{{ end }}`,
		"big number in an else branch":     `{{ if true }}{{ else }}{{ range 9999999 }}{{ end }}{{ end }}`,
		"nested loops, 1001 x 1000":        `{{ range 1001 }}{{ range 1000 }}{{ end }}{{ end }}`,
		"three nested loops":               `{{ range 200 }}{{ range 200 }}{{ range 200 }}{{ end }}{{ end }}{{ end }}`,
		"loops nested through if and with": `{{ range 1000 }}{{ if true }}{{ with "x" }}{{ range 1001 }}{{ end }}{{ end }}{{ end }}{{ end }}`,
		"printf width 5000":                `{{ printf "%5000d" 1 }}`,
		"printf width 999999999":           `{{ printf "%999999999d" 1 }}`,
		"printf precision":                 `{{ printf "%.9999s" "x" }}`,
		"printf star width":                `{{ printf "%*d" 5 1 }}`,
		"printf argument index":            `{{ printf "%[1]s%[1]s" "x" }}`,
		"printf 257 verbs":                 `{{ printf "` + strings.Repeat("%s", 257) + `" "x" }}`,
		"printf width piped in":            `{{ "x" | printf "%999999999s" }}`,
	} {
		_, err := ParseTemplate("t", src)
		var te *TemplateError
		if err == nil || !asTemplateError(err, &te) || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%s: %q was accepted or not refused with a line (err %v)", name, src, err)
		}
	}
	// The line is the one with the construct.
	_, err := ParseTemplate("t", "a\nb\n{{ range 3000000000 }}{{ end }}")
	if err == nil || !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), "1000000") {
		t.Errorf("err = %v", err)
	}
}

func asTemplateError(err error, target **TemplateError) bool {
	te, ok := err.(*TemplateError)
	*target = te
	return ok
}

func TestTemplateAcceptsOrdinaryNumbersLoopsAndFormats(t *testing.T) {
	for _, src := range []string{
		`{{ range 1000000 }}{{ end }}`,
		`{{ range 1000 }}{{ range 1000 }}{{ end }}{{ end }}`,
		`{{ range 1000 }}{{ end }}{{ range 1000 }}{{ end }}{{ range 1000 }}{{ end }}`, // side by side, not nested
		`{{ range 10 }}{{ range 10 }}{{ range 10 }}{{ range 10 }}{{ range 10 }}{{ range 10 }}{{ end }}{{ end }}{{ end }}{{ end }}{{ end }}{{ end }}`,
		`{{ printf "%d" 65535 }}`,
		`{{ printf "%s:%s" (secret "a/b#C") (secret "a/b#D") }}`,
		`{{ printf "%5.3f|%-10s|%04d|%x|%%|%v|%q" 1.5 "x" 7 255 "a" "b" }}`,
		`{{ printf "%4096s" "x" }}`,
		`{{ printf "` + strings.Repeat("%s", 256) + `" "x" }}`,
		`{{ if eq 1000000 1000000 }}x{{ end }}`,
		`{{ range $i, $v := fields "a/b" }}{{ end }}`,
		`plain 3000000000 text outside an action, and {{ "3000000000" }} as a string`,
	} {
		if _, err := ParseTemplate("t", src); err != nil {
			t.Errorf("%.60q refused: %v", src, err)
		}
	}
}

func TestCheckFormat(t *testing.T) {
	for format, ok := range map[string]bool{
		"": true, "plain": true, "%s": true, "%%": true, "100%%": true, "%5d": true, "%-5d": true, "%05d": true, "%.2f": true, "%8.3f": true,
		"%+v": true, "%# x": true, "%4096d": true, "%.4096s": true, "%s%s%s": true, "%": true, "100%": true,
		"%4097d": false, "%.4097s": false, "%99999999999999999999d": false, "%*d": false, "%.*f": false, "%-*d": false, "%[1]d": false,
		"%[3]*[2]d": false, "%5[1]d": false,
		// A verb that is not a letter ends where it is, and the percent sign after it opens a verb of its own with its
		// own width. fmt reads them that way, so the check must too: "%1+%999999d" is a width of 1, an unknown verb
		// "+", and then a verb with a width of 999999 (1000009 bytes written).
		"%1+%999999d": false, "%1+%4097d": false, "%1 %*d": false, "%1 %[1]d": false, "%1.%999999d": false, "%+%999999d": false,
		"%-%999999d": false, "%#%999999d": false, "% %999999d": false, "%0%999999d": false, "%5%999999d": false, "%.%999999d": false,
		"%5%": false, "%.5%": false, "%+%": false, "%1+": false, "%1!": false, "%!": false, "%é": false, "%1é": false, "%\x00": false, "%\n": false,
		"%1\t%5000d": false, "%1,%5000d": false, "%1;%5000d": false, "%2000%2000d": false, "%1_%5000d": false,
		"%\u00e9%5000d": false, "%1+%*d": false, "%1+%[1]d": false,
		// and what is fine
		"%5s%%": true, "100%% sure": true, "%-5s|%5s": true, "%+d": true, "% d": true, "%#x": true, "%06.2f": true, "%v": true, "%T": true,
		"%5": true, "%.": true, "%.5": true, "%+": true, "a%%b%%c": true, "%d%%%d": true, "%%%d": true, "%x%X%o%b%c%U%e%E%g%G%q%t%p": true,
		"%+-# 05.3f": true, "%4096.4096f": true, "%%%": true,
	} {
		if err := checkFormat(format); (err == nil) != ok {
			t.Errorf("checkFormat(%q) = %v, want ok=%v", format, err, ok)
		}
	}
	if checkFormat(strings.Repeat("%d", 256)) != nil || checkFormat(strings.Repeat("%d", 257)) == nil {
		t.Error("the limit is 256 verbs")
	}
	// %% is not a verb.
	if checkFormat(strings.Repeat("%%", 1000)) != nil {
		t.Error("%% is not a verb")
	}
}

// checkFormat must read a format the way fmt does. If it accepts a format, then what fmt.Sprintf builds from it must stay
// within the documented limits: no more than maxFormatWidth for any one verb besides the arguments themselves. The
// formats are made from the pieces of a verb (flags, widths, dots, stars, brackets, letters and junk in the place of the
// verb, literal percent signs), because a format of random bytes would almost never reach the combinations that
// matter ("%1+%9999d" is nine characters in an alphabet of dozens).
func TestCheckFormatAgreesWithFmtOnWhatItBuilds(t *testing.T) {
	flags := []string{"", "+", "-", "#", " ", "0", "+-", "#0", " +"}
	numbers := []string{"", "", "1", "5", "9", "99", "999", "4096", "4097", "9999", "99999", "999999", "1000000", "99999999999"}
	verbs := []string{"d", "s", "v", "x", "q", "f", "T", "t", "%", "+", "-", "#", " ", "0", "1", ".", "*", "[1]", "[2]", "!", "é", "\x00", ",", "_", "\n", "", "%d", "%5d"}
	// The arguments are short: whatever a verb writes beyond them is padding, and padding is what is limited.
	args := []any{1, "xx", 2.5, true, 7, "y", 3, "z", 4, "w"}
	rng := uint64(88172645463325252) // a fixed seed: the same formats on every run
	next := func(n int) int {
		rng ^= rng << 13
		rng ^= rng >> 7
		rng ^= rng << 17
		return int(rng % uint64(n))
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	tried, accepted := 0, 0
	for tried < 400000 && time.Now().Before(deadline) {
		var f strings.Builder
		for k, specs := 0, 1+next(4); k < specs; k++ {
			if next(5) == 0 {
				f.WriteString([]string{"%%", "ab", " ", "100%"}[next(4)])
				continue
			}
			f.WriteString("%" + flags[next(len(flags))] + numbers[next(len(numbers))])
			if next(3) == 0 {
				f.WriteString("." + numbers[next(len(numbers))])
			}
			f.WriteString(verbs[next(len(verbs))])
		}
		format := f.String()
		tried++
		if checkFormat(format) != nil {
			continue
		}
		accepted++
		out := fmt.Sprintf(format, args...)
		// Each % starts at most one verb, and a verb pads to at most maxFormatWidth (plus the few bytes of an argument).
		if limit := strings.Count(format, "%")*(maxFormatWidth+64) + len(format) + 256; len(out) > limit { // 256: the arguments a format leaves unused are listed after it
			t.Fatalf("checkFormat accepted %q, and fmt builds %d bytes from it (the limit for it is %d)", format, len(out), limit)
		}
	}
	if tried < 20000 || accepted < 1000 {
		t.Fatalf("only %d formats tried and %d accepted in the time given: the test is not exercising the check", tried, accepted)
	}
}

// A string that a loop feeds back into a function must not be able to grow without end: each function stops at
// 1 MiB. The sizes here are small enough that the check would not find a hang even without the limit: the loop is
// long enough to cross 1 MiB and short enough to finish quickly if the limit were missing.
func TestTemplateFunctionsStopAValueThatGrowsPastOneMiB(t *testing.T) {
	kb := strings.Repeat("x", 1024)
	amp := strings.Repeat("&", 64)
	bs := strings.Repeat(`\`, 1024)
	for name, src := range map[string]string{
		"printf doubles":  `{{ $s := "` + kb + `" }}{{ range 12 }}{{ $s = printf "%s%s" $s $s }}{{ end }}{{ len $s }}`,
		"print doubles":   `{{ $s := "` + kb + `" }}{{ range 12 }}{{ $s = print $s $s }}{{ end }}{{ len $s }}`,
		"println doubles": `{{ $s := "` + kb + `" }}{{ range 12 }}{{ $s = println $s $s }}{{ end }}{{ len $s }}`,
		"js grows":        `{{ $s := "` + amp + `" }}{{ range 16 }}{{ $s = js $s }}{{ end }}{{ len $s }}`,
		"quote doubles":   `{{ $s := "` + bs + `" }}{{ range 12 }}{{ $s = quote $s }}{{ end }}{{ len $s }}`,
		"json doubles":    `{{ $s := "` + bs + `" }}{{ range 12 }}{{ $s = json $s }}{{ end }}{{ len $s }}`,
		"b64enc grows":    `{{ $s := "` + kb + `" }}{{ range 30 }}{{ $s = b64enc $s }}{{ end }}{{ len $s }}`,
	} {
		tm, err := ParseTemplate("t", src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		start := time.Now()
		out, err := tm.Execute(nil)
		if err == nil || out != nil || !strings.Contains(err.Error(), "larger than 1 MiB") {
			t.Errorf("%s: out %d bytes, err %v: want the 1 MiB limit", name, len(out), err)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "the template failed at line 1: ") {
			t.Errorf("%s: error is not one of ours: %v", name, err)
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("%s: took %v", name, time.Since(start))
		}
	}
	// Short of the limit the same functions work.
	tm, _ := ParseTemplate("t", `{{ $s := "ab" }}{{ range 5 }}{{ $s = printf "%s%s" $s $s }}{{ end }}{{ len $s }}`)
	if out, err := tm.Execute(nil); err != nil || string(out) != "64" {
		t.Errorf("out %q err %v", out, err)
	}
}

// html, js and urlquery write a value out longer than they were given it; one call on a big value stops at the same
// limit (a loop that feeds their result back in grows only a little each time, so only one call can reach it).
func TestTemplateEscapersStopAtOneMiB(t *testing.T) {
	big := strings.Repeat("&", 400<<10) // 400 KiB, five times as long once html escapes it
	vals := map[string]TemplateValue{"a/b#C": {String: big}}
	for _, fn := range []string{"html", "js", "urlquery"} {
		tm, err := ParseTemplate("t", `{{ secret "a/b#C" | `+fn+` | len }}`)
		if err != nil {
			t.Fatal(err)
		}
		out, err := tm.Execute(vals)
		if err == nil || out != nil || !strings.Contains(err.Error(), "larger than 1 MiB") {
			t.Errorf("%s: out %d bytes, err %v", fn, len(out), err)
		}
	}
	// A value that stays under the limit is escaped as usual.
	tm, _ := ParseTemplate("t", `{{ html "a<b>&c" }}|{{ js "a'b" }}|{{ urlquery "a b&c" }}`)
	if out, err := tm.Execute(nil); err != nil || string(out) != `a&lt;b&gt;&amp;c|a\'b|a+b%26c` {
		t.Errorf("out %q err %v", out, err)
	}
}

// Arguments that are too big together are refused before the function writes them out; a format built at run time
// (from a variable, say) is held to the same limits as one written out.
func TestTemplateChecksWhatIsBuiltAtRunTime(t *testing.T) {
	big := strings.Repeat("x", 700<<10)
	vals := map[string]TemplateValue{"a/b#C": {String: big}}
	for name, src := range map[string]string{
		"two big arguments to printf": `{{ printf "%s%s" (secret "a/b#C") (secret "a/b#C") }}`,
		"two big arguments to print":  `{{ print (secret "a/b#C") (secret "a/b#C") }}`,
		"html of two":                 `{{ html (secret "a/b#C") (secret "a/b#C") }}`,
		"format from a variable":      `{{ $f := "%999999999d" }}{{ printf $f 1 }}`,
		"star width from a variable":  `{{ $f := "%*d" }}{{ printf $f 5 1 }}`,
		"index format from a string":  `{{ $f := "%[1]s%[1]s" }}{{ printf $f "x" }}`,
		// The arguments alone are over the limit, though little would be written: refused before anything is built.
		"big arguments, little written": `{{ printf "%.1s%.1s" (secret "a/b#C") (secret "a/b#C") }}`,
	} {
		tm, err := ParseTemplate("t", src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		start := time.Now()
		out, err := tm.Execute(vals)
		if err == nil || out != nil {
			t.Errorf("%s: out %d bytes, err %v: want a refusal", name, len(out), err)
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("%s: took %v", name, time.Since(start))
		}
		if err != nil && strings.Contains(err.Error(), "xxxx") {
			t.Errorf("%s: the error carries the value", name)
		}
	}
	// One big value on its own is fine, and so is a plain format.
	tm, _ := ParseTemplate("t", `{{ printf "%s" (secret "a/b#C") | len }}`)
	if out, err := tm.Execute(vals); err != nil || string(out) != fmt.Sprint(len(big)) {
		t.Errorf("out %q err %v", out, err)
	}
}

// The run has a deadline. The loop below is not refused when the template is read (its outer range is over a
// variable) and does nothing a function could stop, so only the deadline ends it.
func TestTemplateRunHasADeadline(t *testing.T) {
	old := execTimeout
	execTimeout = 100 * time.Millisecond
	t.Cleanup(func() { execTimeout = old })

	tm, err := ParseTemplate("t", `{{ $n := 1000000 }}{{ range $n }}{{ range 600 }}{{ end }}{{ end }}done`)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, err := tm.Execute(nil)
	took := time.Since(start)
	if err == nil || out != nil || !strings.Contains(err.Error(), "ran for more than 100ms and was stopped") || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("out %q err %v after %v", out, err, took)
	}
	if took > 3*time.Second {
		t.Errorf("the run was not stopped at its deadline: %v", took)
	}

	// A run that is abandoned does not disturb the next one.
	next, _ := ParseTemplate("t", `{{ secret "a/b#C" }}`)
	if out, err := next.Execute(map[string]TemplateValue{"a/b#C": {String: "fine"}}); err != nil || string(out) != "fine" {
		t.Errorf("next run: %q %v", out, err)
	}
}

// The output cap counts what the template produces as it is produced, so a loop that writes without end stops at the
// cap quickly, and nothing is returned.
func TestTemplateOutputCapStopsALoopThatWrites(t *testing.T) {
	tm, err := ParseTemplate("t", `{{ range 1000000 }}0123456789abcdef0123456789abcdef{{ end }}`)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, err := tm.Execute(nil)
	if err == nil || out != nil || !strings.Contains(err.Error(), "produces more than 8 MiB") {
		t.Fatalf("out %d bytes err %v", len(out), err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestExecErrorKindsAreFixedSentences(t *testing.T) {
	vals := map[string]TemplateValue{"a/b#C": {String: "SECRETVALUE-xyz"}, "a/b": {IsObject: true, Fields: map[string]string{"K": "SECRETVALUE-abc"}}}
	for src, want := range map[string]string{
		`{{ range (secret "a/b#C") }}{{ end }}`:         "range was used on text",
		`{{ (secret "a/b#C").X }}`:                      "a field was asked of a value that has none",
		`{{ (fields "a/b").NOPE }}`:                     "a name that is not in the secret was used",
		`{{ eq (secret "a/b#C") 3 }}`:                   "a function was given a value of the wrong type",
		`{{ index (fields "a/b") (secret "a/b#C") }}`:   "the secret has no field with that name",
		`{{ index (secret "a/b#C") "x" }}`:              "index works only on the result of fields",
		`{{ slice (secret "a/b#C") 1 100 }}`:            "a function refused its arguments",
		`{{ fields "a/b" | json | printf "%d" 1 2 3 }}`: "",
	} {
		tm, err := ParseTemplate("t", src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		_, err = tm.Execute(vals)
		if want == "" {
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "SECRETVALUE") || !strings.HasPrefix(err.Error(), "the template failed at line 1: ") {
			t.Errorf("%s: err = %v, want a fixed sentence with %q", src, err, want)
		}
	}
}

// The arguments of printf can be under the limit while what it writes is not (%x doubles its argument), so its result
// is bounded on its own, not only its arguments.
func TestTemplatePrintfResultIsBoundedEvenWhenItsArgumentsAreNot(t *testing.T) {
	vals := map[string]TemplateValue{"a/b#C": {String: strings.Repeat("x", 300<<10)}} // 300 KiB: two of them are 600 KiB
	tm, err := ParseTemplate("t", `{{ printf "%x%x" (secret "a/b#C") (secret "a/b#C") | len }}`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tm.Execute(vals)
	if err == nil || out != nil || !strings.Contains(err.Error(), "a value in the template grew larger than 1 MiB") {
		t.Errorf("out %d bytes, err %v: want the result limit, not the arguments limit", len(out), err)
	}
	// One %x of the same value is 600 KiB and fits.
	tm, _ = ParseTemplate("t", `{{ printf "%x" (secret "a/b#C") | len }}`)
	if out, err := tm.Execute(vals); err != nil || string(out) != fmt.Sprint(600<<10) {
		t.Errorf("out %q err %v", out, err)
	}
}

// The reported bypass, through the template: it is refused when the template is read (the format is written out), and
// also when the format is built at run time.
func TestTemplateRefusesTheFormatThatSlippedThroughTheCheck(t *testing.T) {
	for name, src := range map[string]string{
		"width after a junk verb": `{{ printf "%1+%999999d" 1 1 }}`,
		"star after a junk verb":  `{{ printf "%1 %*d" 1 5 1 }}`,
		"index after a junk verb": `{{ printf "%1 %[1]d" 1 }}`,
		"128 of the pairs":        `{{ printf "` + strings.Repeat("%1+%999999d", 128) + `" 1 1 }}`,
		"piped format":            `{{ "x" | printf "%1+%999999d" }}`,
	} {
		_, err := ParseTemplate("t", src)
		if err == nil || !strings.Contains(err.Error(), "line 1") || !strings.Contains(err.Error(), "printf") {
			t.Errorf("%s: err = %v: want a refusal when the template is read", name, err)
		}
	}
	// Built at run time, it meets the same check inside printf, before any string is built.
	for name, src := range map[string]string{
		"from a variable":   `{{ $f := "%1+%999999d" }}{{ printf $f 1 1 }}`,
		"from a variable 2": `{{ $f := "%1 %*d" }}{{ printf $f 1 5 1 }}`,
		"from a secret":     `{{ printf (secret "a/b#F") 1 1 }}`,
	} {
		tm, err := ParseTemplate("t", src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		start := time.Now()
		out, err := tm.Execute(map[string]TemplateValue{"a/b#F": {String: "%1+%999999d"}})
		if err == nil || out != nil || !strings.HasPrefix(err.Error(), "the template failed at line 1: printf: a verb in a format must end in a letter") && !strings.Contains(err.Error(), "from elsewhere") {
			t.Errorf("%s: out %d bytes err %v", name, len(out), err)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("%s: took %v", name, time.Since(start))
		}
	}
}

// ---- the total budget, and what printf may be given -----------------------------------------------------------------

// MaxValueBytes limits one value; the budget limits all of them together. A loop that builds many values of a size
// that is fine on its own (each call below builds 256 KiB, and none is kept) stops at 16 MiB in all.
func TestTemplateTotalOfAllBuiltTextIsLimited(t *testing.T) {
	chunk := strings.Repeat("x", 256<<10)
	tm, err := ParseTemplate("t", `{{ $b := "`+chunk+`" }}{{ range 70 }}{{ $x := printf "%s" $b }}{{ end }}done`)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, err := tm.Execute(nil)
	if err == nil || out != nil || !strings.Contains(err.Error(), "the template has built more than 16 MiB of text in all") ||
		!strings.HasPrefix(err.Error(), "the template failed at line 1: ") {
		t.Fatalf("out %d bytes err %v", len(out), err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	// Under the budget the same template is fine (60 x 256 KiB = 15 MiB), and the budget is for one run, not for all.
	tm, _ = ParseTemplate("t", `{{ $b := "`+chunk+`" }}{{ range 60 }}{{ $x := printf "%s" $b }}{{ end }}done`)
	for run := 0; run < 2; run++ {
		if out, err := tm.Execute(nil); err != nil || string(out) != "done" {
			t.Errorf("run %d: out %q err %v", run, out, err)
		}
	}
}

// Every function that builds text counts against the budget, not only printf.
func TestTemplateEveryBuilderCountsAgainstTheTotal(t *testing.T) {
	chunk := strings.Repeat("a", 512<<10)
	for _, call := range []string{`print $b`, `println $b`, `html $b`, `js $b`, `urlquery $b`, `json $b`, `b64enc $b`, `quote $b`, `printf "%s" $b`} {
		tm, err := ParseTemplate("t", `{{ $b := "`+chunk+`" }}{{ range 40 }}{{ $x := `+call+` }}{{ end }}`)
		if err != nil {
			t.Fatalf("%s: %v", call, err)
		}
		out, err := tm.Execute(nil)
		if err == nil || out != nil || !strings.Contains(err.Error(), "of text in all") {
			t.Errorf("%s: out %d bytes err %v: want the total limit", call, len(out), err)
		}
	}
}

// A map of fields given to printf with a width ("%4096v") is written out with that width for every key and value.
// printf, print, println, html, js and urlquery take text and numbers only; json and range are for maps.
func TestTemplateRefusesAMapOfFieldsAsAnArgumentOfTheTextFunctions(t *testing.T) {
	vals := map[string]TemplateValue{
		"a/b":   {IsObject: true, Fields: map[string]string{"K1": "v1", "K2": "v2", "K3": "v3"}},
		"a/b#C": {String: "text"},
	}
	for name, src := range map[string]string{
		"printf with a width":  `{{ printf "%4096v" (fields "a/b") }}`,
		"printf plain":         `{{ printf "%v" (fields "a/b") }}`,
		"printf after text":    `{{ printf "%s %v" "x" (fields "a/b") }}`,
		"print":                `{{ print (fields "a/b") }}`,
		"println":              `{{ println (fields "a/b") }}`,
		"html":                 `{{ html (fields "a/b") }}`,
		"js":                   `{{ js (fields "a/b") }}`,
		"urlquery":             `{{ urlquery (fields "a/b") }}`,
		"the data of the page": `{{ printf "%v" . }}`,
	} {
		tm, err := ParseTemplate("t", src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, err := tm.Execute(vals)
		if err == nil || out != nil || !strings.Contains(err.Error(), "a map of fields cannot be given to printf") {
			t.Errorf("%s: out %q err %v", name, out, err)
		}
	}
	// Text, numbers and truth values are fine, and json and range are the ways to use a map.
	tm, err := ParseTemplate("t", `{{ printf "%s|%d|%.1f|%t|%5s" (secret "a/b#C") 7 2.5 true "ab" }} {{ print "a" 1 true }} {{ json (fields "a/b") }} {{ range $k, $v := fields "a/b" }}{{ $k }}={{ $v }};{{ end }}`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tm.Execute(vals)
	want := `text|7|2.5|true|   ab a1 true {"K1":"v1","K2":"v2","K3":"v3"} K1=v1;K2=v2;K3=v3;`
	if err != nil || string(out) != want {
		t.Errorf("out %q err %v, want %q", out, err, want)
	}
}

// fields hands out the map itself: a template cannot change a map, and a copy for every call would be memory that no
// budget counts. 2000 variables each set from a secret of 2000 fields must not allocate a copy each.
func TestTemplateFieldsCopiesNothing(t *testing.T) {
	fields := map[string]string{}
	for i := 0; i < 2000; i++ {
		fields[fmt.Sprintf("FIELD_%04d", i)] = "value"
	}
	var src strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&src, `{{ $v%d := fields "a/b" }}`, i)
	}
	src.WriteString("done")
	tm, err := ParseTemplate("t", src.String())
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]TemplateValue{"a/b": {IsObject: true, Fields: fields}}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out, err := tm.Execute(vals)
	runtime.ReadMemStats(&after)
	if err != nil || string(out) != "done" {
		t.Fatalf("out %q err %v", out, err)
	}
	// With a copy per call this is about 2000 x 2000 entries, hundreds of MiB.
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 64<<20 {
		t.Errorf("2000 calls of fields allocated %d MiB", grown>>20)
	}
}
