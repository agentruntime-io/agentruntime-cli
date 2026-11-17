package secrets

// Templates for `agentruntime secrets render`: a Go text/template whose secret references are all known before
// anything is fetched.
//
// The rule that makes this safe to run is that every reference is a quoted string written out in the template.
// ParseTemplate walks the parsed template, collects each argument of secret and fields, and refuses anything it
// cannot read as a literal (a variable, a pipeline result, a parenthesised expression, a function used as a
// value). So the list of secrets a template reads is fixed by its text, one call can carry them all, and no
// template can decide at run time to read something it did not name.
//
// A template runs AFTER the fetch, when a one-use key is already spent, so it is held to limits. These are limits
// on what the template can do, not a promise about the memory or time of every template:
//
//   - Refused when the template is read (see template_limits.go): a cycle among the templates, a call to a template
//     that does not exist, nesting and call chains past a cap (a stack overflow cannot be caught), a number above
//     MaxIntLiteral, loops over written-out numbers nested past MaxLoopProduct, a printf format that could build a
//     huge string.
//   - Enforced while it runs: the functions that build text stop one value at MaxValueBytes and all of it at
//     MaxTotalBytes, printf and its relatives take no map, the output stops at MaxRenderedBytes, and the whole run
//     stops after ExecTimeout.
//   - Not limited: a loop that builds no text, or whose count is not a number written in the template (a variable, a
//     length, a loop split across templates), runs until the deadline, and a run that has been stopped keeps going in
//     the background until the process exits.
//
// Nothing in this file talks to the network or prints anything.

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
	"unicode/utf8"
)

// MaxTemplateBytes is the largest template `secrets render` reads.
const MaxTemplateBytes = 1 << 20

// MaxRenderedBytes is the most a template may produce. The values of one call are capped at 64 KB, so only a
// template that loops over them can come near it.
const MaxRenderedBytes = 8 << 20

// The functions a template may call. index is redefined (see strictIndex); the rest are text/template's own.
const (
	fnSecret = "secret"
	fnFields = "fields"
)

// TemplateValue is one fetched answer: a string for a reference with #field, an object of fields for a whole
// secret.
type TemplateValue struct {
	String   string
	Fields   map[string]string
	IsObject bool
}

// Template is a parsed template and the references it reads.
type Template struct {
	name string
	text string
	tmpl *template.Template
	refs []string          // distinct normalized references, in the order they first appear in the text
	lit  map[string]string // function name + NUL + literal as written -> normalized reference
}

// TemplateError says what is wrong with a template. It names a line, never the text on it.
type TemplateError struct{ Msg string }

func (e *TemplateError) Error() string { return e.Msg }

func tmplErrf(format string, args ...any) error {
	return &TemplateError{Msg: fmt.Sprintf(format, args...)}
}

// ParseTemplate parses text and collects its references. name is used in error messages (a file name).
func ParseTemplate(name, text string) (*Template, error) {
	t := &Template{name: name, text: text, lit: map[string]string{}}
	tm, err := t.parse(nil)
	if err != nil {
		return nil, &TemplateError{Msg: strings.TrimSpace(err.Error())}
	}
	t.tmpl = tm

	c := &collector{t: t, src: text, seen: map[string]bool{}, calls: map[string][]call{}}
	// The main template and every {{define}} / {{block}} body are separate trees; each one is read. The main one
	// comes first and the others by name, so the order of Refs does not depend on map order.
	all := tm.Templates()
	sort.Slice(all, func(i, j int) bool {
		if (all[i] == tm) != (all[j] == tm) {
			return all[i] == tm
		}
		return all[i].Name() < all[j].Name()
	})
	for _, one := range all {
		if one.Tree == nil || one.Tree.Root == nil {
			continue
		}
		c.cur = one.Name()
		if err := c.walk(one.Tree.Root, 1); err != nil {
			return nil, err
		}
	}
	// Which templates call which is known only now. A cycle would run until the stack of the program overflows, which
	// nothing can catch, so it is refused here, before anything is fetched.
	if err := c.checkCalls(); err != nil {
		return nil, err
	}
	return t, nil
}

// Refs returns the distinct references the template reads, normalized as they are sent to the server, in the
// order they first appear.
func (t *Template) Refs() []string { return append([]string(nil), t.refs...) }

// parse builds the template for a set of answers (nil while collecting references, when nothing runs).
func (t *Template) parse(vals map[string]TemplateValue) (*template.Template, error) {
	return template.New(t.name).Option("missingkey=error").Funcs(t.funcs(vals, &budget{})).Parse(t.text)
}

// Execute renders the template with the fetched values, keyed by normalized reference. The whole output is built
// in memory; on any error nothing is returned.
//
// The run has a deadline (ExecTimeout) and an output cap (MaxRenderedBytes), and its functions cannot grow a string
// past MaxValueBytes. An error NEVER carries text from the template engine: the engine's own messages can quote a
// fetched value (ranging over a string prints it), so what comes back is a fixed sentence and the line number, and
// nothing a value could be in.
func (t *Template) Execute(values map[string]TemplateValue) ([]byte, error) {
	answers := make(map[string]TemplateValue, len(values))
	for k, v := range values {
		answers[k] = v // the Fields maps are only read, and fields hands out a copy
	}
	// A template of its own for this run: a run that outlives its deadline keeps reading what it was given. Its
	// functions share one budget, which is what limits all the text they build in this run, added up.
	tm, err := template.New(t.name).Option("missingkey=error").Funcs(t.funcs(answers, &budget{})).Parse(t.text)
	if err != nil {
		return nil, tmplErrf("internal error: the template could not be prepared to run")
	}
	w := &cappedBuffer{max: MaxRenderedBytes}
	done := make(chan error, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- errRunPanicked
			}
		}()
		done <- tm.Execute(w, map[string]any{})
	}()
	timer := time.NewTimer(execTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return nil, execError(err)
		}
		return w.buf.Bytes(), nil
	case <-timer.C:
		// The run cannot be interrupted, only abandoned; the command ends right after, which ends it.
		return nil, tmplErrf("the template ran for more than %s and was stopped (does a loop never end?); nothing was written", execTimeout)
	}
}

// MinScrubLen is the shortest value Scrub replaces without the Masker's help; shorter ones are too likely to be a
// piece of ordinary text.
const MinScrubLen = 3

// Scrub returns text with every value in values replaced by ***: through the Masker (a value of MinMaskLen
// characters or more, in its plain, base64, URL-encoded and JSON-escaped forms), and then, for a shorter value of
// MinScrubLen characters or more, wherever it appears as it is. It is for text that a library built and that may
// have quoted a value, such as an error message.
func Scrub(text string, values []string) string {
	text = string(NewMasker(values).Apply([]byte(text)))
	short := make([]string, 0, len(values))
	for _, v := range values {
		if n := utf8.RuneCountInString(v); n >= MinScrubLen && n < MinMaskLen {
			short = append(short, v)
		}
	}
	sort.Slice(short, func(i, j int) bool { return len(short[i]) > len(short[j]) })
	for _, v := range short {
		text = strings.ReplaceAll(text, v, Mask)
	}
	return text
}

// ---- the functions ----------------------------------------------------------------------------

// funcs are the functions a template may call, for one set of answers.
func (t *Template) funcs(vals map[string]TemplateValue, b *budget) template.FuncMap {
	m := template.FuncMap{
		fnSecret: func(ref string) (string, error) {
			v, err := t.value(vals, fnSecret, ref)
			if err != nil {
				return "", err
			}
			if v.IsObject {
				return "", fixed("unexpected answer from the server (wrong kind of value)")
			}
			return sized(v.String)
		},
		fnFields: func(ref string) (map[string]string, error) {
			v, err := t.value(vals, fnFields, ref)
			if err != nil {
				return nil, err
			}
			if !v.IsObject {
				return nil, fixed("unexpected answer from the server (wrong kind of value)")
			}
			// The map itself, not a copy: a template has nothing that changes a map (range, index, json and .NAME only
			// read one), and a copy per call would be memory the budget does not count (thousands of
			// {{ $v := fields "REF" }} would each hold a copy of the whole secret).
			return v.Fields, nil
		},
		"index": strictIndex,
	}
	for name, fn := range boundedFuncs(b) {
		m[name] = fn
	}
	return m
}

// value looks up what the server answered for a literal reference the walk collected.
func (t *Template) value(vals map[string]TemplateValue, fn, literal string) (TemplateValue, error) {
	key, ok := t.lit[fn+"\x00"+literal]
	if !ok {
		// Unreachable for a template that ParseTemplate accepted: every literal was collected.
		return TemplateValue{}, fixed("internal error: a reference was not collected before the template ran")
	}
	v, ok := vals[key]
	if !ok {
		return TemplateValue{}, fixed("the server did not answer for every reference; nothing was written")
	}
	return v, nil
}

// strictIndex is index for the one thing this template language can index: the map fields returns. Unlike the
// built-in, a name that is not in the secret is an error, not an empty string, so a missing field can never turn
// into an empty value in a config file. Use it for a field name that is not a plain identifier, such as
// {{ index (fields "workspace/app") "db-pass" }}.
func strictIndex(item any, name string) (string, error) {
	m, ok := item.(map[string]string)
	if !ok {
		return "", fixed("index works only on the result of fields")
	}
	v, ok := m[name]
	if !ok {
		// The name is not repeated: it may have been taken from another secret.
		return "", fixed("the secret has no field with that name")
	}
	return v, nil
}

// ---- reading the references out of the parse tree --------------------------------------------

type collector struct {
	t     *Template
	src   string
	seen  map[string]bool
	cur   string            // the template whose body is being read
	depth int               // how deep if, range and with are nested at this point of that body
	calls map[string][]call // which templates each template calls ({{ template "name" }})
}

// call is one {{ template "to" }}, and the line it is on.
type call struct {
	to   string
	line int
}

func (c *collector) line(pos parse.Pos) int {
	if int(pos) > len(c.src) {
		pos = parse.Pos(len(c.src))
	}
	return 1 + strings.Count(c.src[:pos], "\n")
}

// walk reads a node. loops is how many times it can run at most, counting only loops over a number written out in
// the template (range 5): the product of those around it.
func (c *collector) walk(n parse.Node, loops int64) error {
	switch n := n.(type) {
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, x := range n.Nodes {
			if err := c.walk(x, loops); err != nil {
				return err
			}
		}
		return nil
	case *parse.ActionNode:
		return c.pipe(n.Pipe)
	case *parse.IfNode:
		return c.branch(&n.BranchNode, loops)
	case *parse.RangeNode:
		inner := loops
		if times := literalRange(n.Pipe); times > 1 {
			if inner *= times; inner > MaxLoopProduct {
				return tmplErrf("line %d: loops over numbers written in the template are nested more than %d iterations deep in all; "+
					"the template would not finish, and its key is already spent by then", c.line(n.Position()), MaxLoopProduct)
			}
		}
		return c.branch(&n.BranchNode, inner)
	case *parse.WithNode:
		return c.branch(&n.BranchNode, loops)
	case *parse.TemplateNode:
		// The named template must exist: a typo would otherwise be found only when the run reaches it, after the fetch.
		if c.t.tmpl.Lookup(n.Name) == nil {
			return tmplErrf("line %d: {{ template }} names a template that is not defined in this file (check the spelling against its {{ define }}); "+
				"this would only be found after the fetch", c.line(n.Position()))
		}
		c.calls[c.cur] = append(c.calls[c.cur], call{to: n.Name, line: c.line(n.Position())})
		if n.Pipe != nil {
			return c.pipe(n.Pipe)
		}
		return nil
	case *parse.TextNode, *parse.CommentNode, *parse.BreakNode, *parse.ContinueNode:
		return nil
	}
	// A kind of node this code does not know (a newer Go may add one) could hide a call: refuse rather than guess.
	return tmplErrf("line %d: the template uses a construct this version cannot check, so it was not run", c.line(n.Position()))
}

func (c *collector) branch(b *parse.BranchNode, loops int64) error {
	if c.depth++; c.depth > MaxNesting {
		return tmplErrf("line %d: if, range and with are nested more than %d deep", c.line(b.Position()), MaxNesting)
	}
	defer func() { c.depth-- }()
	if err := c.pipe(b.Pipe); err != nil {
		return err
	}
	if err := c.walk(b.List, loops); err != nil {
		return err
	}
	return c.walk(b.ElseList, loops)
}

// checkCalls refuses a template that calls itself, directly or through other templates (a depth-first search of the
// calls found while reading), and a chain of calls longer than MaxCallDepth.
func (c *collector) checkCalls() error {
	names := make([]string, 0, len(c.calls))
	for name := range c.calls {
		names = append(names, name)
	}
	sort.Strings(names)

	const (
		onPath = 1
		done   = 2
	)
	state := map[string]int{}
	longest := map[string]int{} // the most templates in a row that start at this one, itself included
	var visit func(name string) (int, error)
	visit = func(name string) (int, error) {
		if state[name] == done {
			return longest[name], nil
		}
		state[name] = onPath
		deepest := 0
		for _, cl := range c.calls[name] {
			if state[cl.to] == onPath {
				return 0, tmplErrf("line %d: this {{ template }} calls a template that is already running (a template that calls itself, "+
					"directly or through others, would never finish, and that would only show after the fetch)", cl.line)
			}
			d, err := visit(cl.to)
			if err != nil {
				return 0, err
			}
			if d > deepest {
				deepest = d
			}
		}
		state[name] = done
		longest[name] = deepest + 1
		return longest[name], nil
	}
	for _, name := range names {
		d, err := visit(name)
		if err != nil {
			return err
		}
		if d > MaxCallDepth {
			return tmplErrf("templates call each other more than %d deep in a row", MaxCallDepth)
		}
	}
	return nil
}

func (c *collector) pipe(p *parse.PipeNode) error {
	if p == nil {
		return nil
	}
	for i, cmd := range p.Cmds {
		if err := c.command(p, i, cmd); err != nil {
			return err
		}
	}
	return nil
}

func isRefFunc(name string) bool { return name == fnSecret || name == fnFields }

func (c *collector) command(p *parse.PipeNode, i int, cmd *parse.CommandNode) error {
	if len(cmd.Args) == 0 {
		return nil
	}
	if id, ok := cmd.Args[0].(*parse.IdentifierNode); ok && isRefFunc(id.Ident) {
		return c.refCall(p, i, cmd, id)
	}
	// A printf whose format is written out is checked now, before the fetch; one built at run time is checked when it runs.
	if id, ok := cmd.Args[0].(*parse.IdentifierNode); ok && id.Ident == "printf" && len(cmd.Args) > 1 {
		if format, ok := cmd.Args[1].(*parse.StringNode); ok {
			if err := checkFormat(format.Text); err != nil {
				return tmplErrf("line %d: printf: %v", c.line(id.Position()), err)
			}
		}
	}
	for _, a := range cmd.Args {
		if err := c.arg(a); err != nil {
			return err
		}
	}
	return nil
}

// arg checks an argument of any other command: a parenthesised pipeline is read like any pipeline, and secret or
// fields used as a plain value (so that it would run with no reference of its own) is refused.
func (c *collector) arg(a parse.Node) error {
	switch a := a.(type) {
	case *parse.IdentifierNode:
		if isRefFunc(a.Ident) {
			return tmplErrf("line %d: %s must be called with a quoted reference, for example {{ %s \"workspace/app\" }}",
				c.line(a.Position()), a.Ident, a.Ident)
		}
	case *parse.PipeNode:
		return c.pipe(a)
	case *parse.ChainNode:
		return c.arg(a.Node)
	case *parse.NumberNode:
		if tooBig(a) {
			return tmplErrf("line %d: a number larger than %d in a template action; it can only be a loop or a width that would not finish. "+
				"Write it as plain text outside {{ }}, or as a quoted string", c.line(a.Position()), MaxIntLiteral)
		}
	}
	return nil
}

// refCall reads one call of secret or fields: {{ secret "REF#F" }} or {{ "REF#F" | secret }}, and nothing else.
func (c *collector) refCall(p *parse.PipeNode, i int, cmd *parse.CommandNode, id *parse.IdentifierNode) error {
	line := c.line(id.Position())
	var literal *parse.StringNode
	switch {
	case len(cmd.Args) == 2 && i == 0:
		literal, _ = cmd.Args[1].(*parse.StringNode)
	case len(cmd.Args) == 1 && i > 0:
		prev := p.Cmds[i-1]
		if len(prev.Args) == 1 {
			literal, _ = prev.Args[0].(*parse.StringNode)
		}
	}
	if literal == nil {
		return tmplErrf("line %d: %s takes one reference written out as a quoted string, not a variable, a pipeline result or an expression, so that every secret the template reads is known before anything is fetched", line, id.Ident)
	}

	ref, err := Parse(literal.Text)
	if err != nil {
		// The reference's own error never repeats it (see RefError); the line says where.
		return tmplErrf("line %d: %s: %v", line, id.Ident, err)
	}
	switch id.Ident {
	case fnSecret:
		if ref.Whole() {
			return tmplErrf("line %d: secret reads one field, so its reference needs #FIELD; to read every field of a secret use fields", line)
		}
	case fnFields:
		if !ref.Whole() {
			return tmplErrf("line %d: fields reads a whole secret, so its reference must not have #FIELD; to read one field use secret", line)
		}
	}
	norm := ref.String()
	c.t.lit[id.Ident+"\x00"+literal.Text] = norm
	if !c.seen[norm] {
		c.seen[norm] = true
		c.t.refs = append(c.t.refs, norm)
	}
	return nil
}

// ---- output cap ---------------------------------------------------------------------------------

var errTooLarge = errors.New("output too large")

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		return 0, errTooLarge
	}
	return w.buf.Write(p)
}
