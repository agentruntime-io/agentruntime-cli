package cli

// `agentruntime secrets render`: fill a config-file template with secrets and write the result.
//
// The template is a Go text/template. Every secret it reads is a quoted string written out in the template, so
// the whole list is known before anything is fetched, and ONE call to the API carries all of it (at most 20
// references). The template is then executed in memory with the answers. The file is written only when every
// reference resolved and the whole template ran: one bad reference and nothing is written.
//
// The rendered file holds the secrets in plain text and stays on disk. That is what it is for.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/render"
	"github.com/agentruntime-io/agentruntime-cli/internal/secrets"
)

const renderLong = `Fills a template with secrets and writes the result to a file, for a program
that wants its secrets in a config file. The template is a Go text/template:

  database_url = postgres://app:{{ secret "workspace/live/db#PASSWORD" }}@db.example.test/app
  stripe_key   = {{ secret "workspace/live/stripe#API_KEY" | quote }}
  {{ range $name, $value := fields "workspace/live/app" }}{{ $name }}={{ $value | quote }}
  {{ end }}

Functions
  secret "REF#FIELD"   one field of a secret, as text
  fields "REF"         every field of a secret as a map: range over it, or write
                       (fields "REF").NAME, or index (fields "REF") "odd-name"
  json                 a value as JSON: {{ secret "REF#F" | json }}
  b64enc               standard base64 of a string
  quote                a string in double quotes with Go escapes (as Helm's quote)
The usual text/template tools work too (printf, if, range, with, define). A name
that is not in the secret is an error, also with index, never an empty string. To
write a literal {{ put {{ "{{" }} in the template.

Every reference is written out as a quoted string in the template: not a
variable, not a pipeline result, not an expression. The CLI reads the template
first, collects them, and refuses anything else, so what a template can read is
fixed by its text. Names follow the same rules as the other secrets commands
(secret:, my/, project/, workspace/, a name with no room works only when one room
holds it). One call fetches them all, at most 20 different references, all or
nothing: if one cannot be resolved, nothing is written.

The result goes to --output PATH:
  - A new file is created with owner-only permissions (0600 on macOS and Linux; on
    Windows it keeps the permissions of its folder). An existing file is never
    overwritten.
  - --replace replaces an existing regular file: the new content is written to a
    new owner-only file next to it and renamed over it, so a reader sees the old
    file or the whole new one, and a failure leaves the old one. A link or a folder
    is refused. The template itself cannot be the output.
  - --output - prints the result, only when standard output is a terminal (control
    characters are shown as \xNN). Redirected or piped it refuses with exit code 2.

The rendered file contains your secrets in plain text and STAYS on disk: that is
its purpose. Keep it out of version control and remove it when you no longer need
it. 'secrets run --secret-file' is the one that removes its file when the command
ends. Whatever the template prints into the file is not masked.

A template runs after the fetch, when a one-use key is already spent, so it is held
to limits. Before anything is fetched the CLI refuses a template that calls itself
(directly or through other templates), calls a template that is not defined in the
file, nests if, range or with more than 50 deep or calls templates more than 100
deep in a row, writes a number above 1000000 inside {{ }}, nests loops over
written-out numbers past 1000000 iterations in all, or has a printf format with a
width or precision above 4096, a * or [n], a verb that does not end in a letter, or
more than 256 verbs.

While it runs, printf, print, println, html, js, urlquery, json, b64enc and quote
stop any one value at 1 MiB and all the text they build at 16 MiB, printf, print,
println, html, js and urlquery refuse a map of fields as an argument (use json, or
range), the output stops at 8 MiB, and the whole run stops after 10 seconds.
Nothing is written in any of these cases.

That is not a promise about every template's memory or time. What is limited is the
text those functions build, the output, and the 10 seconds. Not limited: a loop
that builds no text, or whose count does not come from a number written in the
template (a variable, a length, a loop split across templates), runs until the 10
seconds are up, and a run that is stopped keeps going in the background until the
command exits.

An error from a running template is a fixed sentence and the line number: the
template engine's own text can quote a secret's value, so none of it is shown.

The key needs the "Fetch secret values" scope (secrets:fetch) and the secrets on
its list.`

func (a *App) secretsRenderCmd() *cobra.Command {
	var output, apiURL string
	var replace bool
	cmd := &cobra.Command{
		Use:   "render <template> --output <path> [--replace]",
		Short: "Fill a config template with secrets and write the file (it stays on disk)",
		Long:  renderLong,
		Example: `  agentruntime secrets render app.conf.tmpl --output app.conf
  agentruntime secrets render app.conf.tmpl --output app.conf --replace
  agentruntime secrets render app.conf.tmpl --output -        # show it, on a terminal only`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.secretsRender(cmd, args[0], output, replace, apiURL)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "where to write the result (required); - prints it, on a terminal only")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace an existing file (atomically) instead of refusing")
	cmd.Flags().StringVar(&apiURL, "api-url", "", apiURLHelp)
	return cmd
}

// readTemplate reads the template file: a regular file of at most MaxTemplateBytes of valid UTF-8 text.
func readTemplate(path string) (string, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, errors.New("cannot read the template: " + errText(err))
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", nil, errors.New("cannot read the template: " + errText(err))
	}
	if !st.Mode().IsRegular() {
		return "", nil, errors.New("the template must be a regular file")
	}
	if st.Size() > secrets.MaxTemplateBytes {
		return "", nil, fmt.Errorf("the template is larger than %d MiB", secrets.MaxTemplateBytes>>20)
	}
	b, err := io.ReadAll(io.LimitReader(f, secrets.MaxTemplateBytes+1))
	if err != nil {
		return "", nil, errors.New("cannot read the template: " + errText(err))
	}
	if len(b) > secrets.MaxTemplateBytes {
		return "", nil, fmt.Errorf("the template is larger than %d MiB", secrets.MaxTemplateBytes>>20)
	}
	if !utf8.Valid(b) {
		return "", nil, errors.New("the template is not valid UTF-8 text")
	}
	return string(b), st, nil
}

// errText is an error's own text without the path the OS put in front of it (the person knows the path).
func errText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func (a *App) secretsRender(cmd *cobra.Command, templatePath, output string, replace bool, apiURL string) error {
	usage := func(format string, args ...any) error {
		return &ExitErr{Code: ExitUsage, Err: fmt.Errorf(format, args...)}
	}
	// Everything that can be checked without the server is checked first, so a mistake never uses up a key's uses
	// (a one-time key has exactly one).
	switch {
	case output == "":
		return usage("--output is required: a file path, or - to show the result on a terminal")
	case output == "-" && replace:
		return usage("--replace has no meaning with --output -")
	case output == "-" && a.flags.json:
		return usage("--json has nothing to add with --output -: the rendered text is printed as it is")
	case output == "-" && !a.stdoutIsTerminal():
		return usage("refusing to print rendered secrets: standard output is not a terminal. Write to a file with --output PATH")
	}

	text, tplInfo, err := readTemplate(templatePath)
	if err != nil {
		return usage("%v", err)
	}
	tm, err := secrets.ParseTemplate(filepath.Base(templatePath), text)
	if err != nil {
		return usage("%v", err)
	}
	refs := tm.Refs()
	switch {
	case len(refs) == 0:
		return usage("nothing to fetch: the template reads no secret (use {{ secret \"REF#FIELD\" }} or {{ fields \"REF\" }})")
	case len(refs) > secrets.MaxRefsPerCall:
		return &ExitErr{Code: ExitUsage, Err: tooManyRefs(len(refs))}
	}

	existed := false
	if output != "-" {
		if existed, err = checkRenderTarget(output, tplInfo, replace); err != nil {
			return usage("%v", err)
		}
	}

	client, err := a.apiClient(apiURL)
	if err != nil {
		return err
	}
	fetched, err := a.fetch(cmd, client, refs)
	if err != nil {
		return err
	}
	answers := make(map[string]secrets.TemplateValue, len(fetched))
	for ref, v := range fetched {
		answers[ref] = secrets.TemplateValue{String: v.String, Fields: v.Fields, IsObject: v.IsObject}
	}
	body, err := tm.Execute(answers)
	if err != nil {
		// Execute scrubs the fetched values from its message; the key is scrubbed here.
		return &ExitErr{Code: ExitError, Err: errors.New(secrets.Scrub(err.Error(), []string{a.resolved.Token}))}
	}

	if output == "-" {
		return a.printForTerminal(func(w io.Writer) error {
			_, err := w.Write(body)
			return err
		})
	}
	if replace {
		err = secrets.ReplaceOwnerOnly(output, body)
	} else {
		err = secrets.WriteOwnerOnly(output, body)
	}
	if err != nil {
		return &ExitErr{Code: ExitError, Err: err}
	}
	if a.flags.json {
		return render.JSON(a.Out, map[string]any{"written": output, "replaced": existed, "bytes": len(body), "references": len(refs)})
	}
	verb := "Wrote"
	if existed {
		verb = "Replaced"
	}
	fmt.Fprintf(a.Out, "%s %s (%d bytes, %d secret reference(s)). It holds your secrets in plain text and stays on disk.\n",
		verb, output, len(body), len(refs))
	return nil
}

// checkRenderTarget decides before anything is fetched whether the output file can be written. It reports whether a
// file is already there (which only --replace may replace).
func checkRenderTarget(output string, template os.FileInfo, replace bool) (existed bool, err error) {
	if st, err := os.Stat(filepath.Dir(output)); err != nil || !st.IsDir() {
		return false, fmt.Errorf("--output %s: the folder does not exist", output)
	}
	st, err := os.Lstat(output)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("--output %s: %s", output, errText(err))
	}
	if real, err := os.Stat(output); err == nil && os.SameFile(real, template) {
		return false, fmt.Errorf("--output %s is the template itself: it would be overwritten with the secrets in it", output)
	}
	switch {
	case !replace:
		return false, fmt.Errorf("--output %s already exists; refusing to overwrite it (remove it first, or use --replace)", output)
	case !st.Mode().IsRegular():
		return false, fmt.Errorf("--output %s is not a regular file (a folder or a link); refusing to replace it", output)
	}
	return true, nil
}
