package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/bffclient"
	"github.com/agentruntime-io/agentruntime-cli/internal/secrets"
)

// Shell conventions for a command that did not run.
const (
	exitNotExecutable = 126
	exitNotFound      = 127
)

type runOpts struct {
	envs, envFrom, files []string
	apiURL               string
	passKey              bool
}

// keyEnvVars are the variables that carry the CLI's own access key. The command that `secrets run` starts does not
// receive them unless --pass-key is given, so the key does not end up in its environment or in its logs by accident
// (the key may be allowed to fetch more than the command was started with). This is accident prevention, not a
// security boundary: a child running as the same user can still read the key file, or the environment of the
// agentruntime process itself (/proc/$PPID/environ on Linux).
var keyEnvVars = []string{"AGENTRUNTIME_PAT"}

type envSpec struct {
	name string
	ref  secrets.Ref
}

// envFromField is one field the person named under --env-from, and the variable
// it sets.
type envFromField struct {
	variable string
	ref      secrets.Ref // the field, as asked of the server
}

// fileField is one field the person named for a --secret-file.
type fileField struct {
	name string
	ref  secrets.Ref
}

type fileSpec struct {
	path   string
	format secrets.FileFormat
	whole  *secrets.Ref // a .json file may take the whole secret: no field was named
	fields []fileField  // otherwise, only these fields are written
}

// runPlan is everything `secrets run` needs, validated before anything is fetched.
type runPlan struct {
	envs    []envSpec
	envFrom []envFromField
	files   []fileSpec
	refs    []string // distinct, normalized, in first-seen order
}

func (a *App) secretsRunCmd() *cobra.Command {
	var o runOpts
	cmd := &cobra.Command{
		Use:   "run [flags] -- command [args...]",
		Short: "Run a command with secrets in its environment or in files (nothing printed or left behind)",
		Long: `Fetches the referenced secrets in ONE call, starts the command with them, and
passes its exit code through. A value is never printed, never part of the
command line, and never written to disk unless you ask for --secret-file.

  --env NAME=REF#FIELD    one variable (NAME) from one field
  --env-from REF#F1,F2    one variable per field YOU name: the field name,
                          upper-cased (db_pass sets DB_PASS). Only the named
                          fields are fetched, and what else the secret holds
                          never becomes a variable, so a field someone adds to
                          the secret later cannot change how the command runs.
                          REF alone, or REF#*, is refused. A name must be plain
                          ASCII letters, digits and _, and must not start with
                          AGENTRUNTIME_. For another variable name use
                          --env NAME=REF#FIELD.
  --secret-file PATH=REF  a secret as a file. Removed when the command ends,
                          also on a signal or a failure. An existing file is
                          never overwritten. Owner-only on macOS and Linux; on
                          Windows it keeps the permissions of its folder.
                            .env or *.env  dotenv: name the fields, REF#F1,F2,
                                           and only those are written (a
                                           program that loads a dotenv file
                                           turns every key into a variable).
                                           A value that bash, docker compose
                                           and python-dotenv would read
                                           differently is refused: use a .json
                                           file for it.
                            *.json         JSON: REF writes the whole secret,
                                           REF#F1,F2 only those fields.

Each field you name is one reference, and one call carries at most 20.

The values come from the workspace the access key belongs to. For a key made by
agentruntime login --device that is the workspace that APPROVED the sign-in, shown
when you signed in: not necessarily yours. Only run login --device yourself, and
only approve your own sign-ins, because a value from someone else's workspace (one you
map to PATH or NODE_OPTIONS, say) would change how the command runs.

Put -- before the command. An explicit --env wins over a variable from
--env-from. Variables replace the ones already in the environment.

The command does not receive AGENTRUNTIME_PAT (your access key), so the key does
not end up in its environment or its logs by accident. That is accident
prevention, not a barrier: a program running as you can still read the key file
or the environment of the agentruntime process itself (/proc/$PPID/environ on
Linux). Add --pass-key if the command runs agentruntime itself and needs the key.

The command's standard output and standard error are filtered: every fetched
value, its whitespace-trimmed form, each line of a multi-line value (a PEM file
printed line by line), and the base64, URL-encoded and JSON-escaped forms of
these are replaced with ***. Pieces shorter than 8 characters are not masked
(the CLI says so once on standard error when a value is that short). A value is
masked line by line for at most 256 distinct lines (the longest first); lines
beyond that are not masked individually, the value as a whole still is. Not
masked: hex, a changed case, base64 broken over several lines, base64 of
"user:value", and anything else the command transforms. Standard input and the
exit code pass through untouched. Because the output is filtered the command
sees pipes, not a terminal, on standard output and standard error. Masking is
accident prevention only (a script that prints its environment); it cannot stop
a program that wants to leak a value it holds.

The key needs the "Fetch secret values" scope (secrets:fetch) and the secrets
on its list. --timeout limits the fetch, not the command. The command is not
started at all when a reference cannot be resolved (all or nothing).`,
		Example: `  agentruntime secrets run --env STRIPE_KEY=workspace/live/stripe#API_KEY -- python job.py
  agentruntime secrets run --env-from workspace/live/stripe#API_KEY,WEBHOOK_SECRET -- ./deploy.sh
  agentruntime secrets run --secret-file .env=workspace/live/app#DB_USER,DB_PASS -- docker compose up
  agentruntime secrets run --secret-file creds.json=my/gcp -- terraform plan`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			switch {
			case dash < 0:
				return &ExitErr{Code: ExitUsage, Err: errors.New("put -- before the command, for example: agentruntime secrets run --env KEY=REF -- python job.py")}
			case dash > 0:
				return &ExitErr{Code: ExitUsage, Err: errors.New("unexpected arguments before --")}
			case len(args) == 0:
				return &ExitErr{Code: ExitUsage, Err: errors.New("missing command after --")}
			}
			return a.secretsRun(cmd, o, args)
		},
	}
	cmd.Flags().StringArrayVar(&o.envs, "env", nil, "NAME=REF#FIELD: set one variable from one field (repeatable)")
	cmd.Flags().StringArrayVar(&o.envFrom, "env-from", nil, "REF#F1,F2: set one variable per field you name, called after the field in upper case; REF alone or REF#* is refused (repeatable)")
	cmd.Flags().StringArrayVar(&o.files, "secret-file", nil, "PATH=REF: write a secret to a .env or .json file, removed when the command ends; a .env file needs REF#F1,F2, a .json file may take the whole REF (repeatable; owner-only except on Windows)")
	cmd.Flags().StringVar(&o.apiURL, "api-url", "", apiURLHelp)
	cmd.Flags().BoolVar(&o.passKey, "pass-key", false, "let the command inherit AGENTRUNTIME_PAT (off by default; keeping the key out is accident prevention, not a barrier)")
	return cmd
}

// buildRunPlan validates every --env, --env-from and --secret-file value. Errors
// name the flag and the variable or path, never the reference text. Everything
// that can be checked from the command line is checked here, before the fetch,
// so a mistake does not use up one of a limited key's uses.
func buildRunPlan(o runOpts) (*runPlan, error) {
	p := &runPlan{}
	var all []secrets.Ref

	names := map[string]bool{}
	for _, spec := range o.envs {
		name, refText, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, errors.New("--env expects NAME=REF#FIELD")
		}
		name = strings.TrimSpace(name)
		if !secrets.ValidEnvName(name) {
			return nil, fmt.Errorf("--env %s: not a valid variable name (letters, digits and _, not starting with a digit)", name)
		}
		if names[name] {
			return nil, fmt.Errorf("--env %s is given twice", name)
		}
		names[name] = true
		ref, err := parseRef("--env "+name, refText)
		if err != nil {
			return nil, err
		}
		if ref.Whole() {
			return nil, fmt.Errorf("--env %s: the reference has no #field; add #FIELD for one value, or use --env-from REF#F1,F2 for several", name)
		}
		p.envs = append(p.envs, envSpec{name: name, ref: ref})
		all = append(all, ref)
	}

	// The variables --env-from sets, so two of them cannot collide.
	vars := map[string]string{}
	for i, text := range o.envFrom {
		label := fmt.Sprintf("--env-from #%d", i+1)
		named, err := secrets.ParseNamed(text)
		if err != nil {
			return nil, envFromRefError(label, err)
		}
		for j, ref := range named.Refs() {
			variable, err := secrets.EnvFromName(ref.Field)
			switch {
			case errors.Is(err, secrets.ErrEnvNameNotPlain):
				return nil, fmt.Errorf("%s: field %d is not a plain ASCII name (letters, digits and _, not starting with a digit), so it cannot name a variable; for another variable name use --env NAME=REF#FIELD", label, j+1)
			case errors.Is(err, secrets.ErrEnvNameReserved):
				return nil, fmt.Errorf("%s: field %d would set %s: names starting with %s are reserved for this tool's own settings; for another variable name use --env NAME=REF#FIELD", label, j+1, variable, secrets.ReservedPrefix)
			case err != nil:
				return nil, fmt.Errorf("%s: field %d: %w", label, j+1, err)
			}
			here := fmt.Sprintf("field %d of %s", j+1, label)
			if prev, dup := vars[variable]; dup {
				return nil, fmt.Errorf("--env-from: %s and %s would both set %s (names that differ only in case give the same variable)", prev, here, variable)
			}
			vars[variable] = here
			p.envFrom = append(p.envFrom, envFromField{variable: variable, ref: ref})
			all = append(all, ref)
		}
	}

	paths := map[string]bool{}
	for _, spec := range o.files {
		path, refText, ok := strings.Cut(spec, "=")
		path = strings.TrimSpace(path)
		if !ok || path == "" {
			return nil, errors.New("--secret-file expects PATH=REF")
		}
		format, err := secrets.FormatForPath(path)
		if err != nil {
			return nil, fmt.Errorf("--secret-file %s: %w", path, err)
		}
		clean := filepath.Clean(path)
		if paths[clean] {
			return nil, fmt.Errorf("--secret-file %s is given twice", path)
		}
		paths[clean] = true
		fs, err := buildFileSpec(path, format, refText)
		if err != nil {
			return nil, err
		}
		// Fail before fetching, so a refused file does not use up a one-time key.
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("--secret-file %s already exists; refusing to overwrite it (remove it first)", path)
		}
		if st, err := os.Stat(filepath.Dir(path)); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("--secret-file %s: the folder does not exist", path)
		}
		p.files = append(p.files, fs)
		if fs.whole != nil {
			all = append(all, *fs.whole)
		}
		for _, f := range fs.fields {
			all = append(all, f.ref)
		}
	}

	if len(all) == 0 {
		return nil, errors.New("nothing to fetch: give at least one --env, --env-from or --secret-file")
	}
	p.refs = uniqueRefs(all)
	if len(p.refs) > secrets.MaxRefsPerCall {
		return nil, tooManyRefs(len(p.refs))
	}
	return p, nil
}

// envFromRefError explains a --env-from value that does not name fields. It
// tells the person what to write, and never repeats what they wrote.
func envFromRefError(label string, err error) error {
	switch {
	case errors.Is(err, secrets.ErrNoFieldNames):
		return fmt.Errorf("%s: name the fields to set, for example --env-from REF#DB_USER,DB_PASS (one variable per field, called after the field in upper case). "+
			"The fields a secret happens to hold never decide what becomes a variable. For another variable name use --env NAME=REF#FIELD", label)
	case errors.Is(err, secrets.ErrWildcardFields):
		return fmt.Errorf("%s: '*' is not accepted: name each field, for example --env-from REF#DB_USER,DB_PASS. "+
			"The fields a secret happens to hold never decide what becomes a variable. For another variable name use --env NAME=REF#FIELD", label)
	}
	return fmt.Errorf("%s: %w", label, err)
}

// buildFileSpec reads the REF of one --secret-file. A dotenv file must name the
// fields to write: whatever program loads it turns every key into a variable, so
// the secret's own list of fields must not decide what goes in. A JSON file is
// not loaded into an environment, so it may take the whole secret.
func buildFileSpec(path string, format secrets.FileFormat, refText string) (fileSpec, error) {
	label := "--secret-file " + path
	fs := fileSpec{path: path, format: format}
	named, err := secrets.ParseNamed(refText)
	switch {
	case err == nil:
		for j, ref := range named.Refs() {
			if format == secrets.FormatDotenv {
				switch err := secrets.DotenvKey(ref.Field); {
				case errors.Is(err, secrets.ErrEnvNameNotPlain):
					return fs, fmt.Errorf("%s: field %d cannot be a key in a dotenv file: use plain ASCII letters, digits and _, not starting with a digit (a '.' or '-' is not a shell variable name); a .json file takes any field name", label, j+1)
				case errors.Is(err, secrets.ErrEnvNameReserved):
					return fs, fmt.Errorf("%s: field %d cannot be a key in a dotenv file: names starting with %s are reserved for this tool's own settings", label, j+1, secrets.ReservedPrefix)
				case err != nil:
					return fs, fmt.Errorf("%s: field %d: %w", label, j+1, err)
				}
			}
			fs.fields = append(fs.fields, fileField{name: ref.Field, ref: ref})
		}
		return fs, nil
	case errors.Is(err, secrets.ErrNoFieldNames) && format == secrets.FormatJSON:
		// A .json file may hold the whole secret: REF with no '#'. (A '#' with
		// nothing after it is still refused, by parseRef.)
		ref, err := parseRef(label, refText)
		if err != nil {
			return fs, err
		}
		fs.whole = &ref
		return fs, nil
	case errors.Is(err, secrets.ErrNoFieldNames), errors.Is(err, secrets.ErrWildcardFields):
		if format == secrets.FormatJSON {
			return fs, fmt.Errorf("%s: '*' is not accepted: leave out '#*' to write the whole secret, or name the fields, REF#F1,F2", label)
		}
		return fs, fmt.Errorf("%s: a dotenv file needs the fields to write, for example --secret-file %s=REF#DB_USER,DB_PASS. "+
			"The program that loads a dotenv file turns every key into a variable, so the fields a secret happens to hold must not decide what is written. "+
			"A .json file may take the whole secret", label, path)
	}
	return fs, fmt.Errorf("%s: %w", label, err)
}

// environment builds the variables to set from the fetched values.
func (p *runPlan) environment(values map[string]bffclient.Value) (map[string]string, error) {
	env := map[string]string{}
	for _, f := range p.envFrom {
		v := values[f.ref.String()]
		if v.IsObject {
			return nil, errors.New("unexpected answer from the server (a named field must be one value)")
		}
		env[f.variable] = v.String
	}
	for _, e := range p.envs {
		v := values[e.ref.String()]
		if v.IsObject {
			return nil, errors.New("unexpected answer from the server (--env needs one value)")
		}
		env[e.name] = v.String
	}
	return env, nil
}

// fileContents renders each --secret-file from the fetched values.
func (p *runPlan) fileContents(values map[string]bffclient.Value) ([][]byte, error) {
	out := make([][]byte, len(p.files))
	for i, f := range p.files {
		fields := map[string]string{}
		if f.whole != nil {
			v := values[f.whole.String()]
			if !v.IsObject {
				return nil, errors.New("unexpected answer from the server (--secret-file needs a whole secret)")
			}
			fields = v.Fields
		} else {
			for _, nf := range f.fields {
				v := values[nf.ref.String()]
				if v.IsObject {
					return nil, errors.New("unexpected answer from the server (a named field must be one value)")
				}
				fields[nf.name] = v.String
			}
		}
		b, err := secrets.Render(f.format, fields)
		if err != nil {
			return nil, fmt.Errorf("--secret-file %s: %w", f.path, err)
		}
		out[i] = b
	}
	return out, nil
}

// allValues lists every fetched value, for masking.
func allValues(values map[string]bffclient.Value) []string {
	var out []string
	for _, v := range values {
		if v.IsObject {
			for _, s := range v.Fields {
				out = append(out, s)
			}
		} else {
			out = append(out, v.String)
		}
	}
	return out
}

func (a *App) secretsRun(cmd *cobra.Command, o runOpts, command []string) error {
	plan, err := buildRunPlan(o)
	if err != nil {
		return &ExitErr{Code: ExitUsage, Err: err}
	}
	// Resolve the program first: a typo must not use up a fetch (and a one-time key).
	path, err := exec.LookPath(command[0])
	if err != nil {
		return &ExitErr{Code: exitNotFound, Err: fmt.Errorf("cannot run %q: %w", command[0], err)}
	}
	client, err := a.apiClient(o.apiURL)
	if err != nil {
		return err
	}
	values, err := a.fetch(cmd, client, plan.refs)
	if err != nil {
		return err
	}
	env, err := plan.environment(values)
	if err != nil {
		return &ExitErr{Code: ExitError, Err: err}
	}
	contents, err := plan.fileContents(values)
	if err != nil {
		return &ExitErr{Code: ExitError, Err: err}
	}
	masker := secrets.NewMasker(allValues(values))

	// Catch signals from here on, so one that arrives while files are being written
	// is handled once the command is running instead of killing us with files left.
	sigs, stopSignals := a.signals()
	defer stopSignals()

	var written secrets.Files
	defer func() {
		if err := written.RemoveAll(); err != nil {
			fmt.Fprintf(a.Err, "%s %v\n", a.stderr.Yellow("warning:"), err)
		}
	}()
	for i, f := range plan.files {
		if err := written.Write(f.path, contents[i]); err != nil {
			return &ExitErr{Code: ExitError, Err: fmt.Errorf("--secret-file %s: %w", f.path, err)}
		}
	}

	if masker.Short > 0 {
		fmt.Fprintf(a.Err, "%s %d fetched value(s) are shorter than %d characters and are not masked in the command's output\n",
			a.stderr.Yellow("note:"), masker.Short, secrets.MinMaskLen)
	}

	foldCase := runtime.GOOS == "windows"
	base := os.Environ()
	if !o.passKey {
		base = withoutEnv(base, keyEnvVars, foldCase)
	}
	code, err := a.execute(path, command, mergeEnv(base, env, foldCase), masker, sigs)
	if err != nil {
		return err
	}
	if code != 0 {
		return &ExitErr{Code: code}
	}
	return nil
}

// signals returns the channel that carries interrupt-style signals while a
// command runs.
func (a *App) signals() (<-chan os.Signal, func()) {
	if a.signalSource != nil {
		return a.signalSource, func() {}
	}
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	return ch, func() { signal.Stop(ch) }
}

// execute runs the command with its output filtered and returns its exit code.
// The first signal is forwarded to the command (on Windows a console Ctrl-C
// already reaches it); the second kills it. In every case this returns after
// the command has ended, so the caller can remove secret files.
func (a *App) execute(path string, command, env []string, masker *secrets.Masker, sigs <-chan os.Signal) (int, error) {
	c := exec.Command(path, command[1:]...)
	c.Args = append([]string{command[0]}, command[1:]...)
	c.Env = env
	c.Stdin = a.In
	// A grandchild that keeps the output pipe open must not hang us forever.
	c.WaitDelay = 5 * time.Second

	var stdout, stderr io.Writer = a.Out, a.Err
	var closers []*secrets.Writer
	if !masker.Empty() {
		so, se := masker.NewWriter(a.Out), masker.NewWriter(a.Err)
		stdout, stderr = so, se
		closers = []*secrets.Writer{so, se}
	}
	c.Stdout, c.Stderr = stdout, stderr

	if err := c.Start(); err != nil {
		return 0, &ExitErr{Code: exitNotExecutable, Err: fmt.Errorf("cannot start %q: %w", command[0], err)}
	}

	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	seen := 0
wait:
	for {
		select {
		case <-done:
			break wait
		case sig := <-sigs:
			seen++
			if seen == 1 {
				_ = c.Process.Signal(sig) // not supported on Windows: the console delivers it
			} else {
				_ = c.Process.Kill()
			}
		}
	}
	for _, w := range closers {
		_ = w.Close()
	}
	return exitCodeOf(c.ProcessState), nil
}

// exitCodeOf maps a finished process to a shell-style exit code (128+n when a
// signal ended it).
func exitCodeOf(ps *os.ProcessState) int {
	if ps == nil {
		return ExitError
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	if c := ps.ExitCode(); c >= 0 {
		return c
	}
	return ExitError
}

// mergeEnv returns base with set applied: a variable in set replaces an existing
// one of the same name (case-insensitively where foldCase is true, as on Windows).
func mergeEnv(base []string, set map[string]string, foldCase bool) []string {
	norm := func(k string) string {
		if foldCase {
			return strings.ToUpper(k)
		}
		return k
	}
	drop := make(map[string]bool, len(set))
	for k := range set {
		drop[norm(k)] = true
	}
	out := make([]string, 0, len(base)+len(set))
	for _, kv := range base {
		if drop[norm(envKey(kv))] {
			continue
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+set[k])
	}
	return out
}

// withoutEnv returns base without the named variables (case-insensitively where foldCase is true).
func withoutEnv(base []string, names []string, foldCase bool) []string {
	drop := make(map[string]bool, len(names))
	for _, n := range names {
		if foldCase {
			n = strings.ToUpper(n)
		}
		drop[n] = true
	}
	out := make([]string, 0, len(base))
	for _, kv := range base {
		k := envKey(kv)
		if foldCase {
			k = strings.ToUpper(k)
		}
		if drop[k] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// envKey returns the variable name of a KEY=value entry. Windows keeps entries
// such as "=C:=C:\dir" whose name starts with '='.
func envKey(kv string) string {
	if kv == "" {
		return ""
	}
	if i := strings.IndexByte(kv[1:], '='); i >= 0 {
		return kv[:i+1]
	}
	return kv
}
