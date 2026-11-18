// Package cli implements the `agentruntime` command tree on top of Platform MCP.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
	"github.com/agentruntime-io/agentruntime-cli/internal/mcpclient"
	"github.com/agentruntime-io/agentruntime-cli/internal/render"
	"github.com/agentruntime-io/agentruntime-cli/internal/version"
)

// Exit codes. Scripts can branch on these after `run --wait` / `await` / `approve`.
const (
	ExitOK        = 0
	ExitError     = 1
	ExitUsage     = 2
	ExitAwaiting  = 3 // workflow is waiting on a human approval gate
	defaultTimout = 6 * time.Minute
)

// ExitErr carries a process exit code. Err may be nil for "silent" exits.
type ExitErr struct {
	Code int
	Err  error
}

func (e *ExitErr) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}
func (e *ExitErr) Unwrap() error { return e.Err }

type globalFlags struct {
	profile string
	url     string
	pat     string
	json    bool
	noColor bool
	timeout time.Duration
	yes     bool // the global --yes: say yes to what a command would ask (login --device: an API host outside agentruntime.io)
	// allowOtherHost lets a command send the saved short-lived key to a host other than the one that issued it. It is its own
	// flag, apart from --yes: confirming a prompt must never also lift that refusal.
	allowOtherHost bool
}

// App holds IO and lazily-created connection state shared by all commands.
type App struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer

	flags    globalFlags
	cfg      *config.File
	resolved config.Resolved
	client   *mcpclient.Client
	stdout   render.Style
	stderr   render.Style

	// Test seams. isTTYOut overrides the "is standard output a terminal" check and
	// signalSource replaces the OS signal channel while `secrets run` waits.
	isTTYOut     func() bool
	signalSource <-chan os.Signal
	now          func() time.Time // the clock; nil means time.Now
	// sleep replaces the wait between polls of `login --device`; openURL replaces the browser opener.
	sleep   func(ctx context.Context, d time.Duration) error
	openURL func(address string) error
	// hostTrusted replaces the rule for which API hosts need no confirmation (the loopback hosts are never a real server
	// in a test of the confirmation).
	hostTrusted func(host string) bool

	warnedKeyHost bool // the warning about a key issued by another host was printed
}

// nowTime is the current time, from the test clock when one is set.
func (a *App) nowTime() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// NewApp creates an App bound to the given streams.
func NewApp(in io.Reader, out, errw io.Writer) *App {
	return &App{In: in, Out: out, Err: errw}
}

// Main runs the CLI and returns the process exit code.
func Main(args []string) int {
	app := NewApp(os.Stdin, os.Stdout, os.Stderr)
	return app.Run(args)
}

// Run executes the command tree with args and returns an exit code.
func (a *App) Run(args []string) int {
	root := a.Root()
	root.SetArgs(args)
	root.SetOut(a.Out)
	root.SetErr(a.Err)
	defer a.close()

	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	var ee *ExitErr
	if errors.As(err, &ee) {
		if ee.Err != nil {
			fmt.Fprintf(a.Err, "%s %v\n", a.stderr.Red("error:"), ee.Err)
		}
		return ee.Code
	}
	fmt.Fprintf(a.Err, "%s %v\n", a.stderr.Red("error:"), err)
	return ExitError
}

func (a *App) close() {
	if a.client != nil {
		_ = a.client.Close()
		a.client = nil
	}
}

// Root builds the cobra command tree.
func (a *App) Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "agentruntime",
		Short: "AgentRuntime CLI — drive the Platform MCP from your terminal",
		Long: `agentruntime is a command-line client for AgentRuntime Platform MCP
(https://mcp.agentruntime.io/mcp). Run workflows, approve human tasks, browse the
connector catalog, manage tenant data, secrets and PATs — or call any
Platform MCP tool directly with "agentruntime tools call".

Get started:
  agentruntime login          # paste a personal access token (PAT)
  agentruntime whoami         # confirm workspace and projects
  agentruntime workflows list
  agentruntime run <workflow-id> --wait

Use a secret in a script without a .env file:
  agentruntime secrets run --env KEY=workspace/live/stripe#API_KEY -- python job.py

Configuration precedence: flags > environment (AGENTRUNTIME_PAT,
AGENTRUNTIME_MCP_URL, AGENTRUNTIME_PROFILE) > saved profile > defaults.`,
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("agentruntime {{.Version}}\n")

	pf := root.PersistentFlags()
	pf.StringVar(&a.flags.profile, "profile", "", "config profile to use (default: current profile)")
	pf.StringVar(&a.flags.url, "url", "", "Platform MCP endpoint (default "+config.DefaultURL+")")
	pf.StringVar(&a.flags.pat, "pat", "", "personal access token (prefer 'agentruntime login' or AGENTRUNTIME_PAT)")
	pf.BoolVar(&a.flags.json, "json", false, "print raw JSON instead of formatted output")
	pf.BoolVar(&a.flags.noColor, "no-color", false, "disable coloured output")
	pf.DurationVar(&a.flags.timeout, "timeout", defaultTimout, "overall timeout for the command")
	pf.BoolVar(&a.flags.yes, "yes", false, "say yes to what a command would ask (login --device: an API host outside agentruntime.io)")
	pf.BoolVar(&a.flags.allowOtherHost, "allow-other-host", false, "send a saved short-lived key to a host other than the one that issued it (refused without this; --yes does not do it)")

	root.PersistentPreRun = func(cmd *cobra.Command, _ []string) {
		a.stdout = render.NewStyle(a.Out, a.flags.noColor)
		a.stderr = render.NewStyle(a.Err, a.flags.noColor)
	}

	root.AddCommand(
		a.loginCmd(), a.logoutCmd(), a.whoamiCmd(), a.profileCmd(), a.statusCmd(),
		a.toolsCmd(), a.callCmd(),
		a.workflowsCmd(), a.runCmd(), a.awaitCmd(), a.inspectCmd(), a.approveCmd(true), a.approveCmd(false),
		a.runsCmd(), a.tasksCmd(),
		a.catalogCmd(), a.tenantDataCmd(), a.secretsCmd(), a.patsCmd(), a.analyticsCmd(), a.projectsCmd(),
		a.upgradeCmd(), a.versionCmd(),
	)
	return root
}

// context returns a cancellable context honouring --timeout and Ctrl-C.
func (a *App) context(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	base := cmd.Context()
	if base == nil {
		base = context.Background()
	}
	sigCtx, stop := signal.NotifyContext(base, os.Interrupt)
	if a.flags.timeout <= 0 {
		return sigCtx, stop
	}
	ctx, cancel := context.WithTimeout(sigCtx, a.flags.timeout)
	return ctx, func() { cancel(); stop() }
}

func (a *App) loadConfig() error {
	if a.cfg != nil {
		return nil
	}
	f, err := config.Load()
	if err != nil {
		return err
	}
	a.cfg = f
	a.resolved = f.Resolve(config.Overrides{Profile: a.flags.profile, URL: a.flags.url, Token: a.flags.pat})
	return nil
}

// connect opens (once) the MCP session using the resolved settings.
func (a *App) connect(ctx context.Context) (*mcpclient.Client, error) {
	if a.client != nil {
		return a.client, nil
	}
	if err := a.loadConfig(); err != nil {
		return nil, err
	}
	if a.resolved.Token == "" && !isLocalURL(a.resolved.URL) {
		return nil, &ExitErr{Code: ExitError, Err: errors.New("not logged in: run `agentruntime login` or set AGENTRUNTIME_PAT")}
	}
	if err := a.checkKeyHostForMCP(); err != nil {
		return nil, err
	}
	c, err := mcpclient.Connect(ctx, a.resolved.URL, a.resolved.Token)
	if err != nil {
		return nil, err
	}
	a.client = c
	return c, nil
}

// invoke connects and calls a tool, returning decoded data.
// When progress is true, MCP progress notifications are echoed to stderr.
func (a *App) invoke(cmd *cobra.Command, tool string, args map[string]any, progress bool) (any, error) {
	ctx, cancel := a.context(cmd)
	defer cancel()
	c, err := a.connect(ctx)
	if err != nil {
		return nil, err
	}
	if progress && !a.flags.json {
		c.OnProgress(func(msg string, p, total float64) {
			if msg == "" {
				return
			}
			fmt.Fprintf(a.Err, "%s %s\n", a.stderr.Dim("…"), msg)
		})
		defer c.OnProgress(nil)
	}
	res, err := c.Call(ctx, tool, args, progress)
	if err != nil {
		return nil, a.explain(err)
	}
	return res.Data, nil
}

func (a *App) explain(err error) error {
	var te *mcpclient.ToolError
	if errors.As(err, &te) {
		return fmt.Errorf("%s: %s", te.Tool, te.Message)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timed out after %s (raise --timeout)", a.flags.timeout)
	}
	if errors.Is(err, context.Canceled) {
		return &ExitErr{Code: 130, Err: errors.New("cancelled")}
	}
	return err
}

// emit prints data as JSON (--json) or in the smart human format.
func (a *App) emit(data any) error {
	if a.flags.json {
		return render.JSON(a.Out, data)
	}
	if m, ok := data.(map[string]any); ok && render.IsOutcome(m) {
		render.Outcome(a.Out, a.stdout, m, render.OutcomeOptions{ShowOutputs: true, Hints: true})
		return nil
	}
	render.Auto(a.Out, a.stdout, data)
	return nil
}

// emitOutcome prints a workflow outcome. When mapExit is true the process exit
// code reflects the outcome (1 failed/stopped, 3 awaiting approval) so scripts can branch.
func (a *App) emitOutcome(data any, showOutputs, mapExit bool) error {
	m, ok := data.(map[string]any)
	if a.flags.json || !ok || !render.IsOutcome(m) {
		if err := a.emit(data); err != nil {
			return err
		}
	} else {
		render.Outcome(a.Out, a.stdout, m, render.OutcomeOptions{ShowOutputs: showOutputs, Hints: true})
	}
	if ok && mapExit {
		switch m["outcome"] {
		case "failed", "stopped":
			return &ExitErr{Code: ExitError}
		case "awaiting_input":
			return &ExitErr{Code: ExitAwaiting}
		}
	}
	return nil
}

// simple builds a command that calls one tool and prints the result.
func (a *App) call1(cmd *cobra.Command, tool string, args map[string]any) error {
	data, err := a.invoke(cmd, tool, args, false)
	if err != nil {
		return err
	}
	return a.emit(data)
}

func isLocalURL(u string) bool {
	for _, p := range []string{"http://127.0.0.1", "http://localhost", "http://[::1]"} {
		if len(u) >= len(p) && u[:len(p)] == p {
			return true
		}
	}
	return false
}
