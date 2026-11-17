package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
	"github.com/agentruntime-io/agentruntime-cli/internal/mcpclient"
	"github.com/agentruntime-io/agentruntime-cli/internal/render"
)

// reader returns a shared buffered reader over stdin.
func (a *App) reader() *bufio.Reader {
	if br, ok := a.In.(*bufio.Reader); ok {
		return br
	}
	br := bufio.NewReader(a.In)
	a.In = br
	return br
}

// isInteractive reports whether we can prompt the user.
func (a *App) isInteractive() bool {
	if f, ok := a.In.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return true // injected reader (tests)
}

func (a *App) readLine() (string, error) {
	s, err := a.reader().ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func (a *App) readSecret(prompt string) (string, error) {
	fmt.Fprint(a.Err, prompt)
	defer fmt.Fprintln(a.Err)
	if f, ok := a.In.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		return strings.TrimSpace(string(b)), err
	}
	return a.readLine()
}

// confirm asks a yes/no question. Defaults to "no".
func (a *App) confirm(prompt string) (bool, error) {
	if !a.isInteractive() {
		return false, errNeedTTY
	}
	fmt.Fprintf(a.Err, "%s [y/N] ", prompt)
	line, err := a.readLine()
	if err != nil {
		return false, err
	}
	switch strings.ToLower(line) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func (a *App) loginCmd() *cobra.Command {
	var token string
	var withToken, noVerify, device bool
	var dev deviceFlags
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Save a personal access token (PAT) for this profile, or sign in with a code (--device)",
		Long: `Stores a PAT (and optionally a custom MCP URL) in the CLI config and makes the
profile current. Create a PAT in the Console under Settings → API tokens.

  agentruntime login                          # hidden prompt
  agentruntime login --token pat_xxx          # non-interactive
  echo $PAT | agentruntime login --with-token # from stdin (CI)
  agentruntime login --profile dev --url http://127.0.0.1:8340/mcp
  agentruntime login --device --ref 'workspace/live/*'   # sign in with a code, see below

The token is stored in the config file with owner-only permissions. In CI prefer
the AGENTRUNTIME_PAT environment variable and skip login entirely.

--device signs in without pasting a key: the CLI prints a code, you approve it in
the Console, and a short-lived key that can only fetch secrets is saved in the
profile.

` + deviceLoginLong,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if device {
				if token != "" || withToken || noVerify {
					return &ExitErr{Code: ExitUsage, Err: errors.New("--device cannot be combined with --token, --with-token or --no-verify")}
				}
				dev.deviceNameSet = cmd.Flags().Changed("device-name")
				return a.loginDevice(cmd, dev)
			}
			for _, name := range deviceOnlyFlags {
				if cmd.Flags().Changed(name) {
					return &ExitErr{Code: ExitUsage, Err: fmt.Errorf("--%s only works with --device", name)}
				}
			}
			if err := a.loadConfig(); err != nil {
				return err
			}
			switch {
			case withToken:
				line, err := a.readLine()
				if err != nil {
					return fmt.Errorf("read token from stdin: %w", err)
				}
				token = line
			case token == "":
				if !a.isInteractive() {
					return errors.New("no token: pass --token, --with-token (stdin) or run in a terminal")
				}
				t, err := a.readSecret("Personal access token (input hidden): ")
				if err != nil {
					return err
				}
				token = t
			}
			token = strings.TrimSpace(token)
			if token == "" {
				return errors.New("empty token")
			}

			name := a.cfg.ProfileName(a.flags.profile)
			url := strings.TrimSpace(a.flags.url)
			if url == "" {
				if p := a.cfg.Profiles[name]; p != nil && p.URL != "" {
					url = p.URL
				} else {
					url = config.DefaultURL
				}
			}

			if !noVerify {
				ctx, cancel := a.context(cmd)
				defer cancel()
				c, err := mcpclient.Connect(ctx, url, token)
				if err != nil {
					return err
				}
				defer c.Close()
				res, err := c.Call(ctx, "ar_get_started", nil, false)
				if err != nil {
					return a.explain(err)
				}
				m := res.Map()
				if auth, ok := m["authenticated"].(bool); ok && !auth {
					return errors.New("server says the token is not authenticated")
				}
				tenant, _ := m["tenant"].(map[string]any)
				fmt.Fprintf(a.Out, "%s Logged in to workspace %s\n", a.stdout.Green("✔"),
					a.stdout.Bold(firstNonEmpty(strOf(tenant, "name"), strOf(tenant, "code"), strOf(tenant, "id"), "(unknown)")))
			}

			if a.cfg.Profiles == nil {
				a.cfg.Profiles = map[string]*config.Profile{}
			}
			prof := a.cfg.Profiles[name]
			if prof == nil {
				prof = &config.Profile{}
				a.cfg.Profiles[name] = prof
			}
			prof.Token = token
			prof.ExpiresAt = "" // a key pasted here has no stored expiry; an old one belonged to the key it replaces
			prof.IssuedByHost = ""
			if strings.TrimSpace(a.flags.url) != "" || prof.URL == "" {
				prof.URL = url
			}
			a.cfg.Current = name
			if err := a.cfg.Save(); err != nil {
				return err
			}
			p, _ := config.Path()
			fmt.Fprintf(a.Out, "Saved profile %q (%s) to %s\n", name, prof.URL, p)
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "PAT to store (omit for a hidden prompt)")
	cmd.Flags().BoolVar(&withToken, "with-token", false, "read the PAT from stdin")
	cmd.Flags().BoolVar(&noVerify, "no-verify", false, "save without checking the token against the server")
	cmd.Flags().BoolVar(&device, "device", false, "sign in with a code you approve in the Console; saves a short-lived key that can only fetch secrets")
	addDeviceFlags(cmd, &dev)
	return cmd
}

func (a *App) logoutCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove the saved token for a profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.loadConfig(); err != nil {
				return err
			}
			names := []string{a.cfg.ProfileName(a.flags.profile)}
			if all {
				names = a.cfg.Names()
			}
			for _, n := range names {
				if p := a.cfg.Profiles[n]; p != nil {
					p.Token = ""
					p.ExpiresAt = ""
					p.IssuedByHost = ""
					fmt.Fprintf(a.Out, "Removed token for profile %q\n", n)
				}
			}
			return a.cfg.Save()
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "remove tokens for every profile")
	return cmd
}

func strOf(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (a *App) whoamiCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show the workspace, user and projects for the current token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args := map[string]any{}
			setIf(args, "project_id", project)
			data, err := a.invoke(cmd, "ar_get_started", args, false)
			if err != nil {
				return err
			}
			if a.flags.json {
				return render.JSON(a.Out, data)
			}
			m, _ := data.(map[string]any)
			if err := a.loadConfig(); err == nil {
				fmt.Fprintf(a.Out, "%s %s (%s)\n", a.stdout.Bold("endpoint "), a.resolved.URL, a.resolved.URLSource)
				fmt.Fprintf(a.Out, "%s %s\n", a.stdout.Bold("profile  "), a.resolved.Profile)
			}
			if t, ok := m["tenant"].(map[string]any); ok {
				fmt.Fprintf(a.Out, "%s %s\n", a.stdout.Bold("workspace"), firstNonEmpty(strOf(t, "name"), strOf(t, "code")))
				fmt.Fprintf(a.Out, "%s %s\n", a.stdout.Bold("tenant id"), strOf(t, "id"))
			}
			if u, ok := m["user"].(map[string]any); ok && len(u) > 0 {
				fmt.Fprintf(a.Out, "%s %s\n", a.stdout.Bold("user     "), firstNonEmpty(strOf(u, "email"), strOf(u, "id")))
			}
			if p, ok := m["default_project"].(map[string]any); ok && len(p) > 0 {
				fmt.Fprintf(a.Out, "%s %s (%s)\n", a.stdout.Bold("project  "), strOf(p, "name"), strOf(p, "id"))
			}
			if pm, ok := m["platform_mcp"].(map[string]any); ok {
				if n, ok := pm["publishable_tool_count"].(float64); ok {
					fmt.Fprintf(a.Out, "%s %d\n", a.stdout.Bold("tools    "), int(n))
				}
			}
			if projects, ok := m["projects"].([]any); ok && len(projects) > 0 {
				fmt.Fprintf(a.Out, "\n%s\n", a.stdout.Bold("Projects"))
				render.Auto(a.Out, a.stdout, projects)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "scope capabilities to a project id")
	return cmd
}

func (a *App) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"health"},
		Short:   "Check Platform MCP and upstream service health",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.call1(cmd, "ar_health_summary", nil)
		},
	}
}

// tokenColumn is what `profile list` shows for a profile's key. A short-lived key (one with a stored expiry) shows no
// character of the key at all, only when it ends; any other key is shown shortened, as before.
func (a *App) tokenColumn(p *config.Profile) string {
	if p.Token == "" || p.ExpiresAt == "" {
		return config.MaskToken(p.Token)
	}
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(p.ExpiresAt))
	switch {
	case err != nil:
		return "short-lived key"
	case !a.nowTime().Before(exp):
		return "short-lived key (expired)"
	}
	return "short-lived key (until " + formatLocal(exp) + ")"
}

func (a *App) profileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage saved connection profiles (e.g. dev, prod)",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:     "list",
			Aliases: []string{"ls"},
			Short:   "List profiles",
			Args:    cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if err := a.loadConfig(); err != nil {
					return err
				}
				cur := a.cfg.ProfileName(a.flags.profile)
				if a.flags.json {
					out := []map[string]any{}
					for _, n := range a.cfg.Names() {
						p := a.cfg.Profiles[n]
						row := map[string]any{"name": n, "url": p.URL, "has_token": p.Token != "", "current": n == cur}
						if p.Token != "" && p.ExpiresAt != "" {
							row["expires_at"] = p.ExpiresAt
						}
						if p.Token != "" && p.IssuedByHost != "" {
							row["issued_by_host"] = p.IssuedByHost
						}
						out = append(out, row)
					}
					return render.JSON(a.Out, out)
				}
				if len(a.cfg.Profiles) == 0 {
					fmt.Fprintln(a.Out, a.stdout.Dim("No profiles saved. Run `agentruntime login`."))
					return nil
				}
				rows := [][]string{}
				for _, n := range a.cfg.Names() {
					p := a.cfg.Profiles[n]
					mark := ""
					if n == cur {
						mark = "*"
					}
					url := p.URL
					if url == "" {
						url = config.DefaultURL
					}
					rows = append(rows, []string{mark, n, url, a.tokenColumn(p)})
				}
				render.Table(a.Out, a.stdout, []string{"", "profile", "url", "token"}, rows, 60)
				return nil
			},
		},
		&cobra.Command{
			Use:   "use <name>",
			Short: "Make a profile current",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := a.loadConfig(); err != nil {
					return err
				}
				if _, ok := a.cfg.Profiles[args[0]]; !ok {
					return fmt.Errorf("no profile %q (try `agentruntime profile list`)", args[0])
				}
				a.cfg.Current = args[0]
				if err := a.cfg.Save(); err != nil {
					return err
				}
				fmt.Fprintf(a.Out, "Current profile: %s\n", args[0])
				return nil
			},
		},
		&cobra.Command{
			Use:     "remove <name>",
			Aliases: []string{"rm"},
			Short:   "Delete a profile",
			Args:    cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := a.loadConfig(); err != nil {
					return err
				}
				if _, ok := a.cfg.Profiles[args[0]]; !ok {
					return fmt.Errorf("no profile %q", args[0])
				}
				delete(a.cfg.Profiles, args[0])
				if a.cfg.Current == args[0] {
					a.cfg.Current = ""
				}
				if err := a.cfg.Save(); err != nil {
					return err
				}
				fmt.Fprintf(a.Out, "Removed profile %q\n", args[0])
				return nil
			},
		},
		&cobra.Command{
			Use:   "path",
			Short: "Print the config file location",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				p, err := config.Path()
				if err != nil {
					return err
				}
				fmt.Fprintln(a.Out, p)
				return nil
			},
		},
	)
	return cmd
}
