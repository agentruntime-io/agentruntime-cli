package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/config"
	"github.com/agentruntime-io/agentruntime-cli/internal/render"
	"github.com/agentruntime-io/agentruntime-cli/internal/update"
	"github.com/agentruntime-io/agentruntime-cli/internal/version"
)

func (a *App) upgradeCmd() *cobra.Command {
	var check bool
	var target string
	cmd := &cobra.Command{
		Use:     "upgrade",
		Aliases: []string{"update", "self-update"},
		Short:   "Update agentruntime to the latest release",
		Long: `Downloads the latest release for this OS/architecture, verifies its SHA-256
checksum and replaces the running binary. Use --check to only look for updates
and --version to install a specific tag.

Set AGENTRUNTIME_CLI_BASE_URL to use a different release host.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := a.context(cmd)
			defer cancel()
			update.CleanupOld()
			res, err := update.Run(ctx, update.Options{Current: version.Version, Target: target, Check: check})
			if err != nil {
				return err
			}
			switch {
			case res.Updated && res.From == res.To:
				fmt.Fprintf(a.Out, "%s Reinstalled %s (%s)\n", a.stdout.Green("✔"), res.To, res.Path)
			case res.Updated:
				fmt.Fprintf(a.Out, "%s Updated %s → %s (%s)\n", a.stdout.Green("✔"), res.From, res.To, res.Path)
			case check && (target != "" || update.Newer(res.To, res.From)):
				fmt.Fprintf(a.Out, "Update available: %s → %s. Run `agentruntime upgrade`.\n", res.From, res.To)
			default:
				fmt.Fprintf(a.Out, "Already up to date (%s).\n", res.From)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only check for a newer release")
	cmd.Flags().StringVar(&target, "version", "", "install this release tag (e.g. v0.2.0)")
	return cmd
}

func (a *App) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgPath, _ := config.Path()
			info := map[string]any{
				"version": version.Version,
				"commit":  version.Commit,
				"built":   version.Date,
				"os":      runtime.GOOS,
				"arch":    runtime.GOARCH,
				"config":  cfgPath,
			}
			if a.flags.json {
				return render.JSON(a.Out, info)
			}
			fmt.Fprintf(a.Out, "agentruntime %s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH)
			fmt.Fprintf(a.Out, "commit %s, built %s\nconfig %s\n", version.Commit, version.Date, cfgPath)
			return nil
		},
	}
}
