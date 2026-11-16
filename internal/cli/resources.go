package cli

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/render"
)

func (a *App) confirmOrAbort(yes bool, prompt string) error {
	if yes {
		return nil
	}
	ok, err := a.confirm(prompt)
	if err != nil {
		return &ExitErr{Code: ExitUsage, Err: err}
	}
	if !ok {
		fmt.Fprintln(a.Err, "Aborted.")
		return &ExitErr{Code: ExitError}
	}
	return nil
}

// ---- projects ---------------------------------------------------------------------

func (a *App) projectsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "projects", Short: "Workspace projects"}
	cmd.AddCommand(&cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List projects visible to your token",
		Args:    cobra.NoArgs,
		RunE:    func(cmd *cobra.Command, _ []string) error { return a.call1(cmd, "projects_list", nil) },
	})
	return cmd
}

// ---- catalog ----------------------------------------------------------------------

func (a *App) catalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Browse connectors, tools, connections, instances and servers",
	}

	var page, pageSize int
	connectors := &cobra.Command{
		Use:   "connectors",
		Short: "Browse the connector catalog (ready / needs connection / catalog)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := map[string]any{}
			setIf(req, "page", page)
			setIf(req, "page_size", pageSize)
			data, err := a.invoke(cmd, "catalog_connectors_browse", req, false)
			if err != nil {
				return err
			}
			if a.flags.json {
				return render.JSON(a.Out, data)
			}
			m, _ := data.(map[string]any)
			groups, _ := m["groups"].(map[string]any)
			if len(groups) == 0 {
				return a.emit(data)
			}
			order := []string{"ready", "needs_connection", "catalog"}
			for k := range groups {
				if !contains(order, k) {
					order = append(order, k)
				}
			}
			for _, name := range order {
				g, ok := groups[name].(map[string]any)
				if !ok {
					continue
				}
				fmt.Fprintf(a.Out, "%s  %s\n", a.stdout.Bold(name), a.stdout.Dim(strOf(g, "description")))
				conns, _ := g["connectors"].(map[string]any)
				slugs := make([]string, 0, len(conns))
				for s := range conns {
					slugs = append(slugs, s)
				}
				sort.Strings(slugs)
				rows := make([][]string, 0, len(slugs))
				for _, s := range slugs {
					rows = append(rows, []string{s, render.Scalar(conns[s])})
				}
				if len(rows) == 0 {
					fmt.Fprintln(a.Out, a.stdout.Dim("  (none)"))
				} else {
					render.Table(a.Out, a.stdout, []string{"connector", "tools"}, rows, 60)
				}
				fmt.Fprintln(a.Out)
			}
			rest := map[string]any{}
			for k, v := range m {
				if k != "groups" {
					rest[k] = v
				}
			}
			if len(rest) > 0 {
				render.KeyValue(a.Out, a.stdout, rest)
			}
			return nil
		},
	}
	connectors.Flags().IntVar(&page, "page", 0, "page number")
	connectors.Flags().IntVar(&pageSize, "page-size", 0, "page size")

	tools := &cobra.Command{Use: "tools", Short: "Search connector tools and read their schemas"}
	var tPage, tPageSize int
	var names []string
	search := &cobra.Command{
		Use:   "search [query]",
		Short: "Search connector tools by keyword or exact name",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{}
			if len(args) == 1 {
				req["query"] = args[0]
			}
			setIf(req, "tools", names)
			setIf(req, "page", tPage)
			setIf(req, "page_size", tPageSize)
			if len(req) == 0 {
				return &ExitErr{Code: ExitUsage, Err: errors.New("give a query or --tool <exact-name>")}
			}
			return a.call1(cmd, "catalog_tools_search", req)
		},
	}
	search.Flags().StringArrayVar(&names, "tool", nil, "exact tool name (repeatable)")
	search.Flags().IntVar(&tPage, "page", 0, "page number")
	search.Flags().IntVar(&tPageSize, "page-size", 0, "page size")
	schema := &cobra.Command{
		Use:   "schema <tool>...",
		Short: "Show input/output JSON schemas for 1-20 connector tools",
		Args:  cobra.RangeArgs(1, 20),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := a.invoke(cmd, "catalog_tools_schema", map[string]any{"tools": args}, false)
			if err != nil {
				return err
			}
			return render.JSON(a.Out, data) // schemas are JSON documents
		},
	}
	tools.AddCommand(search, schema)

	simpleList := func(use, short, tool string) *cobra.Command {
		c := &cobra.Command{Use: use, Short: short}
		c.AddCommand(&cobra.Command{
			Use:     "list",
			Aliases: []string{"ls"},
			Short:   "List " + use,
			Args:    cobra.NoArgs,
			RunE:    func(cmd *cobra.Command, _ []string) error { return a.call1(cmd, tool, nil) },
		})
		return c
	}
	connections := simpleList("connections", "Saved integration connections", "catalog_connections_list")
	instances := simpleList("instances", "Installed MCP instances in the workspace", "catalog_instances_list")
	servers := simpleList("servers", "MCP servers", "catalog_servers_list")
	servers.AddCommand(&cobra.Command{
		Use:   "get <server-id>",
		Short: "Show one MCP server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.call1(cmd, "catalog_servers_get", map[string]any{"server_id": args[0]})
		},
	})

	cmd.AddCommand(connectors, tools, connections, instances, servers)
	return cmd
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---- tenant data ------------------------------------------------------------------

func (a *App) tenantDataCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tenantdata",
		Aliases: []string{"tenant-data", "db"},
		Short:   "Tenant Data databases (logical schemas and API contracts)",
	}
	var tenant string
	cmd.PersistentFlags().StringVar(&tenant, "tenant", "", "tenant id (default: resolved from your token)")

	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List databases",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := map[string]any{}
			setIf(req, "tenant_id", tenant)
			return a.call1(cmd, "tenantdata_databases_list", req)
		},
	}

	var id, name, schemaFile string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a database from a logical schema file",
		Long:  "Creates a database with an initial logical schema ({\"tables\": [...]}). See `agentruntime tenantdata schema` for the schema format.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == "" || name == "" || schemaFile == "" {
				return &ExitErr{Code: ExitUsage, Err: errors.New("--id, --name and --schema-file are required")}
			}
			schema, err := readJSONObject(schemaFile, a.In)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			req := map[string]any{"database_id": id, "database_name": name, "schema": schema}
			setIf(req, "tenant_id", tenant)
			return a.call1(cmd, "tenantdata_databases_create", req)
		},
	}
	create.Flags().StringVar(&id, "id", "", "logical database key, e.g. crm (required)")
	create.Flags().StringVar(&name, "name", "", "display name (required)")
	create.Flags().StringVar(&schemaFile, "schema-file", "", "logical schema JSON file (required; \"-\" for stdin)")

	contract := &cobra.Command{
		Use:   "contract <database-id>",
		Short: "Show a database's published API contract",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{"database_id": args[0]}
			setIf(req, "tenant_id", tenant)
			return a.call1(cmd, "tenantdata_api_contract_get", req)
		},
	}

	schema := &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema for logical schema documents",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := a.invoke(cmd, "tenantdata_logical_schema", nil, false)
			if err != nil {
				return err
			}
			return render.JSON(a.Out, data)
		},
	}

	cmd.AddCommand(list, create, contract, schema)
	return cmd
}

// ---- PATs -------------------------------------------------------------------------

func parseExpiry(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid --expires-in %q", s)
		}
		return int64(n * 24 * 3600), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid --expires-in %q (use e.g. 30d, 12h)", s)
	}
	return int64(d.Seconds()), nil
}

func (a *App) patsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pats",
		Short: "Personal access tokens (create/reveal need the server's risk group)",
	}

	var revoked, expired bool
	var project string
	var limit int
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List tokens",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := map[string]any{}
			setIf(req, "include_revoked", revoked)
			setIf(req, "include_expired", expired)
			setIf(req, "project_id", project)
			setIf(req, "limit", limit)
			return a.call1(cmd, "pats_list", req)
		},
	}
	list.Flags().BoolVar(&revoked, "include-revoked", false, "include revoked tokens")
	list.Flags().BoolVar(&expired, "include-expired", false, "include expired tokens")
	list.Flags().StringVar(&project, "project", "", "filter by project id")
	list.Flags().IntVar(&limit, "limit", 0, "maximum tokens")

	var desc, cProject, expiresIn string
	var scopes []string
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a token (the plaintext is shown once)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{"name": args[0]}
			setIf(req, "description", desc)
			setIf(req, "project_id", cProject)
			setIf(req, "scopes", scopes)
			secs, err := parseExpiry(expiresIn)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			if secs > 0 {
				req["expires_in_seconds"] = secs
			}
			data, err := a.invoke(cmd, "pats_create", req, false)
			if err != nil {
				return err
			}
			if err := a.emit(data); err != nil {
				return err
			}
			if !a.flags.json {
				fmt.Fprintf(a.Err, "\n%s Copy the token now; store it somewhere safe.\n", a.stderr.Yellow("!"))
			}
			return nil
		},
	}
	create.Flags().StringVar(&desc, "description", "", "description")
	create.Flags().StringVar(&cProject, "project", "", "restrict to a project id")
	create.Flags().StringArrayVar(&scopes, "scope", nil, "token scope (repeatable)")
	create.Flags().StringVar(&expiresIn, "expires-in", "", "lifetime, e.g. 30d or 12h (default: server policy)")

	var yes bool
	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.confirmOrAbort(yes, fmt.Sprintf("Revoke token %s?", args[0])); err != nil {
				return err
			}
			return a.call1(cmd, "pats_revoke", map[string]any{"id": args[0]})
		},
	}
	revoke.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")

	reveal := &cobra.Command{
		Use:   "reveal <id>",
		Short: "Show a token's plaintext",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.call1(cmd, "pats_reveal", map[string]any{"id": args[0]})
		},
	}

	cmd.AddCommand(list, create, revoke, reveal)
	return cmd
}

// ---- analytics --------------------------------------------------------------------

var analyticsMetrics = map[string]string{
	"live-runs":          "analytics_live_runs",
	"success-rate":       "analytics_success_rate",
	"execution-duration": "analytics_execution_duration",
	"runs-count":         "analytics_runs_count",
	"steps-executed":     "analytics_steps_executed",
	"credits-consumed":   "analytics_credits_consumed",
	"runs-timeseries":    "analytics_runs_timeseries",
	"usage-timeseries":   "analytics_usage_timeseries",
}

func (a *App) analyticsCmd() *cobra.Command {
	names := make([]string, 0, len(analyticsMetrics))
	for k := range analyticsMetrics {
		names = append(names, k)
	}
	sort.Strings(names)

	var window, owner, from, to, granularity string
	cmd := &cobra.Command{
		Use:   "analytics <metric>",
		Short: "Workspace analytics",
		Long:  "Metrics: " + strings.Join(names, ", ") + "\n\n*-timeseries metrics require --from and --to (RFC 3339 timestamps or dates).",
		Example: `  agentruntime analytics runs-count --window 7d
  agentruntime analytics runs-timeseries --from 2026-11-01 --to 2026-11-12 --granularity day`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: names,
		RunE: func(cmd *cobra.Command, args []string) error {
			tool, ok := analyticsMetrics[args[0]]
			if !ok {
				return &ExitErr{Code: ExitUsage, Err: fmt.Errorf("unknown metric %q (choose: %s)", args[0], strings.Join(names, ", "))}
			}
			req := map[string]any{}
			setIf(req, "owner_id", owner)
			if strings.HasSuffix(args[0], "timeseries") {
				if from == "" || to == "" {
					return &ExitErr{Code: ExitUsage, Err: errors.New("--from and --to are required for timeseries metrics")}
				}
				req["from"], req["to"] = from, to
				setIf(req, "granularity", granularity)
			} else {
				setIf(req, "window", window)
			}
			return a.call1(cmd, tool, req)
		},
	}
	cmd.Flags().StringVar(&window, "window", "", "time window, e.g. 24h or 7d (point-in-time metrics)")
	cmd.Flags().StringVar(&owner, "owner", "", "filter by owner id")
	cmd.Flags().StringVar(&from, "from", "", "range start (timeseries)")
	cmd.Flags().StringVar(&to, "to", "", "range end (timeseries)")
	cmd.Flags().StringVar(&granularity, "granularity", "", "bucket size, e.g. hour or day (timeseries)")
	return cmd
}
