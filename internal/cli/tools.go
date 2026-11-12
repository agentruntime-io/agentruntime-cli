package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/render"
)

type callFlags struct {
	argsJSON string
	argsFile string
	kv       []string
	stream   bool
	raw      bool
}

func (f *callFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.argsJSON, "args", "", "tool arguments as a JSON object")
	cmd.Flags().StringVar(&f.argsFile, "args-file", "", "read tool arguments from a JSON file (\"-\" for stdin)")
	cmd.Flags().StringArrayVarP(&f.kv, "arg", "a", nil, "argument as key=value (repeatable; value may be JSON or @file)")
	cmd.Flags().BoolVar(&f.stream, "progress", false, "request MCP progress notifications and echo them to stderr")
}

func (a *App) runCall(cmd *cobra.Command, name string, f *callFlags) error {
	args, err := mergeArgs(f.argsJSON, f.argsFile, f.kv, a.In)
	if err != nil {
		return &ExitErr{Code: ExitUsage, Err: err}
	}
	data, err := a.invoke(cmd, name, args, f.stream)
	if err != nil {
		return err
	}
	return a.emit(data)
}

const callLong = `Call any Platform MCP tool by name. Arguments come from --args (JSON),
--args-file (JSON file or "-" for stdin) and repeated --arg key=value; later
sources win. Values after '=' are parsed as JSON when possible
(--arg limit=5 --arg include_templates=true --arg 'tools=["a","b"]') and a
leading @ reads the value from a file (--arg html=@body.html).

Discover tools with "agentruntime tools list" and parameters with
"agentruntime tools describe <name>".`

func (a *App) callCmd() *cobra.Command {
	f := &callFlags{}
	cmd := &cobra.Command{
		Use:   "call <tool>",
		Short: "Call any Platform MCP tool (alias of `tools call`)",
		Long:  callLong,
		Example: `  agentruntime call workflows_list --arg limit=5
  agentruntime call catalog_tools_search --arg query=gmail --json
  echo '{"workflow_id":"..."}' | agentruntime call workflows_get --args-file -`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return a.runCall(cmd, args[0], f) },
	}
	f.bind(cmd)
	return cmd
}

func (a *App) toolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Discover and call Platform MCP tools directly",
	}

	var filter string
	list := &cobra.Command{
		Use:     "list [filter]",
		Aliases: []string{"ls"},
		Short:   "List available tools",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				filter = args[0]
			}
			ctx, cancel := a.context(cmd)
			defer cancel()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			tools, err := c.ListTools(ctx)
			if err != nil {
				return a.explain(err)
			}
			sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
			q := strings.ToLower(strings.TrimSpace(filter))
			var shown = tools[:0:0]
			for _, t := range tools {
				if q == "" || strings.Contains(strings.ToLower(t.Name), q) || strings.Contains(strings.ToLower(t.Description), q) {
					shown = append(shown, t)
				}
			}
			if a.flags.json {
				return render.JSON(a.Out, shown)
			}
			if len(shown) == 0 {
				fmt.Fprintln(a.Out, a.stdout.Dim("(no matching tools)"))
				return nil
			}
			rows := make([][]string, 0, len(shown))
			for _, t := range shown {
				rows = append(rows, []string{t.Name, firstLine(t.Description)})
			}
			render.Table(a.Out, a.stdout, []string{"tool", "description"}, rows, 90)
			fmt.Fprintf(a.Out, "\n%s\n", a.stdout.Dim(fmt.Sprintf("%d tool(s). Details: agentruntime tools describe <name>", len(shown))))
			return nil
		},
	}

	describe := &cobra.Command{
		Use:   "describe <tool>",
		Short: "Show a tool's description and parameters",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := a.context(cmd)
			defer cancel()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			tools, err := c.ListTools(ctx)
			if err != nil {
				return a.explain(err)
			}
			for _, t := range tools {
				if t.Name != args[0] {
					continue
				}
				if a.flags.json {
					return render.JSON(a.Out, t)
				}
				fmt.Fprintf(a.Out, "%s\n\n%s\n", a.stdout.Bold(t.Name), strings.TrimSpace(t.Description))
				printParams(a, t.InputSchema)
				return nil
			}
			var near []string
			needle := strings.ToLower(args[0])
			for _, t := range tools {
				if strings.Contains(t.Name, needle) {
					near = append(near, t.Name)
				}
			}
			msg := fmt.Sprintf("no tool named %q", args[0])
			if len(near) > 0 {
				if len(near) > 8 {
					near = near[:8]
				}
				msg += "; did you mean: " + strings.Join(near, ", ")
			}
			return &ExitErr{Code: ExitError, Err: fmt.Errorf("%s", msg)}
		},
	}

	f := &callFlags{}
	call := &cobra.Command{
		Use:   "call <tool>",
		Short: "Call a tool by name",
		Long:  callLong,
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return a.runCall(cmd, args[0], f) },
	}
	f.bind(call)

	cmd.AddCommand(list, describe, call)
	return cmd
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

func printParams(a *App, schema any) {
	b, err := json.Marshal(schema)
	if err != nil {
		return
	}
	var s struct {
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
	}
	if json.Unmarshal(b, &s) != nil || len(s.Properties) == 0 {
		fmt.Fprintf(a.Out, "\n%s\n", a.stdout.Dim("(no parameters)"))
		return
	}
	req := map[string]bool{}
	for _, r := range s.Required {
		req[r] = true
	}
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if req[names[i]] != req[names[j]] {
			return req[names[i]]
		}
		return names[i] < names[j]
	})
	rows := make([][]string, 0, len(names))
	for _, n := range names {
		p := s.Properties[n]
		typ, _ := p["type"].(string)
		if typ == "" {
			typ = "any"
		}
		if typ == "array" {
			if items, ok := p["items"].(map[string]any); ok {
				if it, _ := items["type"].(string); it != "" {
					typ = it + "[]"
				}
			}
		}
		need := ""
		if req[n] {
			need = "required"
		}
		desc, _ := p["description"].(string)
		rows = append(rows, []string{n, typ, need, firstLine(desc)})
	}
	fmt.Fprintln(a.Out)
	render.Table(a.Out, a.stdout, []string{"param", "type", "", "description"}, rows, 80)
}
