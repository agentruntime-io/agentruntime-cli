package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/render"
)

// ---- run --------------------------------------------------------------------

type runFlags struct {
	name        string
	graphFile   string
	inputs      []string
	inputFile   string
	paramsFile  string
	sessionID   string
	runID       string
	wait        bool
	stream      bool
	waitTimeout int
	noOutputs   bool
}

func (f *runFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.name, "name", "", "workflow name (only with --graph-file to create a new workflow)")
	fl.StringVar(&f.graphFile, "graph-file", "", "create the workflow from this graph JSON file (must contain steps[]); \"-\" for stdin")
	fl.StringArrayVarP(&f.inputs, "input", "i", nil, "trigger input as key=value for {{input.key}} (repeatable; value may be JSON or @file)")
	fl.StringVar(&f.inputFile, "input-file", "", "trigger payload JSON file (\"-\" for stdin)")
	fl.StringVar(&f.paramsFile, "params-file", "", "full start params JSON file (trigger_payload, trigger_steps, …)")
	fl.StringVar(&f.sessionID, "session-id", "", "optional session id to group sibling runs")
	fl.StringVar(&f.runID, "run-id", "", "optional client-chosen run UUID")
	fl.BoolVarP(&f.wait, "wait", "w", false, "block until the run completes, fails or reaches an approval gate")
	fl.BoolVarP(&f.stream, "stream", "s", false, "return the full timeline (stream_frames) and echo live progress")
	fl.IntVar(&f.waitTimeout, "wait-timeout", 0, "server-side wait limit in seconds (1-300, default 120)")
	fl.BoolVar(&f.noOutputs, "no-outputs", false, "do not print step outputs")
}

func (a *App) runCmd() *cobra.Command {
	f := &runFlags{}
	cmd := &cobra.Command{
		Use:   "run [workflow-id]",
		Short: "Start a workflow run",
		Long: `Starts a workflow via the workflow_run composite tool.

  --wait    block until completed / failed / awaiting approval (or --wait-timeout)
  --stream  full, untruncated timeline of step outputs and gates

Without --wait or --stream the run starts in the background and the command
returns the run id; follow up with "agentruntime await".

Exit codes: 0 completed or running, 1 failed/stopped/error, 2 usage, 3 awaiting approval.`,
		Example: `  agentruntime run 7d1c… --wait
  agentruntime run 7d1c… -i recipient=jo@example.com -i topic="weekly digest" -w
  agentruntime run --name "Adhoc" --graph-file graph.json --input-file input.json --stream`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wid := ""
			if len(args) == 1 {
				wid = args[0]
			}
			return a.doRun(cmd, wid, f)
		},
	}
	f.bind(cmd)
	return cmd
}

func (a *App) doRun(cmd *cobra.Command, workflowID string, f *runFlags) error {
	usage := func(err error) error { return &ExitErr{Code: ExitUsage, Err: err} }
	args := map[string]any{}
	switch {
	case workflowID != "" && f.graphFile != "":
		return usage(errors.New("pass either a workflow id or --graph-file, not both"))
	case workflowID != "":
		args["workflow_id"] = workflowID
	case f.graphFile != "":
		if f.name == "" {
			return usage(errors.New("--name is required with --graph-file"))
		}
		g, err := readJSONObject(f.graphFile, a.In)
		if err != nil {
			return usage(err)
		}
		args["name"], args["graph"] = f.name, g
	default:
		return usage(errors.New("provide a workflow id, or --name with --graph-file"))
	}

	params := map[string]any{}
	if f.paramsFile != "" {
		p, err := readJSONObject(f.paramsFile, a.In)
		if err != nil {
			return usage(err)
		}
		params = p
	}
	payload := map[string]any{}
	if existing, ok := params["trigger_payload"].(map[string]any); ok {
		payload = existing
	}
	if f.inputFile != "" {
		m, err := readJSONObject(f.inputFile, a.In)
		if err != nil {
			return usage(err)
		}
		for k, v := range m {
			payload[k] = v
		}
	}
	kv, err := parseKV(f.inputs)
	if err != nil {
		return usage(err)
	}
	for k, v := range kv {
		payload[k] = v
	}
	if len(payload) > 0 {
		params["trigger_payload"] = payload
	}
	if len(params) > 0 {
		args["params"] = params
	}
	setIf(args, "session_id", f.sessionID)
	setIf(args, "run_id", f.runID)
	setIf(args, "wait", f.wait)
	setIf(args, "stream", f.stream)
	setIf(args, "timeout_seconds", f.waitTimeout)

	data, err := a.invoke(cmd, "workflow_run", args, f.stream)
	if err != nil {
		return err
	}
	return a.emitOutcome(data, !f.noOutputs, true)
}

// ---- await / inspect / approve ------------------------------------------------

func (a *App) awaitCmd() *cobra.Command {
	var stream bool
	var waitTimeout int
	cmd := &cobra.Command{
		Use:   "await <workflow-id> <run-id>",
		Short: "Wait for an existing run to finish or reach an approval gate",
		Long:  "Resumes waiting on a known run (workflow_await). Returns immediately when the run is already terminal or at a gate.\n\nExit codes: 0 completed or still running, 1 failed/stopped, 3 awaiting approval.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{"workflow_id": args[0], "run_id": args[1]}
			setIf(req, "stream", stream)
			setIf(req, "timeout_seconds", waitTimeout)
			data, err := a.invoke(cmd, "workflow_await", req, stream)
			if err != nil {
				return err
			}
			return a.emitOutcome(data, true, true)
		},
	}
	cmd.Flags().BoolVarP(&stream, "stream", "s", false, "full timeline and live progress")
	cmd.Flags().IntVar(&waitTimeout, "wait-timeout", 0, "server-side wait limit in seconds (1-300, default 120)")
	return cmd
}

func (a *App) inspectCmd() *cobra.Command {
	var task string
	var full, noGate bool
	var steps []string
	cmd := &cobra.Command{
		Use:   "inspect <workflow-id> <run-id>",
		Short: "Read the decision package for a run (read-only)",
		Long: `Shows the run state, step outputs and any open approval gates without side
effects (workflow_inspect). Output is truncated by default (4KB per gate payload,
8KB of outputs); use --full for everything or --step to focus on specific steps.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{"workflow_id": args[0], "run_id": args[1]}
			setIf(req, "task_id", task)
			setIf(req, "full", full)
			setIf(req, "include_steps", steps)
			if noGate {
				req["include_gate_payload"] = false
			}
			data, err := a.invoke(cmd, "workflow_inspect", req, false)
			if err != nil {
				return err
			}
			return a.emitOutcome(data, true, false)
		},
	}
	cmd.Flags().StringVar(&task, "task", "", "only this approval gate (task id)")
	cmd.Flags().BoolVar(&full, "full", false, "no truncation of payloads and outputs")
	cmd.Flags().StringArrayVar(&steps, "step", nil, "limit outputs to this step id (repeatable)")
	cmd.Flags().BoolVar(&noGate, "no-gate-payload", false, "omit approval payloads")
	return cmd
}

func (a *App) approveCmd(approve bool) *cobra.Command {
	var comment string
	var edits []string
	var yes, noWait, stream bool
	var waitTimeout int

	use, verb := "approve <workflow-id> <run-id> <task-id>", "Approve"
	if !approve {
		use, verb = "reject <workflow-id> <run-id> <task-id>", "Reject"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: verb + " a human approval gate",
		Long: verb + ` a human_task gate (workflow_approve). Before acting, the CLI shows the gate
summary and payload and asks for confirmation; pass --yes to skip (required in scripts).
Find task ids with "agentruntime tasks list" or from the awaiting_input outcome.

--edit key=value overrides upstream step outputs at approve time. Keys are
<step_id>.<path> (for example f4db….html) and values are strings or @file.
Edits are only valid when approving.`,
		Example: `  agentruntime approve <wf> <run> <task>
  agentruntime approve <wf> <run> <task> --edit "f4db….recipient=jo@example.com" --comment "fixed recipient"
  agentruntime reject <wf> <run> <task> --comment "wrong audience" --yes`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			wf, run, task := args[0], args[1], args[2]
			ctxEdits, err := parseKVStrings(edits)
			if err != nil {
				return &ExitErr{Code: ExitUsage, Err: err}
			}
			if len(ctxEdits) > 0 && !approve {
				return &ExitErr{Code: ExitUsage, Err: errors.New("--edit is only valid with approve")}
			}

			if !yes {
				if err := a.showGate(cmd, wf, run, task); err != nil {
					return err
				}
				ok, err := a.confirm(fmt.Sprintf("%s task %s?", verb, task))
				if err != nil {
					return &ExitErr{Code: ExitUsage, Err: err}
				}
				if !ok {
					fmt.Fprintln(a.Err, "Aborted.")
					return &ExitErr{Code: ExitError}
				}
			}

			req := map[string]any{"workflow_id": wf, "run_id": run, "task_id": task, "approved": approve}
			setIf(req, "comment", comment)
			if len(ctxEdits) > 0 {
				req["context_edits"] = ctxEdits
			}
			req["wait"] = !noWait
			setIf(req, "stream", stream)
			setIf(req, "timeout_seconds", waitTimeout)
			data, err := a.invoke(cmd, "workflow_approve", req, stream)
			if err != nil {
				return err
			}
			return a.emitOutcome(data, true, true)
		},
	}
	cmd.Flags().StringVar(&comment, "comment", "", "note recorded with the decision")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "return the current snapshot instead of waiting for the next outcome")
	cmd.Flags().BoolVarP(&stream, "stream", "s", false, "full timeline of the post-decision steps")
	cmd.Flags().IntVar(&waitTimeout, "wait-timeout", 0, "server-side wait limit in seconds (1-300, default 120)")
	if approve {
		cmd.Flags().StringArrayVar(&edits, "edit", nil, "override upstream output: <step_id>.<path>=value (repeatable)")
	}
	return cmd
}

// showGate prints the open gate for task so the user can decide.
func (a *App) showGate(cmd *cobra.Command, wf, run, task string) error {
	data, err := a.invoke(cmd, "workflow_inspect", map[string]any{"workflow_id": wf, "run_id": run, "task_id": task}, false)
	if err != nil {
		return err
	}
	var w io.Writer = a.Out
	st := a.stdout
	if a.flags.json {
		w, st = a.Err, a.stderr // keep stdout clean for the final JSON result
	}
	if m, ok := data.(map[string]any); ok && render.IsOutcome(m) {
		render.Outcome(w, st, m, render.OutcomeOptions{})
		fmt.Fprintln(w)
		return nil
	}
	render.Auto(w, st, data)
	return nil
}

// ---- runs / tasks -----------------------------------------------------------------

func (a *App) runsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "runs", Short: "Inspect workflow runs"}

	var limit int
	var cursor string
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List recent runs across the workspace",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args := map[string]any{}
			setIf(args, "limit", limit)
			setIf(args, "cursor", cursor)
			return a.call1(cmd, "runs_list_tenant", args)
		},
	}
	list.Flags().IntVar(&limit, "limit", 0, "page size")
	list.Flags().StringVar(&cursor, "cursor", "", "pagination cursor from a previous response")

	get := &cobra.Command{
		Use:     "get <workflow-id> <run-id>",
		Aliases: []string{"summary"},
		Short:   "Show a run's status summary",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.call1(cmd, "runs_get_summary", map[string]any{"workflow_id": args[0], "run_id": args[1]})
		},
	}

	var evLimit, evOffset int
	events := &cobra.Command{
		Use:   "events <workflow-id> <run-id>",
		Short: "List run events (debugging)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{"workflow_id": args[0], "run_id": args[1]}
			setIf(req, "limit", evLimit)
			setIf(req, "offset", evOffset)
			return a.call1(cmd, "runs_list_events", req)
		},
	}
	events.Flags().IntVar(&evLimit, "limit", 0, "page size")
	events.Flags().IntVar(&evOffset, "offset", 0, "offset")

	context := &cobra.Command{
		Use:   "context <workflow-id> <run-id>",
		Short: "Dump the full run context (debugging)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.call1(cmd, "runs_get_context", map[string]any{"workflow_id": args[0], "run_id": args[1]})
		},
	}

	cmd.AddCommand(list, get, events, context)
	return cmd
}

func (a *App) tasksCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "tasks", Short: "Human approval tasks (Command Center inbox)"}

	var limit int
	var wf, run string
	var noNames bool
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "pending"},
		Short:   "List pending human tasks",
		Long:    "Lists pending human tasks across the workspace, or for one run with --workflow and --run.",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (wf == "") != (run == "") {
				return &ExitErr{Code: ExitUsage, Err: errors.New("--workflow and --run must be used together")}
			}
			if wf != "" {
				return a.call1(cmd, "tasks_list_pending_run", map[string]any{"workflow_id": wf, "run_id": run})
			}
			args := map[string]any{"include_workflow_name": !noNames}
			setIf(args, "limit", limit)
			return a.call1(cmd, "tasks_list_pending", args)
		},
	}
	list.Flags().IntVar(&limit, "limit", 0, "maximum tasks")
	list.Flags().StringVar(&wf, "workflow", "", "workflow id (with --run)")
	list.Flags().StringVar(&run, "run", "", "run id (with --workflow)")
	list.Flags().BoolVar(&noNames, "no-workflow-names", false, "skip resolving workflow names")

	cmd.AddCommand(list)
	return cmd
}

// ---- workflows ------------------------------------------------------------------

func (a *App) workflowsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "workflows",
		Aliases: []string{"workflow", "wf"},
		Short:   "List, create, validate and run workflows",
	}

	var limit int
	var cursor, owner string
	var templates bool
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List workflows",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args := map[string]any{}
			setIf(args, "limit", limit)
			setIf(args, "cursor", cursor)
			setIf(args, "owner_id", owner)
			setIf(args, "include_templates", templates)
			return a.call1(cmd, "workflows_list", args)
		},
	}
	list.Flags().IntVar(&limit, "limit", 0, "page size")
	list.Flags().StringVar(&cursor, "cursor", "", "pagination cursor from a previous response")
	list.Flags().StringVar(&owner, "owner", "", "filter by owner id")
	list.Flags().BoolVar(&templates, "templates", false, "include templates")

	var version string
	get := &cobra.Command{
		Use:   "get <workflow-id>",
		Short: "Show a workflow including its graph",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{"workflow_id": args[0]}
			setIf(req, "version_id", version)
			data, err := a.invoke(cmd, "workflows_get", req, false)
			if err != nil {
				return err
			}
			// A workflow is mostly its graph — always print JSON for it.
			return render.JSON(a.Out, data)
		},
	}
	get.Flags().StringVar(&version, "version", "", "specific version id")

	var cName, cDesc, cProject, cGraph string
	var cTemplate bool
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a workflow",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cName == "" {
				return &ExitErr{Code: ExitUsage, Err: errors.New("--name is required")}
			}
			req := map[string]any{"name": cName}
			setIf(req, "description", cDesc)
			setIf(req, "project_id", cProject)
			setIf(req, "is_template", cTemplate)
			if cGraph != "" {
				g, err := readJSONObject(cGraph, a.In)
				if err != nil {
					return &ExitErr{Code: ExitUsage, Err: err}
				}
				req["graph"] = g
			}
			return a.call1(cmd, "workflows_create", req)
		},
	}
	create.Flags().StringVar(&cName, "name", "", "workflow name (required)")
	create.Flags().StringVar(&cDesc, "description", "", "description")
	create.Flags().StringVar(&cProject, "project", "", "project id (default: your default project)")
	create.Flags().StringVar(&cGraph, "graph-file", "", "graph JSON file with steps[] (\"-\" for stdin)")
	create.Flags().BoolVar(&cTemplate, "template", false, "mark as a template")

	var vGraph, vPayload, vParams string
	validate := &cobra.Command{
		Use:   "validate <workflow-id>",
		Short: "Dry-run a workflow graph (no MCP or SQL executed)",
		Long: `Compile-checks a graph with workflows_validate. Uses the saved graph unless
--graph-file is given, so you can validate local edits before publishing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{"workflow_id": args[0]}
			if vGraph != "" {
				g, err := readJSONObject(vGraph, a.In)
				if err != nil {
					return &ExitErr{Code: ExitUsage, Err: err}
				}
				req["graph"] = g
			} else {
				data, err := a.invoke(cmd, "workflows_get", map[string]any{"workflow_id": args[0]}, false)
				if err != nil {
					return err
				}
				g := findGraph(data)
				if g == nil {
					return errors.New("could not find a graph on the saved workflow; pass --graph-file")
				}
				req["graph"] = g
			}
			if vPayload != "" {
				p, err := readJSONObject(vPayload, a.In)
				if err != nil {
					return &ExitErr{Code: ExitUsage, Err: err}
				}
				req["payload"] = p
			}
			if vParams != "" {
				p, err := readJSONObject(vParams, a.In)
				if err != nil {
					return &ExitErr{Code: ExitUsage, Err: err}
				}
				req["params"] = p
			}
			data, err := a.invoke(cmd, "workflows_validate", req, false)
			if err != nil {
				return err
			}
			if err := a.emit(data); err != nil {
				return err
			}
			if m, ok := data.(map[string]any); ok {
				if valid, ok := m["valid"].(bool); ok && !valid {
					return &ExitErr{Code: ExitError}
				}
			}
			return nil
		},
	}
	validate.Flags().StringVar(&vGraph, "graph-file", "", "validate this graph JSON instead of the saved one")
	validate.Flags().StringVar(&vPayload, "payload-file", "", "trigger payload JSON for template checks")
	validate.Flags().StringVar(&vParams, "params-file", "", "start params JSON")

	var archiveYes bool
	archive := &cobra.Command{
		Use:   "archive <workflow-id>",
		Short: "Archive (delete) a workflow",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !archiveYes {
				ok, err := a.confirm(fmt.Sprintf("Archive workflow %s?", args[0]))
				if err != nil {
					return &ExitErr{Code: ExitUsage, Err: err}
				}
				if !ok {
					fmt.Fprintln(a.Err, "Aborted.")
					return &ExitErr{Code: ExitError}
				}
			}
			return a.call1(cmd, "workflows_archive", map[string]any{"workflow_id": args[0]})
		},
	}
	archive.Flags().BoolVarP(&archiveYes, "yes", "y", false, "skip the confirmation prompt")

	var rLimit int
	var rCursor string
	runs := &cobra.Command{
		Use:   "runs <workflow-id>",
		Short: "List runs of one workflow",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := map[string]any{"workflow_id": args[0]}
			setIf(req, "limit", rLimit)
			setIf(req, "cursor", rCursor)
			return a.call1(cmd, "workflows_list_runs", req)
		},
	}
	runs.Flags().IntVar(&rLimit, "limit", 0, "page size")
	runs.Flags().StringVar(&rCursor, "cursor", "", "pagination cursor")

	cmd.AddCommand(list, get, create, validate, archive, runs, a.runCmd())
	return cmd
}

// findGraph locates graph on a workflows_get result, which may nest it.
func findGraph(data any) map[string]any {
	m, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	if g, ok := m["graph"].(map[string]any); ok {
		return g
	}
	for _, k := range []string{"workflow", "version", "item", "data"} {
		if g := findGraph(m[k]); g != nil {
			return g
		}
	}
	return nil
}
