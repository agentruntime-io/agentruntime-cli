package render

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// OutcomeOptions tunes workflow outcome rendering.
type OutcomeOptions struct {
	ShowOutputs bool // print the outputs object
	Hints       bool // print "next step" commands
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// IsOutcome reports whether m looks like a workflow outcome envelope.
func IsOutcome(m map[string]any) bool {
	_, hasOutcome := m["outcome"].(string)
	_, hasRun := m["run_id"].(string)
	return hasOutcome && hasRun
}

func outcomeColor(st Style, outcome string) string {
	switch outcome {
	case "completed":
		return st.Green(outcome)
	case "failed", "stopped":
		return st.Red(outcome)
	case "awaiting_input":
		return st.Yellow(outcome)
	default:
		return st.Cyan(outcome)
	}
}

// Outcome renders the workflow_run / await / inspect / approve envelope.
func Outcome(w io.Writer, st Style, m map[string]any, opt OutcomeOptions) {
	outcome := str(m, "outcome")
	wf, run := str(m, "workflow_id"), str(m, "run_id")

	fmt.Fprintf(w, "%s %s\n", st.Bold("Outcome"), outcomeColor(st, outcome))
	fmt.Fprintf(w, "%s %s\n", st.Dim("workflow"), wf)
	fmt.Fprintf(w, "%s %s\n", st.Dim("run     "), run)
	if s := str(m, "agent_user_summary"); s != "" {
		fmt.Fprintf(w, "\n%s\n", s)
	}

	if e, ok := m["error"].(map[string]any); ok && len(e) > 0 {
		fmt.Fprintf(w, "\n%s %s\n", st.Red("Error"), str(e, "message"))
		for _, k := range []string{"failure_code", "failure_layer", "failed_step_id"} {
			if v := str(e, k); v != "" {
				fmt.Fprintf(w, "  %s %s\n", st.Dim(k+":"), v)
			}
		}
	}

	if frames, ok := m["stream_frames"].([]any); ok && len(frames) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.Bold("Timeline"))
		for _, f := range frames {
			if fm, ok := f.(map[string]any); ok {
				Frame(w, st, fm)
			}
		}
	}

	gates, _ := m["blocked_on"].([]any)
	for _, g := range gates {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintf(w, "\n%s %s\n", st.Yellow("Approval required"), str(gm, "step_name"))
		fmt.Fprintf(w, "  %s %s\n", st.Dim("task:"), str(gm, "task_id"))
		fmt.Fprintf(w, "  %s %s\n", st.Dim("step:"), str(gm, "step_id"))
		if s := str(gm, "summary"); s != "" {
			fmt.Fprintf(w, "  %s\n", strings.ReplaceAll(s, "\n", "\n  "))
		}
		if p, ok := gm["task_payload"].(map[string]any); ok && len(p) > 0 {
			fmt.Fprintf(w, "  %s\n", st.Dim("payload:"))
			var sb strings.Builder
			_ = JSON(&sb, p)
			fmt.Fprintln(w, indent(strings.TrimRight(sb.String(), "\n"), "    "))
		}
		if t, _ := gm["payload_truncated"].(bool); t {
			fmt.Fprintf(w, "  %s\n", st.Yellow("payload truncated — re-run inspect with --full"))
		}
	}

	if opt.ShowOutputs {
		if out, ok := m["outputs"].(map[string]any); ok && len(out) > 0 {
			fmt.Fprintf(w, "\n%s\n", st.Bold("Outputs"))
			var sb strings.Builder
			_ = JSON(&sb, out)
			fmt.Fprintln(w, indent(strings.TrimRight(sb.String(), "\n"), "  "))
		}
	}
	if t, _ := m["outputs_truncated"].(bool); t {
		fmt.Fprintf(w, "\n%s agentruntime inspect %s %s --full\n", st.Yellow("Outputs truncated. Full data:"), wf, run)
	}

	if opt.Hints {
		switch outcome {
		case "running":
			fmt.Fprintf(w, "\n%s agentruntime await %s %s\n", st.Dim("next:"), wf, run)
		case "awaiting_input":
			for _, g := range gates {
				if gm, ok := g.(map[string]any); ok {
					fmt.Fprintf(w, "\n%s agentruntime approve %s %s %s   (or: reject)\n", st.Dim("next:"), wf, run, str(gm, "task_id"))
				}
			}
		}
	}
}

// Frame prints one stream frame as a timeline line.
func Frame(w io.Writer, st Style, f map[string]any) {
	switch ft := str(f, "frame_type"); ft {
	case "run_started":
		fmt.Fprintf(w, "  %s run started %s\n", st.Cyan("▶"), st.Dim(str(f, "run_id")))
	case "step_completed":
		line := fmt.Sprintf("  %s step %s", st.Green("✔"), str(f, "step_id"))
		if out, ok := f["output"]; ok && out != nil {
			line += " " + st.Dim(Compact(out, 100))
		}
		fmt.Fprintln(w, line)
	case "gate_open":
		fmt.Fprintf(w, "  %s gate open %s\n", st.Yellow("⏸"), st.Dim("task "+firstTaskID(f)))
	case "gate_resolved":
		verdict := st.Red("rejected")
		if a, _ := f["approved"].(bool); a {
			verdict = st.Green("approved")
		}
		fmt.Fprintf(w, "  %s gate resolved: %s %s\n", st.Green("✓"), verdict, st.Dim("task "+str(f, "task_id")))
	case "run_terminal":
		fmt.Fprintf(w, "  %s run %s\n", st.Bold("■"), outcomeColor(st, str(f, "outcome")))
	default:
		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "  · %s %s\n", ft, st.Dim(Compact(f, 100)))
	}
}

func firstTaskID(f map[string]any) string {
	if id := str(f, "task_id"); id != "" {
		return id
	}
	if gates, ok := f["blocked_on"].([]any); ok && len(gates) > 0 {
		if gm, ok := gates[0].(map[string]any); ok {
			return str(gm, "task_id")
		}
	}
	return ""
}
