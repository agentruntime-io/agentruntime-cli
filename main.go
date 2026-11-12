// Command agentruntime is the AgentRuntime CLI, a client for Platform MCP.
package main

import (
	"os"

	"github.com/agentruntime-io/agentruntime-cli/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
