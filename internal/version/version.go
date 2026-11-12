// Package version holds build-time metadata, injected with -ldflags.
package version

import "runtime"

// Set via: -ldflags "-X github.com/agentruntime-io/agentruntime-cli/internal/version.Version=v1.2.3 ..."
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// UserAgent is sent on every MCP HTTP request.
func UserAgent() string {
	return "agentruntime-cli/" + Version + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
