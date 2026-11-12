// Package mcpclient is a thin wrapper over the MCP go-sdk for talking to
// AgentRuntime Platform MCP over streamable HTTP.
package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agentruntime-io/agentruntime-cli/internal/version"
)

// ProgressFunc receives MCP notifications/progress while a tool call is running.
type ProgressFunc func(message string, progress, total float64)

// Client is a connected MCP session.
type Client struct {
	sess *mcp.ClientSession

	mu       sync.RWMutex
	progress ProgressFunc
	seq      atomic.Int64
}

// ToolError is returned when the server reports a tool-level error (isError).
type ToolError struct {
	Tool    string
	Message string
}

func (e *ToolError) Error() string { return e.Message }

// Result is a decoded tool result.
type Result struct {
	// Data is the structured content, or parsed JSON text, or {"text": "..."}.
	Data any
}

// Map returns Data as an object, or nil.
func (r *Result) Map() map[string]any {
	m, _ := r.Data.(map[string]any)
	return m
}

type headerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (t *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	r := req.Clone(req.Context())
	if t.token != "" {
		r.Header.Set("Authorization", "Bearer "+t.token)
	}
	r.Header.Set("User-Agent", version.UserAgent())
	return base.RoundTrip(r)
}

// Connect opens an MCP session. token may be empty for unauthenticated local servers.
func Connect(ctx context.Context, endpoint, token string) (*Client, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, errors.New("no MCP endpoint configured")
	}
	c := &Client{}
	client := mcp.NewClient(
		&mcp.Implementation{Name: "agentruntime-cli", Version: version.Version},
		&mcp.ClientOptions{
			ProgressNotificationHandler: func(_ context.Context, req *mcp.ProgressNotificationClientRequest) {
				c.mu.RLock()
				fn := c.progress
				c.mu.RUnlock()
				if fn != nil && req != nil && req.Params != nil {
					fn(req.Params.Message, req.Params.Progress, req.Params.Total)
				}
			},
		},
	)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           &http.Client{Transport: &headerRoundTripper{token: strings.TrimSpace(token)}},
		DisableStandaloneSSE: true,
	}
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, explainConnectError(endpoint, token, err)
	}
	c.sess = sess
	return c, nil
}

func explainConnectError(endpoint, token string, err error) error {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "401") || strings.Contains(low, "unauthorized"):
		if token == "" {
			return fmt.Errorf("%s rejected the request (401): no token configured. Run `agentruntime login`", endpoint)
		}
		return fmt.Errorf("%s rejected the token (401): it may be invalid, expired or revoked. Run `agentruntime login`", endpoint)
	case strings.Contains(low, "403") || strings.Contains(low, "forbidden"):
		return fmt.Errorf("%s denied access (403): the token lacks permission for this workspace", endpoint)
	case strings.Contains(low, "connection refused"), strings.Contains(low, "no such host"),
		strings.Contains(low, "dial tcp"), strings.Contains(low, "context deadline exceeded"):
		return fmt.Errorf("cannot reach %s: %w", endpoint, err)
	}
	return fmt.Errorf("connect to %s: %w", endpoint, err)
}

// Close ends the session.
func (c *Client) Close() error {
	if c == nil || c.sess == nil {
		return nil
	}
	return c.sess.Close()
}

// OnProgress registers a handler for progress notifications (nil to clear).
func (c *Client) OnProgress(fn ProgressFunc) {
	c.mu.Lock()
	c.progress = fn
	c.mu.Unlock()
}

// ListTools returns every tool, following pagination.
func (c *Client) ListTools(ctx context.Context) ([]*mcp.Tool, error) {
	var all []*mcp.Tool
	params := &mcp.ListToolsParams{}
	for {
		res, err := c.sess.ListTools(ctx, params)
		if err != nil {
			return nil, err
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" {
			return all, nil
		}
		params = &mcp.ListToolsParams{Cursor: res.NextCursor}
	}
}

// Call invokes a tool. Pass wantProgress to request live progress notifications.
func (c *Client) Call(ctx context.Context, name string, args map[string]any, wantProgress bool) (*Result, error) {
	if args == nil {
		args = map[string]any{}
	}
	params := &mcp.CallToolParams{Name: name, Arguments: args}
	if wantProgress {
		params.SetProgressToken(fmt.Sprintf("agentruntime-cli-%d", c.seq.Add(1)))
	}
	res, err := c.sess.CallTool(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if res.IsError {
		msg := TextOf(res.Content)
		if msg == "" {
			msg = "unknown tool error"
		}
		return nil, &ToolError{Tool: name, Message: msg}
	}
	if res.StructuredContent != nil {
		return &Result{Data: normalize(res.StructuredContent)}, nil
	}
	if text := TextOf(res.Content); text != "" {
		var v any
		if json.Unmarshal([]byte(text), &v) == nil {
			return &Result{Data: v}, nil
		}
		return &Result{Data: map[string]any{"text": text}}, nil
	}
	return &Result{Data: map[string]any{}}, nil
}

// normalize round-trips through JSON so the data is plain maps/slices/float64.
func normalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return out
}

// TextOf returns the first non-empty text block.
func TextOf(items []mcp.Content) string {
	for _, item := range items {
		if tc, ok := item.(*mcp.TextContent); ok {
			if s := strings.TrimSpace(tc.Text); s != "" {
				return s
			}
		}
	}
	return ""
}
