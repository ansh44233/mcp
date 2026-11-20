package server

import (
	"context"
	"runtime"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	Name    = "universal-mcp"
	Version = "0.1.0"
)

var startedAt = time.Now()

// New constructs the MCP server and registers the platform's built-in tools.
// Provider integrations are registered here as they are implemented.
func New() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    Name,
		Version: Version,
	}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "platform_status",
		Description: "Return the Universal MCP server version, uptime, Go runtime and supported transports.",
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		result := map[string]any{
			"name":       Name,
			"version":    Version,
			"status":     "ok",
			"uptime_sec": int64(time.Since(startedAt).Seconds()),
			"go_version": runtime.Version(),
			"transports": []string{"stdio", "streamable-http"},
			"integrations": []string{},
		}
		return nil, result, nil
	})

	return s
}
