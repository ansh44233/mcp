package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Executor runs a registered capability. Implementations should enforce
// provider-specific authorization and must treat arguments as untrusted input.
type Executor func(context.Context, Definition, json.RawMessage) (any, error)

// RegisterMCP publishes every catalog entry as an MCP tool. The SDK validates
// incoming arguments against each definition's JSON Schema before execution.
func RegisterMCP(server *mcp.Server, registry *Registry, execute Executor) error {
	if server == nil {
		return fmt.Errorf("MCP server is required")
	}
	if registry == nil {
		return fmt.Errorf("tool registry is required")
	}
	if execute == nil {
		return fmt.Errorf("tool executor is required")
	}

	for _, definition := range registry.List() {
		definition := definition
		tool := &mcp.Tool{
			Name:        definition.ID,
			Description: definition.Description,
			InputSchema: json.RawMessage(append([]byte(nil), definition.InputSchema...)),
		}
		mcp.AddTool(server, tool, func(ctx context.Context, _ *mcp.CallToolRequest, input map[string]any) (*mcp.CallToolResult, any, error) {
			arguments, err := json.Marshal(input)
			if err != nil {
				return nil, nil, fmt.Errorf("encode arguments for %q: %w", definition.ID, err)
			}
			output, err := execute(ctx, definition, arguments)
			if err != nil {
				return nil, nil, fmt.Errorf("execute %q: %w", definition.ID, err)
			}
			return nil, output, nil
		})
	}
	return nil
}
