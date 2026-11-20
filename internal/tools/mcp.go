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
	return RegisterMCPWithPolicy(server, registry, execute, ReadOnlyPolicy())
}

// AuthorizeFunc evaluates a tool against trusted request context. Implementations
// must derive identity from server-side authentication, never tool arguments.
type AuthorizeFunc func(context.Context, Definition) error

// RegisterMCPWithPolicy publishes catalog tools with an execution-time policy.
func RegisterMCPWithPolicy(server *mcp.Server, registry *Registry, execute Executor, policy Policy) error {
	return RegisterMCPWithAuthorization(server, registry, execute, policy, nil)
}

// RegisterMCPWithAuthorization adds a request-context authorizer after the
// static capability policy. The callback runs immediately before execution.
func RegisterMCPWithAuthorization(server *mcp.Server, registry *Registry, execute Executor, policy Policy, authorize AuthorizeFunc) error {
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
			if err := policy.Authorize(definition); err != nil {
				return nil, nil, fmt.Errorf("authorize %q: %w", definition.ID, err)
			}
			if authorize != nil {
				if err := authorize(ctx, definition); err != nil {
					return nil, nil, fmt.Errorf("authorize principal for %q: %w", definition.ID, err)
				}
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
