package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegisterMCPEnforcesPolicyBeforeExecution(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(Definition{
		ID: "dangerous_write", Provider: "example", Name: "write",
		Description: "A write operation.", Risk: RiskWrite,
		InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
	}); err != nil {
		t.Fatalf("register definition: %v", err)
	}

	executed := false
	server := mcp.NewServer(&mcp.Implementation{Name: "policy-test", Version: "0.0.1"}, nil)
	if err := RegisterMCP(server, registry, func(context.Context, Definition, json.RawMessage) (any, error) {
		executed = true
		return map[string]any{"ok": true}, nil
	}); err != nil {
		t.Fatalf("register MCP tools: %v", err)
	}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "policy-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dangerous_write", Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !result.IsError {
		t.Fatal("write tool should be rejected by default policy")
	}
	if executed {
		t.Fatal("executor ran despite policy denial")
	}
}
