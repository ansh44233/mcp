package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegisterMCPWithAuthorizationBlocksExecution(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(Definition{
		ID: "repo_read", Provider: "github", Name: "Read repository",
		Description: "Read repository metadata.", Risk: RiskRead,
		InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
	}); err != nil {
		t.Fatalf("register definition: %v", err)
	}

	executed := false
	server := mcp.NewServer(&mcp.Implementation{Name: "authorization-test", Version: "0.0.1"}, nil)
	if err := RegisterMCPWithAuthorization(
		server, registry,
		func(context.Context, Definition, json.RawMessage) (any, error) {
			executed = true
			return map[string]any{"ok": true}, nil
		},
		ReadOnlyPolicy(),
		func(context.Context, Definition) error {
			return context.Canceled
		},
	); err != nil {
		t.Fatalf("register MCP tools: %v", err)
	}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "authorization-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "repo_read", Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !result.IsError {
		t.Fatal("tool should be rejected by request authorizer")
	}
	if executed {
		t.Fatal("executor ran despite request authorization denial")
	}
	if len(result.Content) == 0 {
		t.Fatal("expected authorization error content")
	}
	if text, ok := result.Content[0].(*mcp.TextContent); ok && !strings.Contains(text.Text, "authorize principal") {
		t.Fatalf("unexpected error content: %q", text.Text)
	}
}
