package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegisterMCPPublishesAndExecutesCatalogTools(t *testing.T) {
	registry := NewRegistry()
	definition := validDefinition("github_repo_get")
	if err := registry.Register(definition); err != nil {
		t.Fatal(err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "catalog-test", Version: "0.0.1"}, nil)
	called := false
	err := RegisterMCP(server, registry, func(_ context.Context, got Definition, args json.RawMessage) (any, error) {
		called = true
		if got.ID != definition.ID {
			t.Fatalf("executor received tool %q", got.ID)
		}
		var input map[string]any
		if err := json.Unmarshal(args, &input); err != nil {
			t.Fatal(err)
		}
		if input["owner"] != "octo" {
			t.Fatalf("unexpected arguments: %#v", input)
		}
		return map[string]any{"full_name": "octo/project"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "catalog-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 1 || listed.Tools[0].Name != definition.ID {
		t.Fatalf("unexpected tool listing: %#v", listed.Tools)
	}

	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      definition.ID,
		Arguments: map[string]any{"owner": "octo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || !called {
		t.Fatalf("tool did not execute successfully: result=%#v called=%v", result, called)
	}
	if result.StructuredContent == nil {
		t.Fatal("expected structured output")
	}
}

func TestRegisterMCPRejectsMissingDependencies(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "catalog-test", Version: "0.0.1"}, nil)
	registry := NewRegistry()
	executor := Executor(func(context.Context, Definition, json.RawMessage) (any, error) {
		return nil, nil
	})
	tests := []struct {
		name     string
		server   *mcp.Server
		registry *Registry
		executor Executor
	}{
		{
			name:     "nil server",
			server:   nil,
			registry: registry,
			executor: executor,
		},
		{
			name:     "nil registry",
			server:   server,
			registry: nil,
			executor: executor,
		},
		{
			name:     "nil executor",
			server:   server,
			registry: registry,
			executor: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := RegisterMCP(test.server, test.registry, test.executor); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
