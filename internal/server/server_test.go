package server

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPlatformStatusToolIsRegisteredAndCallable(t *testing.T) {
	ctx := context.Background()
	server := New()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "universal-mcp-test", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "platform_status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call platform_status: %v", err)
	}
	if result.IsError {
		t.Fatal("platform_status returned an MCP tool error")
	}
	if result.StructuredContent == nil {
		t.Fatal("platform_status did not return structured content")
	}
}

func TestGitHubReadOnlyToolsAreDiscoverable(t *testing.T) {
	ctx := context.Background()
	server := New()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "catalog-test", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	expected := map[string]bool{
		"github_repository_get":     false,
		"github_branches_list":      false,
		"github_commits_list":       false,
		"github_issues_list":        false,
		"github_pull_requests_list": false,
	}
	for _, tool := range listed.Tools {
		if _, ok := expected[tool.Name]; ok {
			expected[tool.Name] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("expected GitHub tool %q to be discoverable", name)
		}
	}
}
