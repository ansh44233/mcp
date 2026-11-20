package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
		"github_file_get":           false,
		"github_tree_get":           false,
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

func TestDashboardUsesRegisteredMCPDefinitions(t *testing.T) {
	handler := DashboardHandler()
	toolsResponse := httptest.NewRecorder()
	handler.ServeHTTP(toolsResponse, httptest.NewRequest(http.MethodGet, "/api/v1/tools", nil))
	if toolsResponse.Code != http.StatusOK {
		t.Fatalf("tools endpoint status = %d", toolsResponse.Code)
	}
	for _, name := range []string{
		"platform_status", "github_repository_get", "github_file_get", "github_tree_get",
	} {
		if !strings.Contains(toolsResponse.Body.String(), name) {
			t.Errorf("dashboard tool catalog is missing %q", name)
		}
	}

	connectorResponse := httptest.NewRecorder()
	handler.ServeHTTP(connectorResponse, httptest.NewRequest(http.MethodGet, "/api/v1/connectors", nil))
	if connectorResponse.Code != http.StatusOK || !strings.Contains(connectorResponse.Body.String(), "github") {
		t.Fatalf("unexpected connector inventory response: %s", connectorResponse.Body.String())
	}
}
