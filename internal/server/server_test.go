package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/approvals"
	"github.com/ansh44233/mcp/internal/security"
	"github.com/ansh44233/mcp/internal/tools"
	"github.com/ansh44233/mcp/internal/workflows"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPlatformStatusToolIsRegisteredAndCallable(t *testing.T) {
	ctx := context.Background()
	runtime := NewRuntime("")
	defer runtime.Close(context.Background())
	server := runtime.Server
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
	auditResponse := httptest.NewRecorder()
	runtime.DashboardHandler().ServeHTTP(auditResponse, httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil))
	if auditResponse.Code != http.StatusOK || !strings.Contains(auditResponse.Body.String(), "platform_status") {
		t.Fatalf("platform_status call was not audited: %s", auditResponse.Body.String())
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
	runtime := NewRuntime("")
	handler := runtime.DashboardHandler()
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

func TestRuntimeCloseShutsDownManagedConnectors(t *testing.T) {
	runtime := NewRuntime("")
	if runtime == nil || runtime.Server == nil {
		t.Fatal("runtime did not construct an MCP server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("close runtime twice: %v", err)
	}
}

func TestRuntimeOwnsOptionalDurableWorkflowStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workflows.jsonl")
	runtime := NewRuntimeWithStores("", "", path)
	if runtime.workflows == nil {
		t.Fatal("configured workflow store was not initialized")
	}
	ctx := security.WithPrincipal(context.Background(), security.Principal{
		ID: "alice", TenantID: "tenant-a", Authenticated: true,
		Authentication: "test", MaxRisk: tools.RiskRead,
	})
	item, err := runtime.workflows.Create(ctx, "runtime lifecycle", []string{"github_repository_get"})
	if err != nil {
		t.Fatal(err)
	}
	healthResponse := httptest.NewRecorder()
	runtime.DashboardHandler().ServeHTTP(healthResponse, httptest.NewRequest(http.MethodGet, "/api/v1/workflows/health", nil))
	if healthResponse.Code != http.StatusOK || !strings.Contains(healthResponse.Body.String(), `"persistent":true`) || !strings.Contains(healthResponse.Body.String(), `"workflows":1`) {
		t.Fatalf("workflow health endpoint did not reflect runtime store: status=%d body=%s", healthResponse.Code, healthResponse.Body.String())
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("close runtime: %v", err)
	}

	recovered, err := workflows.NewFileStore(path, 1000)
	if err != nil {
		t.Fatalf("reopen workflow journal: %v", err)
	}
	defer recovered.Close()
	got, err := recovered.Get(ctx, item.ID)
	if err != nil || got.ID != item.ID || got.Status != workflows.Pending {
		t.Fatalf("workflow did not survive runtime shutdown: %+v %v", got, err)
	}
}

func TestRuntimeOwnsOptionalDurableApprovalStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.jsonl")
	runtime := NewRuntimeWithAllStores("", "", "", path)
	if runtime.approvals == nil {
		t.Fatal("approval store was not initialized")
	}
	ctx := security.WithPrincipal(context.Background(), security.Principal{
		ID: "alice", TenantID: "tenant-a", Authenticated: true,
		Authentication: "test", MaxRisk: tools.RiskWrite,
	})
	_, err := runtime.approvals.Create(ctx, tools.Definition{
		ID: "github_issue_create", Provider: "github", Name: "issue_create", Risk: tools.RiskWrite,
	}, json.RawMessage(`{"owner":"acme","repo":"demo","title":"test"}`), time.Minute)
	if err != nil {
		t.Fatalf("create approval request: %v", err)
	}
	healthResponse := httptest.NewRecorder()
	runtime.DashboardHandler().ServeHTTP(healthResponse, httptest.NewRequest(http.MethodGet, "/api/v1/approvals/health", nil))
	if healthResponse.Code != http.StatusOK ||
		!strings.Contains(healthResponse.Body.String(), `"persistent":true`) ||
		!strings.Contains(healthResponse.Body.String(), `"requests":1`) {
		t.Fatalf("approval health endpoint did not reflect runtime store: status=%d body=%s", healthResponse.Code, healthResponse.Body.String())
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	recovered, err := approvals.NewFileStore(path, 10000)
	if err != nil {
		t.Fatalf("reopen approval journal: %v", err)
	}
	defer recovered.Close()
	health := recovered.Health()
	if health.Requests != 1 || health.Sequence != 1 || !health.Persistent || !health.Healthy {
		t.Fatalf("approval request did not survive runtime shutdown: %+v", health)
	}
}
