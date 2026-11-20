package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/approvals"
	"github.com/ansh44233/mcp/internal/audit"
	"github.com/ansh44233/mcp/internal/workflows"
	"github.com/ansh44233/mcp/internal/security"
	"github.com/ansh44233/mcp/internal/tools"
)

func testConfig() Config {
	return Config{
		Version:    "0.1.0",
		Transports: []string{"stdio", "streamable-http"},
		Connectors: []ConnectorInfo{{
			ID: "github", Name: "GitHub", Version: "0.1.0",
			Description: "Read-only repository access",
			Operations:  []string{"repository_get", "file_get"}, ReadOnly: true,
		}},
		Tools: []ToolInfo{
			{ID: "platform_status", Provider: "platform", Name: "status", Description: "Platform status", Risk: "read"},
			{ID: "github_repository_get", Provider: "github", Name: "repository_get", Description: "Get repository metadata", Risk: "read"},
			{ID: "github_file_get", Provider: "github", Name: "file_get", Description: "Read a text file", Risk: "read"},
		},
	}
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	HandlerWithConfig(testConfig()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("unexpected health response: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestStatusEndpointReflectsConfig(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	HandlerWithConfig(testConfig()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.Name != "universal-mcp" || got.Status != "ok" || got.Version != "0.1.0" {
		t.Fatalf("unexpected status payload: %+v", got)
	}
	if got.ToolCount != 3 || len(got.Integrations) != 1 || got.Integrations[0] != "github" {
		t.Fatalf("status did not reflect supplied configuration: %+v", got)
	}
}

func TestToolCatalogEndpointAndFilters(t *testing.T) {
	handler := HandlerWithConfig(testConfig())
	for _, test := range []struct {
		path string
		want int
	}{
		{"/api/v1/tools", 3},
		{"/api/v1/tools?provider=github", 2},
		{"/api/v1/tools?q=file", 1},
		{"/api/v1/tools?provider=unknown", 0},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, test.path, nil))
		var got struct {
			Tools []ToolInfo `json:"tools"`
			Count int        `json:"count"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode %s: %v", test.path, err)
		}
		if got.Count != test.want || len(got.Tools) != test.want {
			t.Errorf("%s returned %d tools, want %d", test.path, got.Count, test.want)
		}
	}
}

func TestConnectorInventoryEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	HandlerWithConfig(testConfig()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/connectors", nil))
	var got struct {
		Connectors []ConnectorInfo `json:"connectors"`
		Count      int             `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 1 || len(got.Connectors[0].Operations) != 2 || !got.Connectors[0].ReadOnly {
		t.Fatalf("unexpected connector inventory: %+v", got)
	}
}

func TestDashboardRoot(t *testing.T) {
	rec := httptest.NewRecorder()
	HandlerWithConfig(testConfig()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Universal MCP") {
		t.Fatalf("unexpected dashboard response: status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Search the exact tool definitions") {
		t.Fatal("dashboard does not contain the tool catalog interface")
	}
}

func TestConnectorHealthCheckEndpoint(t *testing.T) {
	config := testConfig()
	config.HealthChecks = map[string]func(context.Context) error{
		"github": func(context.Context) error { return nil },
		"broken": func(context.Context) error { return context.DeadlineExceeded },
	}
	handler := HandlerWithConfig(config)

	for _, test := range []struct {
		id       string
		wantCode int
		wantBody string
	}{
		{"github", http.StatusOK, `"status":"healthy"`},
		{"broken", http.StatusOK, `"status":"unhealthy"`},
		{"missing", http.StatusNotFound, ""},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/connectors/"+test.id+"/health-check", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != test.wantCode {
			t.Errorf("%s: status=%d want=%d", test.id, rec.Code, test.wantCode)
		}
		if test.wantBody != "" && !strings.Contains(rec.Body.String(), test.wantBody) {
			t.Errorf("%s: body %q does not contain %q", test.id, rec.Body.String(), test.wantBody)
		}
	}
}

func TestAuditEventsEndpoint(t *testing.T) {
	config := testConfig()
	config.AuditEvents = func(limit int) []audit.Event {
		if limit != 2 {
			t.Errorf("limit = %d, want 2", limit)
		}
		return []audit.Event{{Sequence: 7, ToolID: "github_repository_get", Outcome: "succeeded"}}
	}
	rec := httptest.NewRecorder()
	HandlerWithConfig(config).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=2", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sequence":7`) {
		t.Fatalf("unexpected audit response: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func approvalContext(id, tenant string, canApprove bool) context.Context {
	return security.WithPrincipal(context.Background(), security.Principal{
		ID: id, TenantID: tenant, Authenticated: true, Authentication: "test",
		CanApprove: canApprove, MaxRisk: tools.RiskDestructive,
	})
}

func TestApprovalDashboardAPIEnforcesRequesterAndReviewerScopes(t *testing.T) {
	store := approvals.NewStore(10)
	definition := tools.Definition{ID: "repo_update", Provider: "github", Risk: tools.RiskWrite}
	first, err := store.Create(approvalContext("alice", "tenant-a", false), definition, json.RawMessage(`{"x":1}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(approvalContext("carol", "tenant-a", false), definition, json.RawMessage(`{"x":2}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig()
	config.ApprovalStore = store
	handler := HandlerWithConfig(config)

	unauth := httptest.NewRecorder()
	handler.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil))
	if unauth.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated list status = %d, want %d", unauth.Code, http.StatusForbidden)
	}

	ownerReq := httptest.NewRequest(http.MethodGet, "/api/v1/approvals", nil)
	ownerReq = ownerReq.WithContext(approvalContext("alice", "tenant-a", false))
	ownerRec := httptest.NewRecorder()
	handler.ServeHTTP(ownerRec, ownerReq)
	var ownerResult struct {
		Requests []approvals.Request `json:"requests"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(ownerRec.Body.Bytes(), &ownerResult); err != nil {
		t.Fatal(err)
	}
	if ownerRec.Code != http.StatusOK || ownerResult.Count != 1 || ownerResult.Requests[0].ID != first.ID {
		t.Fatalf("requester list was not scoped: status=%d result=%+v", ownerRec.Code, ownerResult)
	}

	decision := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+first.ID+"/decision", strings.NewReader(`{"approve":true,"reason":"reviewed"}`))
	decision = decision.WithContext(approvalContext("reviewer", "tenant-a", true))
	decisionRec := httptest.NewRecorder()
	handler.ServeHTTP(decisionRec, decision)
	if decisionRec.Code != http.StatusOK || !strings.Contains(decisionRec.Body.String(), `"status":"approved"`) {
		t.Fatalf("review decision failed: status=%d body=%s", decisionRec.Code, decisionRec.Body.String())
	}
}

func TestApprovalDecisionRequiresExplicitBooleanAndBoundedJSON(t *testing.T) {
	store := approvals.NewStore(10)
	definition := tools.Definition{ID: "repo_update", Provider: "github", Risk: tools.RiskWrite}
	request, err := store.Create(approvalContext("alice", "tenant-a", false), definition, json.RawMessage(`{}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig()
	config.ApprovalStore = store
	handler := HandlerWithConfig(config)
	for _, body := range []string{`{"reason":"missing decision"}`, `{"approve":true,"unknown":1}`, `{"approve":true} {"approve":false}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+request.ID+"/decision", strings.NewReader(body))
		req = req.WithContext(approvalContext("reviewer", "tenant-a", true))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("payload %q status = %d, want %d", body, rec.Code, http.StatusBadRequest)
		}
	}
}

func TestBuiltDashboardStaticAssetsAndSPAFallback(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("<html>react-dashboard</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "assets", "app.js"), []byte("console.log('dashboard')"), 0o644); err != nil {
		t.Fatal(err)
	}

	handler := HandlerWithConfig(Config{StaticDir: directory})
	for _, test := range []struct {
		path string
		want string
		code int
	}{
		{"/", "react-dashboard", http.StatusOK},
		{"/assets/app.js", "console.log", http.StatusOK},
		{"/connectors/github", "react-dashboard", http.StatusOK},
		{"/assets/missing.js", "", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, test.path, nil))
		if rec.Code != test.code {
			t.Errorf("%s: status=%d want=%d body=%s", test.path, rec.Code, test.code, rec.Body.String())
		}
		if test.want != "" && !strings.Contains(rec.Body.String(), test.want) {
			t.Errorf("%s: body %q does not contain %q", test.path, rec.Body.String(), test.want)
		}
	}
}

func TestMissingStaticBuildFallsBackToEmbeddedDashboard(t *testing.T) {
	config := testConfig()
	config.StaticDir = filepath.Join(t.TempDir(), "missing-dist")
	rec := httptest.NewRecorder()
	HandlerWithConfig(config).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Universal MCP") {
		t.Fatalf("missing build should use embedded fallback: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWorkflowHealthEndpoint(t *testing.T) {
	config := testConfig()
	config.WorkflowHealth = func() workflows.Health {
		return workflows.Health{Persistent: true, Healthy: true, Workflows: 3, Sequence: 9}
	}
	rec := httptest.NewRecorder()
	HandlerWithConfig(config).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/workflows/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got workflows.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode workflow health: %v", err)
	}
	if !got.Persistent || !got.Healthy || got.Workflows != 3 || got.Sequence != 9 {
		t.Fatalf("unexpected workflow health: %+v", got)
	}
}

func TestWorkflowHealthEndpointWithoutStore(t *testing.T) {
	rec := httptest.NewRecorder()
	HandlerWithConfig(testConfig()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/workflows/health", nil))
	var got workflows.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode workflow health: %v", err)
	}
	if rec.Code != http.StatusOK || got.Persistent || got.Healthy {
		t.Fatalf("unexpected unconfigured workflow health: status=%d health=%+v", rec.Code, got)
	}
}

func TestApprovalHealthEndpoint(t *testing.T) {
	config := testConfig()
	config.ApprovalHealth = func() approvals.Health {
		return approvals.Health{Persistent: true, Healthy: true, Requests: 4, Sequence: 7}
	}
	rec := httptest.NewRecorder()
	HandlerWithConfig(config).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/approvals/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got approvals.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode approval health: %v", err)
	}
	if !got.Persistent || !got.Healthy || got.Requests != 4 || got.Sequence != 7 {
		t.Fatalf("unexpected approval health: %+v", got)
	}
}

func TestApprovalHealthEndpointWithoutStore(t *testing.T) {
	rec := httptest.NewRecorder()
	HandlerWithConfig(testConfig()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/approvals/health", nil))
	var got approvals.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode approval health: %v", err)
	}
	if rec.Code != http.StatusOK || got.Persistent || got.Healthy {
		t.Fatalf("unexpected unconfigured approval health: status=%d health=%+v", rec.Code, got)
	}
}
