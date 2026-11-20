package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testConfig() Config {
	return Config{
		Version:    "0.1.0",
		Transports: []string{"stdio", "streamable-http"},
		Connectors: []ConnectorInfo{{
			ID: "github", Name: "GitHub", Version: "0.1.0",
			Description: "Read-only repository access",
			Operations: []string{"repository_get", "file_get"}, ReadOnly: true,
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
