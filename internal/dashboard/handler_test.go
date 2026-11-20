package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("unexpected health response: %s", rec.Body.String())
	}
}

func TestStatusEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.Name != "universal-mcp" || got.Status != "ok" {
		t.Fatalf("unexpected status payload: %+v", got)
	}
	if got.ToolCount != 8 || len(got.Tools) != 8 {
		t.Fatalf("expected 8 registered tools, got count=%d tools=%v", got.ToolCount, got.Tools)
	}
	if len(got.Integrations) != 1 || got.Integrations[0] != "github" {
		t.Fatalf("expected GitHub integration in dashboard status, got %v", got.Integrations)
	}
}

func TestDashboardRoot(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "Universal MCP") {
		t.Fatal("dashboard HTML does not contain product title")
	}
	if !strings.Contains(rec.Body.String(), "Connected · read-only") {
		t.Fatal("dashboard does not reflect the GitHub connector")
	}
}
