package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ansh44233/mcp/internal/integrations"
)

func TestClientRepositoryUsesReadOnlyAuthenticatedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet { t.Fatalf("unexpected method %s", r.Method) }
		if r.URL.Path != "/repos/octo/project" { t.Fatalf("unexpected path %s", r.URL.Path) }
		if r.Header.Get("Authorization") != "Bearer test-token" { t.Fatal("authorization header missing") }
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":42,"full_name":"octo/project","private":false,"default_branch":"main"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTPClient(server.URL, "test-token", server.Client())
	repository, err := client.Repository(context.Background(), "octo", "project")
	if err != nil { t.Fatal(err) }
	if repository.FullName != "octo/project" || repository.DefaultBranch != "main" {
		t.Fatalf("unexpected repository: %#v", repository)
	}
}

func TestClientBoundsPaginationAndRejectsInvalidState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" || r.URL.Query().Get("per_page") != "100" {
			t.Fatalf("pagination was not bounded: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()
	client := NewClientWithHTTPClient(server.URL, "", server.Client())
	if _, err := client.Branches(context.Background(), "octo", "project", 0, 500); err != nil { t.Fatal(err) }
	if _, err := client.Issues(context.Background(), "octo", "project", "pending", 1, 30); err == nil {
		t.Fatal("expected invalid state error")
	}
}

func TestConnectorLifecycle(t *testing.T) {
	connector := NewConnector()
	if err := connector.HealthCheck(context.Background()); err == nil { t.Fatal("expected uninitialized health check error") }
	if err := connector.Initialize(context.Background(), integrations.Config{"base_url": "https://api.github.com"}); err != nil { t.Fatal(err) }
	if _, err := connector.Client(); err != nil { t.Fatal(err) }
	if err := connector.Shutdown(context.Background()); err != nil { t.Fatal(err) }
	if _, err := connector.Client(); err == nil { t.Fatal("expected client unavailable after shutdown") }
}

func TestConnectorRejectsInsecureRemoteBaseURL(t *testing.T) {
	connector := NewConnector()
	if err := connector.Initialize(context.Background(), integrations.Config{"base_url": "http://example.com"}); err == nil {
		t.Fatal("expected insecure remote URL rejection")
	}
}
