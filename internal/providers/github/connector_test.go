package github

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ansh44233/mcp/internal/integrations"
)

func TestClientRepositoryUsesReadOnlyAuthenticatedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/repos/octo/project" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("authorization header missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":42,"full_name":"octo/project","private":false,"default_branch":"main"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTPClient(server.URL, "test-token", server.Client())
	repository, err := client.Repository(context.Background(), "octo", "project")
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := client.Branches(context.Background(), "octo", "project", 0, 500); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Issues(context.Background(), "octo", "project", "pending", 1, 30); err == nil {
		t.Fatal("expected invalid state error")
	}
}

func TestClientFiltersPullRequestsFromIssues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"number":1,"title":"Issue","state":"open"},
			{"number":2,"title":"PR","state":"open","pull_request":{"url":"https://api.github.com/repos/o/p/pulls/2"}}
		]`))
	}))
	defer server.Close()

	client := NewClientWithHTTPClient(server.URL, "", server.Client())
	issues, err := client.Issues(context.Background(), "octo", "project", "open", 1, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 1 || issues[0].Number != 1 {
		t.Fatalf("unexpected issue results: %#v", issues)
	}
}

func TestConnectorLifecycle(t *testing.T) {
	connector := NewConnector()
	if err := connector.HealthCheck(context.Background()); err == nil {
		t.Fatal("expected uninitialized health check error")
	}
	if err := connector.Initialize(context.Background(), integrations.Config{"base_url": "https://api.github.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := connector.Client(); err != nil {
		t.Fatal(err)
	}
	if err := connector.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := connector.Client(); err == nil {
		t.Fatal("expected client unavailable after shutdown")
	}
}

func TestConnectorRejectsInsecureRemoteBaseURL(t *testing.T) {
	connector := NewConnector()
	if err := connector.Initialize(context.Background(), integrations.Config{"base_url": "http://example.com"}); err == nil {
		t.Fatal("expected insecure remote URL rejection")
	}
}

func TestClientReadsAndDecodesTextFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/octo/project/contents/docs/readme.md" {
			t.Fatalf("unexpected contents path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("ref") != "main" {
			t.Fatalf("unexpected ref: %s", r.URL.RawQuery)
		}
		encoded := base64.StdEncoding.EncodeToString([]byte("# hello"))
		_, _ = w.Write([]byte(`{"name":"readme.md","path":"docs/readme.md","size":7,"encoding":"base64","content":"` + encoded + `"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTPClient(server.URL, "", server.Client())
	file, err := client.Contents(context.Background(), "octo", "project", "docs/readme.md", "main")
	if err != nil {
		t.Fatal(err)
	}
	if file.DecodedText != "# hello" || file.Content != "" {
		t.Fatalf("unexpected decoded file: %#v", file)
	}
}

func TestClientRejectsUnsafeAndOversizedFilePaths(t *testing.T) {
	client := NewClientWithHTTPClient("https://api.github.com", "", nil)
	if _, err := client.Contents(context.Background(), "octo", "project", "../secret", "main"); err == nil {
		t.Fatal("expected path traversal rejection")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"large.bin","path":"large.bin","size":1048577,"encoding":"base64","content":""}`))
	}))
	defer server.Close()
	client = NewClientWithHTTPClient(server.URL, "", server.Client())
	if _, err := client.Contents(context.Background(), "octo", "project", "large.bin", "main"); err == nil {
		t.Fatal("expected oversized file rejection")
	}
}

func TestClientListsRecursiveTree(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/octo/project/git/trees/main" || r.URL.Query().Get("recursive") != "1" {
			t.Fatalf("unexpected tree request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"sha":"abc","truncated":false,"tree":[{"path":"README.md","type":"blob","sha":"def","size":10}]}`))
	}))
	defer server.Close()
	client := NewClientWithHTTPClient(server.URL, "", server.Client())
	tree, err := client.Tree(context.Background(), "octo", "project", "main")
	if err != nil {
		t.Fatal(err)
	}
	if tree.Truncated || len(tree.Tree) != 1 || tree.Tree[0].Path != "README.md" {
		t.Fatalf("unexpected tree: %#v", tree)
	}
}

func TestClientReturnsTypedRateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1900000000")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer server.Close()
	client := NewClientWithHTTPClient(server.URL, "", server.Client())
	_, err := client.Repository(context.Background(), "octo", "project")
	var rateLimit *RateLimitError
	if !errors.As(err, &rateLimit) {
		t.Fatalf("expected RateLimitError, got %v", err)
	}
	if rateLimit.Remaining != "0" || rateLimit.ResetAt.IsZero() {
		t.Fatalf("missing rate limit metadata: %#v", rateLimit)
	}
}
