package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ansh44233/mcp/internal/integrations"
)

// Connector adapts GitHub's read-only REST capabilities to the platform lifecycle.
type Connector struct {
	mu sync.RWMutex
	client *Client
	initialized bool
}

func NewConnector() *Connector { return &Connector{} }

func (c *Connector) Metadata() integrations.Metadata {
	return integrations.Metadata{ID: "github", Name: "GitHub", Version: "0.1.0", Description: "Read-only GitHub repository, branch, commit, issue and pull-request access"}
}

func (c *Connector) Initialize(_ context.Context, config integrations.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.initialized { return fmt.Errorf("GitHub connector is already initialized") }
	baseURL := strings.TrimRight(config["base_url"], "/")
	if baseURL == "" { baseURL = defaultAPIBase }
	if !strings.HasPrefix(baseURL, "https://") && !strings.HasPrefix(baseURL, "http://127.0.0.1") && !strings.HasPrefix(baseURL, "http://localhost") {
		return fmt.Errorf("GitHub API base URL must use HTTPS")
	}
	c.client = NewClientWithHTTPClient(baseURL, config["token"], &http.Client{Timeout: 15 * time.Second})
	c.initialized = true
	return nil
}

func (c *Connector) HealthCheck(ctx context.Context) error {
	c.mu.RLock()
	client, ready := c.client, c.initialized
	c.mu.RUnlock()
	if !ready { return fmt.Errorf("GitHub connector is not initialized") }
	_, err := client.Repository(ctx, "github", "gitignore")
	return err
}

func (c *Connector) Operations() []integrations.Operation {
	return []integrations.Operation{
		{ID: "repository_get", Description: "Get public or authorized repository metadata", ReadOnly: true},
		{ID: "branches_list", Description: "List repository branches", ReadOnly: true},
		{ID: "commits_list", Description: "List repository commits", ReadOnly: true},
		{ID: "issues_list", Description: "List repository issues", ReadOnly: true},
		{ID: "pull_requests_list", Description: "List repository pull requests", ReadOnly: true},
	}
}

func (c *Connector) Client() (*Client, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.initialized || c.client == nil { return nil, fmt.Errorf("GitHub connector is not initialized") }
	return c.client, nil
}

func (c *Connector) Shutdown(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client = nil
	c.initialized = false
	return nil
}
