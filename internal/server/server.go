package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ansh44233/mcp/internal/dashboard"
	"github.com/ansh44233/mcp/internal/integrations"
	githubprovider "github.com/ansh44233/mcp/internal/providers/github"
	platformtools "github.com/ansh44233/mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	Name    = "universal-mcp"
	Version = "0.1.0"
)

var startedAt = time.Now()

// Runtime owns the MCP server and the connector lifecycle manager.
type Runtime struct {
	Server  *mcp.Server
	manager *integrations.Manager
}

// Close gracefully shuts down all managed provider connectors.
func (r *Runtime) Close(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Close(ctx)
}

// New constructs the MCP server, built-in tools and configured provider tools.
func New() *mcp.Server {
	return NewRuntime(os.Getenv("GITHUB_TOKEN")).Server
}

// NewWithGitHubToken constructs the platform with an optional GitHub token.
func NewWithGitHubToken(token string) *mcp.Server {
	return NewRuntime(token).Server
}

// NewRuntime constructs the MCP server and retains ownership of provider lifecycles.
// The token is held only in the connector's in-memory HTTP client.
func NewRuntime(token string) *Runtime {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    Name,
		Version: Version,
	}, nil)

	connectorRegistry := integrations.NewRegistry()
	connectorManager := integrations.NewManager(connectorRegistry)
	githubConnector := githubprovider.NewConnector()
	if err := connectorManager.Register(context.Background(), githubConnector, integrations.Config{
		"token": token,
	}); err != nil {
		panic(fmt.Errorf("register GitHub connector: %w", err))
	}
	registeredGitHub, ok := connectorRegistry.Get("github")
	if !ok {
		panic("GitHub connector missing after successful registration")
	}
	githubClient, err := registeredGitHub.(*githubprovider.Connector).Client()
	if err != nil {
		panic(err)
	}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "platform_status",
		Description: "Return the Universal MCP server version, uptime, Go runtime and supported transports.",
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		result := map[string]any{
			"name":         Name,
			"version":      Version,
			"status":       "ok",
			"uptime_sec":   int64(time.Since(startedAt).Seconds()),
			"go_version":   runtime.Version(),
			"transports":   []string{"stdio", "streamable-http"},
			"integrations": []string{"github"},
		}
		return nil, result, nil
	})

	catalog := platformtools.NewRegistry()
	for _, definition := range githubToolDefinitions() {
		if err := catalog.Register(definition); err != nil {
			panic(fmt.Errorf("register tool %q: %w", definition.ID, err))
		}
	}
	if err := platformtools.RegisterMCPWithPolicy(s, catalog, githubExecutor(githubClient), platformtools.ReadOnlyPolicy()); err != nil {
		panic(fmt.Errorf("publish catalog tools: %w", err))
	}

	return &Runtime{Server: s, manager: connectorManager}
}

func githubToolDefinitions() []platformtools.Definition {
	const commonSchema = `"owner":{"type":"string","minLength":1},"repo":{"type":"string","minLength":1}`
	const paginationSchema = `"page":{"type":"integer","minimum":1,"default":1},"per_page":{"type":"integer","minimum":1,"maximum":100,"default":30}`

	return []platformtools.Definition{
		{
			ID:          "github_repository_get",
			Provider:    "github",
			Name:        "repository_get",
			Description: "Get GitHub repository metadata. Read-only.",
			Risk:        platformtools.RiskRead,
			InputSchema: json.RawMessage(`{"type":"object","properties":{` + commonSchema + `},"required":["owner","repo"],"additionalProperties":false}`),
		},
		{
			ID:          "github_branches_list",
			Provider:    "github",
			Name:        "branches_list",
			Description: "List branches in a GitHub repository. Read-only.",
			Risk:        platformtools.RiskRead,
			InputSchema: json.RawMessage(`{"type":"object","properties":{` + commonSchema + `,` + paginationSchema + `},"required":["owner","repo"],"additionalProperties":false}`),
		},
		{
			ID:          "github_commits_list",
			Provider:    "github",
			Name:        "commits_list",
			Description: "List commits in a GitHub repository. Read-only.",
			Risk:        platformtools.RiskRead,
			InputSchema: json.RawMessage(`{"type":"object","properties":{` + commonSchema + `,` + paginationSchema + `},"required":["owner","repo"],"additionalProperties":false}`),
		},
		{
			ID:          "github_issues_list",
			Provider:    "github",
			Name:        "issues_list",
			Description: "List issues in a GitHub repository, excluding pull requests. Read-only.",
			Risk:        platformtools.RiskRead,
			InputSchema: json.RawMessage(`{"type":"object","properties":{` + commonSchema + `,"state":{"type":"string","enum":["open","closed","all"]},` + paginationSchema + `},"required":["owner","repo"],"additionalProperties":false}`),
		},
		{
			ID:          "github_pull_requests_list",
			Provider:    "github",
			Name:        "pull_requests_list",
			Description: "List pull requests in a GitHub repository. Read-only.",
			Risk:        platformtools.RiskRead,
			InputSchema: json.RawMessage(`{"type":"object","properties":{` + commonSchema + `,"state":{"type":"string","enum":["open","closed","all"]},` + paginationSchema + `},"required":["owner","repo"],"additionalProperties":false}`),
		},
		{
			ID:          "github_file_get",
			Provider:    "github",
			Name:        "file_get",
			Description: "Read a text file from a GitHub repository. Read-only; files are limited to 1 MiB.",
			Risk:        platformtools.RiskRead,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"owner":{"type":"string","minLength":1},"repo":{"type":"string","minLength":1},"path":{"type":"string","minLength":1},"ref":{"type":"string"}},"required":["owner","repo","path"],"additionalProperties":false}`),
		},
		{
			ID:          "github_tree_get",
			Provider:    "github",
			Name:        "tree_get",
			Description: "List a repository Git tree recursively for a branch, tag or commit. Check the truncated field for very large trees.",
			Risk:        platformtools.RiskRead,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"owner":{"type":"string","minLength":1},"repo":{"type":"string","minLength":1},"ref":{"type":"string","minLength":1}},"required":["owner","repo","ref"],"additionalProperties":false}`),
		},
	}
}

func githubExecutor(client *githubprovider.Client) platformtools.Executor {
	return func(ctx context.Context, definition platformtools.Definition, raw json.RawMessage) (any, error) {
		var input struct {
			Owner   string `json:"owner"`
			Repo    string `json:"repo"`
			State   string `json:"state"`
			Page    int    `json:"page"`
			PerPage int    `json:"per_page"`
			Path    string `json:"path"`
			Ref     string `json:"ref"`
		}
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, fmt.Errorf("decode GitHub tool arguments: %w", err)
		}
		input.Owner = strings.TrimSpace(input.Owner)
		input.Repo = strings.TrimSpace(input.Repo)
		if input.Owner == "" || input.Repo == "" {
			return nil, fmt.Errorf("owner and repo are required")
		}

		switch definition.Name {
		case "repository_get":
			return client.Repository(ctx, input.Owner, input.Repo)
		case "branches_list":
			return client.Branches(ctx, input.Owner, input.Repo, input.Page, input.PerPage)
		case "commits_list":
			return client.Commits(ctx, input.Owner, input.Repo, input.Page, input.PerPage)
		case "issues_list":
			return client.Issues(ctx, input.Owner, input.Repo, input.State, input.Page, input.PerPage)
		case "pull_requests_list":
			return client.PullRequests(ctx, input.Owner, input.Repo, input.State, input.Page, input.PerPage)
		case "file_get":
			return client.Contents(ctx, input.Owner, input.Repo, input.Path, input.Ref)
		case "tree_get":
			return client.Tree(ctx, input.Owner, input.Repo, input.Ref)
		default:
			return nil, fmt.Errorf("unsupported GitHub operation %q", definition.Name)
		}
	}
}

// DashboardHandler exposes metadata and bounded health checks for registered connectors.
func DashboardHandler() http.Handler {
	registry := integrations.NewRegistry()
	manager := integrations.NewManager(registry)
	connector := githubprovider.NewConnector()
	if err := manager.Register(context.Background(), connector, integrations.Config{"token": os.Getenv("GITHUB_TOKEN")}); err != nil {
		panic(fmt.Errorf("register dashboard GitHub connector: %w", err))
	}

	connectors := make([]dashboard.ConnectorInfo, 0)
	healthChecks := make(map[string]func(context.Context) error)
	for _, metadata := range registry.List() {
		registered, ok := registry.Get(metadata.ID)
		if !ok {
			continue
		}
		operations := registered.Operations()
		operationNames := make([]string, 0, len(operations))
		readOnly := true
		for _, operation := range operations {
			operationNames = append(operationNames, operation.ID)
			if !operation.ReadOnly {
				readOnly = false
			}
		}
		connectors = append(connectors, dashboard.ConnectorInfo{
			ID: metadata.ID, Name: metadata.Name, Version: metadata.Version,
			Description: metadata.Description, Operations: operationNames, ReadOnly: readOnly,
		})
		healthChecks[metadata.ID] = registered.HealthCheck
	}

	definitions := githubToolDefinitions()
	toolInfos := make([]dashboard.ToolInfo, 0, len(definitions)+1)
	toolInfos = append(toolInfos, dashboard.ToolInfo{
		ID:          "platform_status",
		Provider:    "platform",
		Name:        "status",
		Description: "Return the server version, uptime, Go runtime and supported transports.",
		Risk:        "read",
	})
	for _, definition := range definitions {
		toolInfos = append(toolInfos, dashboard.ToolInfo{
			ID: definition.ID, Provider: definition.Provider, Name: definition.Name,
			Description: definition.Description, Risk: string(definition.Risk),
		})
	}

	return dashboard.HandlerWithConfig(dashboard.Config{
		Version:      Version,
		Transports:   []string{"stdio", "streamable-http"},
		Tools:        toolInfos,
		Connectors:   connectors,
		HealthChecks: healthChecks,
	})
}
