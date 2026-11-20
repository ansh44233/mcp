package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAPIBase  = "https://api.github.com"
	maxResponseSize = 2 << 20
)

// Client performs bounded, read-only requests to the GitHub REST API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func NewClient(token string) *Client {
	return NewClientWithHTTPClient(defaultAPIBase, token, &http.Client{Timeout: 15 * time.Second})
}

// NewClientWithHTTPClient allows deterministic tests against an httptest server.
func NewClientWithHTTPClient(baseURL, token string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		httpClient: httpClient,
	}
}

type Repository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	Description   string `json:"description"`
	HTMLURL       string `json:"html_url"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
}

type Branch struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
}

type Commit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
		Author  struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

type Issue struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
}

type PullRequest struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
}

func (c *Client) Repository(ctx context.Context, owner, repo string) (Repository, error) {
	var result Repository
	err := c.get(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo), nil, &result)
	return result, err
}

func (c *Client) Branches(ctx context.Context, owner, repo string, page, perPage int) ([]Branch, error) {
	var result []Branch
	err := c.get(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/branches", pagination(page, perPage), &result)
	return result, err
}

func (c *Client) Commits(ctx context.Context, owner, repo string, page, perPage int) ([]Commit, error) {
	var result []Commit
	err := c.get(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/commits", pagination(page, perPage), &result)
	return result, err
}

func (c *Client) Issues(ctx context.Context, owner, repo, state string, page, perPage int) ([]Issue, error) {
	if state == "" {
		state = "open"
	}
	if state != "open" && state != "closed" && state != "all" {
		return nil, fmt.Errorf("invalid issue state %q", state)
	}

	query := pagination(page, perPage)
	query.Set("state", state)
	query.Set("filter", "all")
	var raw []struct {
		Issue
		PullRequest json.RawMessage `json:"pull_request"`
	}
	err := c.get(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/issues", query, &raw)
	if err != nil {
		return nil, err
	}
	result := make([]Issue, 0, len(raw))
	for _, item := range raw {
		if len(item.PullRequest) == 0 || string(item.PullRequest) == "null" {
			result = append(result, item.Issue)
		}
	}
	return result, nil
}

func (c *Client) PullRequests(ctx context.Context, owner, repo, state string, page, perPage int) ([]PullRequest, error) {
	if state == "" {
		state = "open"
	}
	if state != "open" && state != "closed" && state != "all" {
		return nil, fmt.Errorf("invalid pull request state %q", state)
	}

	query := pagination(page, perPage)
	query.Set("state", state)
	var result []PullRequest
	err := c.get(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/pulls", query, &result)
	return result, err
}

func pagination(page, perPage int) url.Values {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 30
	}
	if perPage > 100 {
		perPage = 100
	}
	return url.Values{
		"page":     {strconv.Itoa(page)},
		"per_page": {strconv.Itoa(perPage)},
	}
}

func (c *Client) get(ctx context.Context, path string, query url.Values, output any) error {
	if c.baseURL == "" {
		return fmt.Errorf("GitHub API base URL is empty")
	}
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create GitHub request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "universal-mcp")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("read GitHub response: %w", err)
	}
	if len(body) > maxResponseSize {
		return fmt.Errorf("GitHub response exceeds %d bytes", maxResponseSize)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		if len(message) > 512 {
			message = message[:512]
		}
		return fmt.Errorf("GitHub API returned %s: %s", resp.Status, message)
	}
	if err := json.Unmarshal(body, output); err != nil {
		return fmt.Errorf("decode GitHub response: %w", err)
	}
	return nil
}
