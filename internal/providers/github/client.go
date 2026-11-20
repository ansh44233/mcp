package github

import (
	"context"
	"encoding/base64"
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
	maxFileSize     = 1 << 20
)

// RateLimitError describes a GitHub API rate-limit response.
type RateLimitError struct {
	Message       string
	RetryAfter    time.Duration
	Remaining     string
	ResetAt       time.Time
	SecondaryLimit bool
}

func (e *RateLimitError) Error() string {
	if e.SecondaryLimit {
		return "GitHub secondary rate limit exceeded: " + e.Message
	}
	return "GitHub API rate limit exceeded: " + e.Message
}

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

type FileContent struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA         string `json:"sha"`
	Size        int    `json:"size"`
	HTMLURL     string `json:"html_url"`
	Content     string `json:"content"`
	Encoding    string `json:"encoding"`
	DecodedText string `json:"decoded_text"`
}

type TreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size,omitempty"`
}

type GitTree struct {
	SHA       string      `json:"sha"`
	Truncated bool        `json:"truncated"`
	Tree      []TreeEntry `json:"tree"`
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

// Contents retrieves a single text file from a repository. Binary files and
// files larger than maxFileSize are rejected rather than returned as text.
func (c *Client) Contents(ctx context.Context, owner, repo, path, ref string) (FileContent, error) {
	var result FileContent
	if strings.TrimSpace(path) == "" {
		return result, fmt.Errorf("file path is required")
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	escaped := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return result, fmt.Errorf("invalid file path")
		}
		escaped = append(escaped, url.PathEscape(segment))
	}
	query := url.Values{}
	if ref != "" {
		query.Set("ref", ref)
	}
	endpoint := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/contents/" + strings.Join(escaped, "/")
	if err := c.get(ctx, endpoint, query, &result); err != nil {
		return result, err
	}
	if result.Size > maxFileSize {
		return result, fmt.Errorf("file exceeds %d byte limit", maxFileSize)
	}
	if result.Encoding != "base64" {
		return result, fmt.Errorf("unsupported GitHub file encoding %q", result.Encoding)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(result.Content, "\n", ""))
	if err != nil {
		return result, fmt.Errorf("decode GitHub file content: %w", err)
	}
	if len(decoded) > maxFileSize {
		return result, fmt.Errorf("decoded file exceeds %d byte limit", maxFileSize)
	}
	result.DecodedText = string(decoded)
	result.Content = ""
	return result, nil
}

// Tree lists repository tree entries. GitHub may mark very large recursive
// trees as truncated; callers must inspect the Truncated field.
func (c *Client) Tree(ctx context.Context, owner, repo, ref string) (GitTree, error) {
	var result GitTree
	if strings.TrimSpace(ref) == "" {
		return result, fmt.Errorf("tree ref is required")
	}
	query := url.Values{"recursive": {"1"}}
	err := c.get(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/git/trees/"+url.PathEscape(ref), query, &result)
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
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		if remaining == "0" || resp.Header.Get("Retry-After") != "" || strings.Contains(strings.ToLower(string(body)), "rate limit") {
			retryAfter, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
			resetUnix, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
			return &RateLimitError{
				Message:        strings.TrimSpace(string(body)),
				RetryAfter:     time.Duration(retryAfter) * time.Second,
				Remaining:      remaining,
				ResetAt:        time.Unix(resetUnix, 0),
				SecondaryLimit: remaining != "0",
			}
		}
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
