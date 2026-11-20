package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/execution"
	platformtools "github.com/ansh44233/mcp/internal/tools"
)

func TestBoundedExecutorPassesOutputAndArguments(t *testing.T) {
	runner := execution.New(execution.Config{MaxConcurrent: 1, Timeout: time.Second})
	definition := platformtools.Definition{ID: "test_read", Provider: "test", Name: "read", Risk: platformtools.RiskRead}
	wantArgs := json.RawMessage(`{"key":"value"}`)
	executor := boundedExecutor(runner, func(ctx context.Context, got platformtools.Definition, args json.RawMessage) (any, error) {
		if got.ID != definition.ID {
			t.Fatalf("definition ID = %q", got.ID)
		}
		if string(args) != string(wantArgs) {
			t.Fatalf("arguments = %s, want %s", args, wantArgs)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("execution context has no deadline")
		}
		return map[string]string{"status": "ok"}, nil
	})
	output, err := executor(context.Background(), definition, wantArgs)
	if err != nil {
		t.Fatalf("executor error = %v", err)
	}
	if output.(map[string]string)["status"] != "ok" {
		t.Fatalf("unexpected output: %#v", output)
	}
}

func TestBoundedExecutorReturnsExecutionError(t *testing.T) {
	runner := execution.New(execution.Config{MaxConcurrent: 1, Timeout: time.Second})
	wantErr := errors.New("provider unavailable")
	executor := boundedExecutor(runner, func(context.Context, platformtools.Definition, json.RawMessage) (any, error) {
		return nil, wantErr
	})
	_, err := executor(context.Background(), platformtools.Definition{ID: "test_read"}, json.RawMessage("{}"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped provider error", err)
	}
}

func TestBoundedExecutorEnforcesDeadline(t *testing.T) {
	runner := execution.New(execution.Config{MaxConcurrent: 1, Timeout: 20 * time.Millisecond})
	executor := boundedExecutor(runner, func(ctx context.Context, _ platformtools.Definition, _ json.RawMessage) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	_, err := executor(context.Background(), platformtools.Definition{ID: "slow_read"}, json.RawMessage("{}"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
}

func TestGitHubToolExecutionTimeoutsAreTrustedAndBounded(t *testing.T) {
	cases := map[string]time.Duration{
		"github_repository_get":      8 * time.Second,
		"github_branches_list":       12 * time.Second,
		"github_commits_list":        12 * time.Second,
		"github_issues_list":         12 * time.Second,
		"github_pull_requests_list":  12 * time.Second,
		"github_file_get":            10 * time.Second,
		"github_tree_get":            20 * time.Second,
		"unknown_tool":               0,
	}
	for id, want := range cases {
		if got := toolExecutionTimeout(id); got != want {
			t.Errorf("toolExecutionTimeout(%q) = %v, want %v", id, got, want)
		}
	}
}
