package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ansh44233/mcp/internal/execution"
	platformtools "github.com/ansh44233/mcp/internal/tools"
)

// toolExecutionTimeout is trusted server-side policy, never caller input.
func toolExecutionTimeout(toolID string) time.Duration {
	switch toolID {
	case "github_repository_get":
		return 8 * time.Second
	case "github_branches_list", "github_commits_list", "github_issues_list", "github_pull_requests_list":
		return 12 * time.Second
	case "github_file_get":
		return 10 * time.Second
	case "github_tree_get":
		return 20 * time.Second
	default:
		return 0
	}
}

// boundedExecutor places a trusted execution boundary around provider calls.
// Retry policy is intentionally absent until each provider operation has an
// explicit, tested transient-error classification.
func boundedExecutor(runner *execution.Runner, next platformtools.Executor) platformtools.Executor {
	return func(ctx context.Context, definition platformtools.Definition, arguments json.RawMessage) (any, error) {
		var output any
		_, err := runner.Execute(ctx, execution.Operation{
			ID:      definition.ID,
			Timeout: toolExecutionTimeout(definition.ID),
		}, func(execCtx context.Context) error {
			var executeErr error
			output, executeErr = next(execCtx, definition, arguments)
			return executeErr
		})
		if err != nil {
			return nil, err
		}
		return output, nil
	}
}
