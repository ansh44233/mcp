package server

import (
	"context"
	"encoding/json"

	"github.com/ansh44233/mcp/internal/execution"
	platformtools "github.com/ansh44233/mcp/internal/tools"
)

// boundedExecutor places a trusted execution boundary around provider calls.
// Retry policy is intentionally absent until each provider operation has an
// explicit, tested transient-error classification.
func boundedExecutor(runner *execution.Runner, next platformtools.Executor) platformtools.Executor {
	return func(ctx context.Context, definition platformtools.Definition, arguments json.RawMessage) (any, error) {
		var output any
		_, err := runner.Execute(ctx, execution.Operation{ID: definition.ID}, func(execCtx context.Context) error {
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
