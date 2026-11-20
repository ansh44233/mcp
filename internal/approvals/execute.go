package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ansh44233/mcp/internal/tools"
)

var ErrExecutorRequired = errors.New("approved operation executor is required")

// Executor performs one provider operation after approval has been consumed.
type Executor func(context.Context, tools.Definition, json.RawMessage) (any, error)

// ExecuteApproved consumes a matching, single-use approval before invoking the
// executor. Consumption is intentionally not rolled back if execution fails:
// retrying an uncertain external side effect requires a new approval.
func ExecuteApproved(
	ctx context.Context,
	store *Store,
	requestID string,
	definition tools.Definition,
	arguments json.RawMessage,
	execute Executor,
) (any, error) {
	if store == nil {
		return nil, errors.New("approval store is required")
	}
	if execute == nil {
		return nil, ErrExecutorRequired
	}
	if _, err := store.Consume(ctx, requestID, definition, arguments); err != nil {
		return nil, fmt.Errorf("consume approval: %w", err)
	}
	return execute(ctx, definition, arguments)
}
