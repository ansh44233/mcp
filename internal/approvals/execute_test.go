package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/tools"
)

func TestExecuteApprovedConsumesBeforeCallingExecutor(t *testing.T) {
	store := NewStore(10)
	ctx := principal("alice", "tenant-a", true)
	args := json.RawMessage(`{"owner":"acme","repo":"demo"}`)
	request, err := store.Create(ctx, writeTool(), args, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(approver("bob", "tenant-a"), request.ID, true, "reviewed"); err != nil {
		t.Fatal(err)
	}

	calls := 0
	result, err := ExecuteApproved(ctx, store, request.ID, writeTool(), args,
		func(_ context.Context, definition tools.Definition, got json.RawMessage) (any, error) {
			calls++
			if definition.ID != "repo_update" || string(got) != string(args) {
				t.Fatalf("executor received unexpected operation: %+v %s", definition, got)
			}
			return map[string]string{"status": "updated"}, nil
		})
	if err != nil || calls != 1 || result == nil {
		t.Fatalf("approved execution failed: result=%v calls=%d err=%v", result, calls, err)
	}

	_, err = ExecuteApproved(ctx, store, request.ID, writeTool(), args,
		func(context.Context, tools.Definition, json.RawMessage) (any, error) {
			calls++
			return nil, nil
		})
	if !errors.Is(err, ErrInvalidState) || calls != 1 {
		t.Fatalf("replay must be blocked before executor: calls=%d err=%v", calls, err)
	}
}

func TestExecuteApprovedConsumesEvenWhenExecutorFails(t *testing.T) {
	store := NewStore(10)
	ctx := principal("alice", "tenant-a", true)
	args := json.RawMessage(`{"x":1}`)
	request, err := store.Create(ctx, writeTool(), args, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(approver("bob", "tenant-a"), request.ID, true, "reviewed"); err != nil {
		t.Fatal(err)
	}
	executionErr := errors.New("provider outcome uncertain")
	_, err = ExecuteApproved(ctx, store, request.ID, writeTool(), args,
		func(context.Context, tools.Definition, json.RawMessage) (any, error) {
			return nil, executionErr
		})
	if !errors.Is(err, executionErr) {
		t.Fatalf("expected executor error, got %v", err)
	}
	if _, err := store.Consume(ctx, request.ID, writeTool(), args); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("failed external execution must not make approval reusable: %v", err)
	}
}

func TestExecuteApprovedRejectsMismatchedArgumentsWithoutExecution(t *testing.T) {
	store := NewStore(10)
	ctx := principal("alice", "tenant-a", true)
	args := json.RawMessage(`{"x":1}`)
	request, err := store.Create(ctx, writeTool(), args, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(approver("bob", "tenant-a"), request.ID, true, "reviewed"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = ExecuteApproved(ctx, store, request.ID, writeTool(), json.RawMessage(`{"x":2}`),
		func(context.Context, tools.Definition, json.RawMessage) (any, error) {
			calls++
			return nil, nil
		})
	if !errors.Is(err, ErrArgumentChange) || calls != 0 {
		t.Fatalf("changed arguments must not execute: calls=%d err=%v", calls, err)
	}
}

func TestExecuteApprovedRequiresStoreAndExecutor(t *testing.T) {
	if _, err := ExecuteApproved(context.Background(), nil, "id", writeTool(), json.RawMessage(`{}`), func(context.Context, tools.Definition, json.RawMessage) (any, error) { return nil, nil }); err == nil {
		t.Fatal("nil store should be rejected")
	}
	if _, err := ExecuteApproved(context.Background(), NewStore(1), "id", writeTool(), json.RawMessage(`{}`), nil); !errors.Is(err, ErrExecutorRequired) {
		t.Fatalf("nil executor should be rejected: %v", err)
	}
}
