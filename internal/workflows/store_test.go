package workflows

import (
	"context"
	"errors"
	"testing"

	"github.com/ansh44233/mcp/internal/security"
	"github.com/ansh44233/mcp/internal/tools"
)

func workflowContext(id, tenant string, authenticated bool) context.Context {
	return security.WithPrincipal(context.Background(), security.Principal{
		ID: id, TenantID: tenant, Authenticated: authenticated,
		Authentication: "test", MaxRisk: tools.RiskRead,
	})
}

func TestWorkflowSequentialCheckpointsAndRetry(t *testing.T) {
	store := NewStore(10)
	ctx := workflowContext("alice", "tenant-a", true)
	item, err := store.Create(ctx, "release review", []string{"github_repository_get", "github_pull_requests_list"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartStep(ctx, item.ID, "step-02"); !errors.Is(err, ErrStepOrder) {
		t.Fatalf("out-of-order step should fail: %v", err)
	}
	if _, err := store.StartStep(ctx, item.ID, "step-01"); err != nil {
		t.Fatal(err)
	}
	failed, err := store.FailStep(ctx, item.ID, "step-01", "provider_timeout")
	if err != nil || failed.Status != Failed || failed.Steps[0].ErrorCode != "provider_timeout" {
		t.Fatalf("expected failed checkpoint: %+v %v", failed, err)
	}
	retried, err := store.RetryStep(ctx, item.ID, "step-01")
	if err != nil || retried.Status != Pending || retried.Steps[0].Attempts != 1 {
		t.Fatalf("retry should requeue without erasing attempts: %+v %v", retried, err)
	}
	if _, err := store.StartStep(ctx, item.ID, "step-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteStep(ctx, item.ID, "step-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartStep(ctx, item.ID, "step-02"); err != nil {
		t.Fatal(err)
	}
	done, err := store.CompleteStep(ctx, item.ID, "step-02")
	if err != nil || done.Status != Succeeded {
		t.Fatalf("workflow should complete: %+v %v", done, err)
	}
}

func TestWorkflowTenantAndOwnerIsolation(t *testing.T) {
	store := NewStore(10)
	owner := workflowContext("alice", "tenant-a", true)
	item, err := store.Create(owner, "private workflow", []string{"tool_read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(workflowContext("bob", "tenant-b", true), item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant workflow should be hidden: %v", err)
	}
	if _, err := store.StartStep(workflowContext("bob", "tenant-a", true), item.ID, "step-01"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-owner should not mutate workflow: %v", err)
	}
	if _, err := store.List(context.Background(), 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthenticated listing should fail: %v", err)
	}
}

func TestWorkflowCopiesAndCancellation(t *testing.T) {
	store := NewStore(10)
	ctx := workflowContext("alice", "tenant-a", true)
	item, err := store.Create(ctx, "cancel me", []string{"tool_read"})
	if err != nil {
		t.Fatal(err)
	}
	item.Steps[0].ToolID = "tampered"
	got, err := store.Get(ctx, item.ID)
	if err != nil || got.Steps[0].ToolID != "tool_read" {
		t.Fatalf("caller mutation leaked into store: %+v %v", got, err)
	}
	cancelled, err := store.Cancel(ctx, item.ID)
	if err != nil || cancelled.Status != Cancelled {
		t.Fatalf("cancel failed: %+v %v", cancelled, err)
	}
	if _, err := store.StartStep(ctx, item.ID, "step-01"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("cancelled workflow must be terminal: %v", err)
	}
}
