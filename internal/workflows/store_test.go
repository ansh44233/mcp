package workflows

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestFileStoreRecoversWorkflowAndInterruptedStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workflows.jsonl")
	ctx := workflowContext("alice", "tenant-a", true)
	store, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.Create(ctx, "durable run", []string{"tool_read", "tool_list"})
	if err != nil {
		t.Fatal(err)
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
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	got, err := recovered.Get(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != Failed || got.Steps[1].Status != Failed ||
		got.Steps[1].ErrorCode != "interrupted_after_restart" {
		t.Fatalf("running step must recover as explicit failure, not auto-replay: %+v", got)
	}
	if got.Steps[0].Status != Succeeded || got.Steps[0].Attempts != 1 {
		t.Fatalf("completed checkpoint was not recovered: %+v", got.Steps[0])
	}
	if health := recovered.Health(); !health.Persistent || !health.Healthy || health.Sequence != 5 {
		t.Fatalf("unexpected recovered journal health: %+v", health)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-argument") {
		t.Fatal("workflow journal must not contain tool arguments")
	}
}

func TestFileStoreRejectsTamperedJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workflows.jsonl")
	store, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(workflowContext("alice", "tenant-a", true), "audit", []string{"tool_read"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), "alice", "mallory", 1)
	if tampered == string(data) {
		t.Fatal("expected journal content to contain owner")
	}
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path, 10); err == nil {
		t.Fatal("tampered journal must fail closed")
	}
}

func TestFileStoreDoesNotPublishAfterAppendFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workflows.jsonl")
	store, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(workflowContext("alice", "tenant-a", true), "closed", []string{"tool_read"}); err == nil {
		t.Fatal("write to closed workflow store should fail")
	}
	if health := store.Health(); health.Healthy {
		t.Fatalf("closed store should be unhealthy: %+v", health)
	}
	if _, err := store.List(workflowContext("alice", "tenant-a", true), 10); err != nil {
		t.Fatalf("read from closed store should remain available: %v", err)
	}
}

func TestValidWorkflowUpdateRejectsIncoherentTransitions(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	started := now.Add(time.Minute)
	completed := now.Add(2 * time.Minute)
	old := Workflow{
		ID: "workflow-1", TenantID: "tenant-a", OwnerID: "alice", Name: "test",
		Status: Pending, CreatedAt: now, UpdatedAt: now,
		Steps: []Step{{ID: "step-01", ToolID: "tool_read", Status: Pending}},
	}
	next := cloneWorkflow(old)
	next.Status = Running
	next.UpdatedAt = started
	if validWorkflowUpdate(old, next) {
		t.Fatal("workflow must not become running without starting a step")
	}

	running := cloneWorkflow(old)
	running.Status = Running
	running.UpdatedAt = started
	running.Steps[0].Status = Running
	running.Steps[0].Attempts = 1
	running.Steps[0].StartedAt = &started
	next = cloneWorkflow(running)
	next.Status = Succeeded
	next.UpdatedAt = completed
	if validWorkflowUpdate(running, next) {
		t.Fatal("workflow must not succeed while its step remains running")
	}

	next = cloneWorkflow(running)
	next.Steps[0].StartedAt = nil
	next.UpdatedAt = completed
	if validWorkflowUpdate(running, next) {
		t.Fatal("journal must not rewrite timestamps on an unchanged step state")
	}

	next = cloneWorkflow(running)
	next.Status = Succeeded
	next.Steps[0].Status = Succeeded
	next.Steps[0].CompletedAt = &completed
	next.UpdatedAt = completed
	if !validWorkflowUpdate(running, next) {
		t.Fatal("valid final-step completion should be accepted")
	}
}

func TestWorkflowCancellationClosesRunningCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cancel.jsonl")
	ctx := workflowContext("alice", "tenant-a", true)
	store, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.Create(ctx, "cancel active", []string{"tool_read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartStep(ctx, item.ID, "step-01"); err != nil {
		t.Fatal(err)
	}
	cancelled, err := store.Cancel(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != Cancelled || cancelled.Steps[0].Status != Cancelled ||
		cancelled.Steps[0].CompletedAt == nil || cancelled.Steps[0].ErrorCode != "cancelled_by_owner" {
		t.Fatalf("cancellation must close active checkpoint: %+v", cancelled)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	got, err := recovered.Get(ctx, item.ID)
	if err != nil || got.Status != Cancelled || got.Steps[0].Status != Cancelled {
		t.Fatalf("cancelled workflow did not recover: %+v %v", got, err)
	}
}
