package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ansh44233/mcp/internal/security"
	"github.com/ansh44233/mcp/internal/tools"
)

func principal(id, tenant string, authenticated bool) context.Context {
	return security.WithPrincipal(context.Background(), security.Principal{
		ID: id, TenantID: tenant, Authenticated: authenticated, Authentication: "test", MaxRisk: tools.RiskDestructive,
	})
}

func approver(id, tenant string) context.Context {
	return security.WithPrincipal(context.Background(), security.Principal{
		ID: id, TenantID: tenant, Authenticated: true, Authentication: "test",
		CanApprove: true, MaxRisk: tools.RiskDestructive,
	})
}

func writeTool() tools.Definition {
	return tools.Definition{ID: "repo_update", Provider: "github", Risk: tools.RiskWrite}
}

func TestApprovalRequiresIndependentSameTenantApprover(t *testing.T) {
	store := NewStore(10)
	args := json.RawMessage(`{"owner":"acme","repo":"demo"}`)
	request, err := store.Create(principal("alice", "tenant-a", true), writeTool(), args, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(approver("alice", "tenant-a"), request.ID, true, "self"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("self approval should be forbidden: %v", err)
	}
	if _, err := store.Decide(approver("bob", "tenant-b"), request.ID, true, "cross tenant"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant lookup should be hidden: %v", err)
	}
	approved, err := store.Decide(approver("bob", "tenant-a"), request.ID, true, "reviewed")
	if err != nil || approved.Status != Approved {
		t.Fatalf("approval failed: %+v %v", approved, err)
	}
}

func TestConsumeBindsExactArgumentsAndIsSingleUse(t *testing.T) {
	store := NewStore(10)
	args := json.RawMessage(`{"owner":"acme","repo":"demo"}`)
	request, err := store.Create(principal("alice", "tenant-a", true), writeTool(), args, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(approver("bob", "tenant-a"), request.ID, true, "ok"); err != nil {
		t.Fatal(err)
	}
	changed := json.RawMessage(`{"owner":"acme","repo":"other"}`)
	if _, err := store.Consume(principal("alice", "tenant-a", true), request.ID, writeTool(), changed); !errors.Is(err, ErrArgumentChange) {
		t.Fatalf("changed arguments should be rejected: %v", err)
	}
	consumed, err := store.Consume(principal("alice", "tenant-a", true), request.ID, writeTool(), args)
	if err != nil || consumed.Status != Consumed {
		t.Fatalf("consume failed: %+v %v", consumed, err)
	}
	if _, err := store.Consume(principal("alice", "tenant-a", true), request.ID, writeTool(), args); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("second consume should fail: %v", err)
	}
}

func TestApprovalRejectsReadToolsAndUnauthenticatedApprover(t *testing.T) {
	store := NewStore(10)
	if _, err := store.Create(principal("alice", "tenant-a", true), tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead}, json.RawMessage(`{}`), time.Minute); err == nil {
		t.Fatal("read tool should not require approval")
	}
	request, err := store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(principal("bob", "tenant-a", false), request.ID, true, "no auth"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthenticated approver should fail: %v", err)
	}
}

func TestApprovalExpires(t *testing.T) {
	store := NewStore(10)
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	request, err := store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{}`), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := store.Decide(approver("bob", "tenant-a"), request.ID, true, "late"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestConcurrentConsumeOnlySucceedsOnce(t *testing.T) {
	store := NewStore(10)
	args := json.RawMessage(`{"x":1}`)
	request, err := store.Create(principal("alice", "tenant-a", true), writeTool(), args, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(approver("bob", "tenant-a"), request.ID, true, "ok"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Consume(principal("alice", "tenant-a", true), request.ID, writeTool(), args); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("expected exactly one successful consume, got %d", successes)
	}
}

func TestApprovalRequiresExplicitApproverPermission(t *testing.T) {
	store := NewStore(10)
	request, err := store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(principal("bob", "tenant-a", true), request.ID, true, "no approval role"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("authenticated principal without approval permission should be denied: %v", err)
	}
	approved, err := store.Decide(approver("carol", "tenant-a"), request.ID, true, "reviewed")
	if err != nil || approved.Status != Approved {
		t.Fatalf("authorized approver should be able to decide: %+v %v", approved, err)
	}
}
