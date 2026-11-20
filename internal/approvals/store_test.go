package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestListIsTenantScopedNewestFirstAndExpiresPending(t *testing.T) {
	store := NewStore(10)
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	first, err := store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{}`), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Millisecond)
	second, err := store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{"x":1}`), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(principal("bob", "tenant-b", true), writeTool(), json.RawMessage(`{}`), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	listed, err := store.List(principal("alice", "tenant-a", true), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].ID != second.ID || listed[1].ID != first.ID {
		t.Fatalf("unexpected tenant list ordering/content: %+v", listed)
	}
	if listed[1].Status != Expired {
		t.Fatalf("pending request should become expired when listed, got %s", listed[1].Status)
	}
	limited, err := store.List(principal("alice", "tenant-a", true), 1)
	if err != nil || len(limited) != 1 || limited[0].ID != second.ID {
		t.Fatalf("limit not applied: %+v %v", limited, err)
	}
	if _, err := store.List(context.Background(), 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing principal should be rejected: %v", err)
	}
}

func TestApprovalInspectionRequiresAuthenticatedPrincipal(t *testing.T) {
	store := NewStore(10)
	request, err := store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{"x":1}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	local := security.WithPrincipal(context.Background(), security.LocalPrincipal())
	if _, err := store.List(local, 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("local unauthenticated principal must not list approvals: %v", err)
	}
	if _, err := store.Get(local, request.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("local unauthenticated principal must not inspect approval: %v", err)
	}
	if _, err := store.List(principal("mallory", "tenant-b", true), 10); err != nil {
		t.Fatalf("authenticated other tenant should receive an empty list: %v", err)
	}
	if _, err := store.Get(principal("mallory", "tenant-b", true), request.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant request should remain hidden: %v", err)
	}
	if got, err := store.Get(principal("alice", "tenant-a", true), request.ID); err != nil || got.ID != request.ID {
		t.Fatalf("authenticated owner should inspect request: %+v %v", got, err)
	}
}

func TestApprovalInspectionIsOwnerOrReviewerScoped(t *testing.T) {
	store := NewStore(10)
	first, err := store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{"x":1}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(principal("carol", "tenant-a", true), writeTool(), json.RawMessage(`{"x":2}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	ownerList, err := store.List(principal("alice", "tenant-a", true), 10)
	if err != nil || len(ownerList) != 1 || ownerList[0].ID != first.ID {
		t.Fatalf("requester should only list own requests: %+v %v", ownerList, err)
	}
	if _, err := store.Get(principal("alice", "tenant-a", true), second.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("requester must not inspect another requester's request: %v", err)
	}

	reviewerList, err := store.List(approver("reviewer", "tenant-a"), 10)
	if err != nil || len(reviewerList) != 2 {
		t.Fatalf("authorized reviewer should list tenant requests: %+v %v", reviewerList, err)
	}
	if got, err := store.Get(approver("reviewer", "tenant-a"), second.ID); err != nil || got.ID != second.ID {
		t.Fatalf("authorized reviewer should inspect tenant request: %+v %v", got, err)
	}
	if _, err := store.Get(approver("reviewer", "tenant-b"), second.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reviewer must not cross tenant boundary: %v", err)
	}
}

func TestReviewerInspectionHonorsRiskAndCapabilityScopes(t *testing.T) {
	store := NewStore(10)
	definition := writeTool()
	request, err := store.Create(principal("requester", "tenant-a", true), definition, json.RawMessage(`{"x":1}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	restricted := security.WithPrincipal(context.Background(), security.Principal{
		ID: "reviewer", TenantID: "tenant-a", Authenticated: true, Authentication: "test",
		CanApprove: true, MaxRisk: tools.RiskRead,
	})
	if _, err := store.Get(restricted, request.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reviewer below request risk must not inspect: %v", err)
	}
	if requests, err := store.List(restricted, 10); err != nil || len(requests) != 0 {
		t.Fatalf("reviewer below request risk must not list request: %+v %v", requests, err)
	}
	restricted = security.WithPrincipal(context.Background(), security.Principal{
		ID: "reviewer", TenantID: "tenant-a", Authenticated: true, Authentication: "test",
		CanApprove: true, MaxRisk: tools.RiskDestructive,
		AllowedTools: map[string]struct{}{"different_tool": {}},
		AllowedProviders: map[string]struct{}{"github": {}},
	})
	if _, err := store.Get(restricted, request.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reviewer outside tool scope must not inspect: %v", err)
	}
}

func TestFileStoreRecoversApprovalTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.jsonl")
	store, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	args := json.RawMessage(`{"owner":"acme","repo":"demo"}`)
	request, err := store.Create(principal("alice", "tenant-a", true), writeTool(), args, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Decide(approver("bob", "tenant-a"), request.ID, true, "reviewed"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(principal("alice", "tenant-a", true), request.ID, writeTool(), args); err != nil {
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
	got, err := recovered.Get(principal("alice", "tenant-a", true), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != Consumed || got.ApproverID != "bob" || got.Reason != "reviewed" {
		t.Fatalf("unexpected recovered request: %+v", got)
	}
	health := recovered.Health()
	if !health.Persistent || !health.Healthy || health.Sequence != 3 {
		t.Fatalf("unexpected journal health: %+v", health)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "acme") || strings.Contains(string(data), "demo") {
		t.Fatal("journal must not contain raw tool arguments")
	}
}

func TestFileStoreRejectsTamperedJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.jsonl")
	store, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{"x":1}`), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "alice", "mallory", 1))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path, 10); err == nil {
		t.Fatal("tampered journal should fail verification")
	}
}

func TestFileStoreDoesNotPublishTransitionAfterAppendFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.jsonl")
	store, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(principal("alice", "tenant-a", true), writeTool(), json.RawMessage(`{}`), time.Hour)
	if err == nil {
		t.Fatal("write to closed journal should fail")
	}
	if got := store.Health(); got.Healthy {
		t.Fatal("journal should report unhealthy after append failure")
	}
	if len(store.requests) != 0 {
		t.Fatal("failed transition must not be published in memory")
	}
}
