package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/ansh44233/mcp/internal/security"
	"github.com/ansh44233/mcp/internal/tools"
)

func TestStoreKeepsNewestEventsWithinCapacity(t *testing.T) {
	store := NewStore(2)
	definition := tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead}
	for i := 0; i < 3; i++ {
		store.ObserveToolCall(context.Background(), definition, "succeeded", 10)
	}
	events := store.List(10)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Sequence != 3 || events[1].Sequence != 2 {
		t.Fatalf("events are not newest-first: %+v", events)
	}
}

func TestStoreCapturesPrincipalWithoutRequestPayload(t *testing.T) {
	store := NewStore(10)
	ctx := security.WithPrincipal(context.Background(), security.Principal{
		ID: "user-42", TenantID: "tenant-a", Authenticated: true,
		Authentication: "test", MaxRisk: tools.RiskRead,
	})
	store.ObserveToolCall(ctx, tools.Definition{
		ID: "github_repository_get", Provider: "github", Risk: tools.RiskRead,
	}, "succeeded", 25)
	event := store.List(1)[0]
	if event.ActorID != "user-42" || event.TenantID != "tenant-a" {
		t.Fatalf("principal metadata missing: %+v", event)
	}
	if event.Outcome != "succeeded" || event.Duration != 25 {
		t.Fatalf("execution metadata missing: %+v", event)
	}
}

func TestStoreConcurrentWritesAndReads(t *testing.T) {
	store := NewStore(64)
	definition := tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				store.ObserveToolCall(context.Background(), definition, "succeeded", 1)
				_ = store.List(20)
			}
		}()
	}
	wg.Wait()
	if got := len(store.List(500)); got != 64 {
		t.Fatalf("got %d retained events, want 64", got)
	}
}
