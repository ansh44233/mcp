package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ansh44233/mcp/internal/tools"
)

func TestFileStorePersistsAndVerifiesHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	store, err := NewFileStore(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	store.ObserveToolCall(context.Background(), tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead}, "succeeded", 10)
	store.ObserveToolCall(context.Background(), tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead}, "denied", 5)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	events := reopened.List(10)
	if len(events) != 2 || events[0].Sequence != 2 || events[1].Sequence != 1 {
		t.Fatalf("persisted events mismatch: %+v", events)
	}
	if events[0].PreviousHash != events[1].Hash || events[0].Hash == "" {
		t.Fatalf("hash chain is not linked: %+v", events)
	}
	if health := reopened.Health(); !health.Persistent || !health.Healthy || health.LastSequence != 2 {
		t.Fatalf("unexpected health: %+v", health)
	}
}

func TestFileStoreRejectsTamperedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	store, err := NewFileStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	store.ObserveToolCall(context.Background(), tools.Definition{ID: "repo_read", Provider: "github", Risk: tools.RiskRead}, "succeeded", 1)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "succeeded", "tampered", 1))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path, 10); err == nil || !strings.Contains(err.Error(), "integrity failure") {
		t.Fatalf("expected integrity failure, got %v", err)
	}
}

func TestFileStoreRejectsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte("not-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path, 10); err == nil {
		t.Fatal("expected malformed audit log to be rejected")
	}
}
