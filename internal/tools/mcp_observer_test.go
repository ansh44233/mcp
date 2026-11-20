package tools

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type observedCall struct { outcome string }

type testObserver struct {
	mu sync.Mutex
	calls []observedCall
}

func (o *testObserver) ObserveToolCall(_ context.Context, _ Definition, outcome string, _ time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, observedCall{outcome: outcome})
}

func (o *testObserver) outcomes() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make([]string, len(o.calls))
	for i, call := range o.calls { result[i] = call.outcome }
	return result
}

func TestRegisterMCPWithObserverRecordsDeniedFailedAndSuccessfulCalls(t *testing.T) {
	registry := NewRegistry()
	for _, id := range []string{"denied_tool", "failed_tool", "successful_tool"} {
		if err := registry.Register(Definition{
			ID: id, Provider: "test", Name: id, Description: "Observer test tool.",
			Risk: RiskRead, InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		}); err != nil { t.Fatal(err) }
	}
	observer := &testObserver{}
	server := mcp.NewServer(&mcp.Implementation{Name: "observer-test", Version: "0.0.1"}, nil)
	executor := func(_ context.Context, definition Definition, _ json.RawMessage) (any, error) {
		if definition.ID == "failed_tool" { return nil, context.DeadlineExceeded }
		return map[string]any{"ok": true}, nil
	}
	authorize := func(_ context.Context, definition Definition, _ json.RawMessage) error {
		if definition.ID == "denied_tool" { return context.Canceled }
		return nil
	}
	if err := RegisterMCPWithObserver(server, registry, executor, ReadOnlyPolicy(), authorize, observer); err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil { t.Fatal(err) }
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "observer-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil { t.Fatal(err) }
	defer clientSession.Close()
	for _, name := range []string{"denied_tool", "failed_tool", "successful_tool"} {
		if _, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{}}); err != nil {
			t.Fatalf("call %s: %v", name, err)
		}
	}
	got := observer.outcomes()
	want := []string{"denied", "failed", "succeeded"}
	if len(got) != len(want) { t.Fatalf("outcomes = %v", got) }
	for i := range want { if got[i] != want[i] { t.Fatalf("outcomes = %v, want %v", got, want) } }
}
