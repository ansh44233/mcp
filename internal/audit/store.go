package audit

import (
	"context"
	"sync"
	"time"

	"github.com/ansh44233/mcp/internal/security"
	"github.com/ansh44233/mcp/internal/tools"
)

const DefaultCapacity = 1000

// Event is a deliberately data-minimized record of one MCP tool attempt.
// It never stores tool arguments, credentials, or raw error messages.
type Event struct {
	Sequence  uint64        `json:"sequence"`
	Timestamp time.Time     `json:"timestamp"`
	ActorID   string        `json:"actor_id,omitempty"`
	TenantID  string        `json:"tenant_id,omitempty"`
	ToolID    string        `json:"tool_id"`
	Provider  string        `json:"provider"`
	Risk      tools.Risk    `json:"risk"`
	Outcome   string        `json:"outcome"`
	Duration  time.Duration `json:"duration_ns"`
}

// Store is a bounded, concurrency-safe in-memory audit buffer.
// It is useful for local operations, but is not durable across restarts.
type Store struct {
	mu       sync.RWMutex
	capacity int
	next     uint64
	events   []Event
}

func NewStore(capacity int) *Store {
	if capacity < 1 {
		capacity = DefaultCapacity
	}
	return &Store{capacity: capacity, events: make([]Event, 0, capacity)}
}

// ObserveToolCall implements the tools.ExecutionObserver contract.
func (s *Store) ObserveToolCall(ctx context.Context, definition tools.Definition, outcome string, duration time.Duration) {
	if s == nil {
		return
	}
	event := Event{
		Timestamp: time.Now().UTC(),
		ToolID: definition.ID, Provider: definition.Provider,
		Risk: definition.Risk, Outcome: outcome, Duration: duration,
	}
	if principal, ok := security.PrincipalFromContext(ctx); ok {
		event.ActorID = principal.ID
		event.TenantID = principal.TenantID
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	event.Sequence = s.next
	if len(s.events) == s.capacity {
		copy(s.events, s.events[1:])
		s.events = s.events[:len(s.events)-1]
	}
	s.events = append(s.events, event)
}

// List returns newest-first copies. Limits are clamped to a safe range.
func (s *Store) List(limit int) []Event {
	if s == nil {
		return []Event{}
	}
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := len(s.events)
	if limit < count {
		count = limit
	}
	result := make([]Event, count)
	for i := 0; i < count; i++ {
		result[i] = s.events[len(s.events)-1-i]
	}
	return result
}
