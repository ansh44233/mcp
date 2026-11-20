package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ansh44233/mcp/internal/security"
	"github.com/ansh44233/mcp/internal/tools"
)

const (
	DefaultCapacity = 1000
	maxAuditLine    = 1 << 20
)

// Event is a data-minimized audit record. It excludes arguments, credentials and raw errors.
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
	PreviousHash string     `json:"previous_hash,omitempty"`
	Hash      string        `json:"hash,omitempty"`
}

type hashPayload struct {
	Sequence uint64        `json:"sequence"`
	Timestamp time.Time    `json:"timestamp"`
	ActorID string         `json:"actor_id,omitempty"`
	TenantID string        `json:"tenant_id,omitempty"`
	ToolID string          `json:"tool_id"`
	Provider string        `json:"provider"`
	Risk tools.Risk        `json:"risk"`
	Outcome string         `json:"outcome"`
	Duration time.Duration `json:"duration_ns"`
	PreviousHash string    `json:"previous_hash,omitempty"`
}

// Store is a bounded in-memory view with optional append-only JSONL persistence.
type Store struct {
	mu sync.RWMutex
	capacity int
	next uint64
	lastHash string
	events []Event
	file *os.File
	lastError error
}

func NewStore(capacity int) *Store {
	if capacity < 1 { capacity = DefaultCapacity }
	return &Store{capacity: capacity, events: make([]Event, 0, capacity)}
}

// NewFileStore opens or creates a private append-only JSONL audit log and verifies its hash chain.
func NewFileStore(path string, capacity int) (*Store, error) {
	if path == "" { return nil, errors.New("audit log path is required") }
	if capacity < 1 { capacity = DefaultCapacity }
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { return nil, fmt.Errorf("create audit directory: %w", err) }
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil { return nil, fmt.Errorf("open audit log: %w", err) }
	store := &Store{capacity: capacity, events: make([]Event, 0, capacity), file: file}
	if err := store.loadAndVerify(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) loadAndVerify() error {
	if _, err := s.file.Seek(0, 0); err != nil { return err }
	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 64*1024), maxAuditLine)
	line := 0
	for scanner.Scan() {
		line++
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil { return fmt.Errorf("audit log line %d is invalid: %w", line, err) }
		if event.Sequence != s.next+1 { return fmt.Errorf("audit log integrity failure at line %d: unexpected sequence", line) }
		if event.PreviousHash != s.lastHash { return fmt.Errorf("audit log integrity failure at line %d: previous hash mismatch", line) }
		expected, err := eventHash(event)
		if err != nil { return fmt.Errorf("hash audit log line %d: %w", line, err) }
		if event.Hash == "" || event.Hash != expected { return fmt.Errorf("audit log integrity failure at line %d: event hash mismatch", line) }
		s.next, s.lastHash = event.Sequence, event.Hash
		s.appendMemory(event)
	}
	if err := scanner.Err(); err != nil { return fmt.Errorf("read audit log: %w", err) }
	_, err := s.file.Seek(0, 2)
	return err
}

func eventHash(event Event) (string, error) {
	payload := hashPayload{
		Sequence:event.Sequence, Timestamp:event.Timestamp, ActorID:event.ActorID,
		TenantID:event.TenantID, ToolID:event.ToolID, Provider:event.Provider,
		Risk:event.Risk, Outcome:event.Outcome, Duration:event.Duration,
		PreviousHash:event.PreviousHash,
	}
	encoded, err := json.Marshal(payload)
	if err != nil { return "", err }
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Store) appendMemory(event Event) {
	if len(s.events) == s.capacity {
		copy(s.events, s.events[1:])
		s.events = s.events[:len(s.events)-1]
	}
	s.events = append(s.events, event)
}

// ObserveToolCall implements tools.ExecutionObserver. Persistence failures are retained for
// operator visibility; this observer contract cannot reject a tool call after execution.
func (s *Store) ObserveToolCall(ctx context.Context, definition tools.Definition, outcome string, duration time.Duration) {
	if s == nil { return }
	event := Event{
		Timestamp:time.Now().UTC(), ToolID:definition.ID, Provider:definition.Provider,
		Risk:definition.Risk, Outcome:outcome, Duration:duration,
	}
	if principal, ok := security.PrincipalFromContext(ctx); ok {
		event.ActorID, event.TenantID = principal.ID, principal.TenantID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event.Sequence = s.next+1
	event.PreviousHash = s.lastHash
	hash, err := eventHash(event)
	if err != nil { s.lastError = err; return }
	event.Hash = hash
	if s.file != nil {
		encoded, err := json.Marshal(event)
		if err == nil { _, err = s.file.Write(append(encoded, '\\n')) }
		if err == nil { err = s.file.Sync() }
		if err != nil { s.lastError = fmt.Errorf("persist audit event: %w", err); return }
	}
	s.next, s.lastHash, s.lastError = event.Sequence, event.Hash, nil
	s.appendMemory(event)
}

type Health struct {
	Persistent bool `json:"persistent"`
	Healthy bool `json:"healthy"`
	EventsRetained int `json:"events_retained"`
	LastSequence uint64 `json:"last_sequence"`
	LastError string `json:"last_error,omitempty"`
}

// Health reports persistence and integrity status without exposing filesystem details.
func (s *Store) Health() Health {
	if s == nil { return Health{} }
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := Health{Persistent:s.file != nil, Healthy:s.lastError == nil, EventsRetained:len(s.events), LastSequence:s.next}
	if s.lastError != nil { result.LastError = "audit persistence error" }
	return result
}

// List returns newest-first copies. Limits are clamped to a safe range.
func (s *Store) List(limit int) []Event {
	if s == nil { return []Event{} }
	if limit < 1 { limit = 100 }
	if limit > 500 { limit = 500 }
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := len(s.events)
	if limit < count { count = limit }
	result := make([]Event, count)
	for i:=0; i<count; i++ { result[i] = s.events[len(s.events)-1-i] }
	return result
}

// Close flushes and closes the persistent log, if configured.
func (s *Store) Close() error {
	if s == nil { return nil }
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil { return nil }
	if err := s.file.Sync(); err != nil { return err }
	err := s.file.Close()
	s.file = nil
	return err
}
