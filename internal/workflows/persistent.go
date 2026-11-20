package workflows

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const maxWorkflowJournalLine = 1 << 20

type journalRecord struct {
	Sequence     uint64   `json:"sequence"`
	PreviousHash string   `json:"previous_hash,omitempty"`
	Workflow     Workflow `json:"workflow"`
	Hash         string   `json:"hash"`
}

type journalPayload struct {
	Sequence     uint64   `json:"sequence"`
	PreviousHash string   `json:"previous_hash,omitempty"`
	Workflow     Workflow `json:"workflow"`
}

// NewFileStore opens a private append-only journal and verifies it before
// exposing recovered workflows. An interrupted running step is marked failed
// with a stable error code: its external side effect may have happened, so it
// is never automatically replayed after a crash.
func NewFileStore(path string, maxItems int) (*Store, error) {
	if path == "" {
		return nil, errors.New("workflow journal path is required")
	}
	if maxItems < 1 {
		maxItems = 1000
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create workflow journal directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open workflow journal: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure workflow journal permissions: %w", err)
	}
	store := NewStore(maxItems)
	store.file = file
	if err := store.loadAndVerify(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if len(store.items) > maxItems {
		_ = file.Close()
		return nil, errors.New("workflow journal exceeds configured capacity")
	}
	// Running steps have an uncertain outcome after process loss. Persist a
	// failed checkpoint so operators must explicitly decide whether to retry.
	for id, item := range store.items {
		if item.Status != Running {
			continue
		}
		for i := range item.Steps {
			if item.Steps[i].Status == Running {
				now := time.Now().UTC()
				item.Steps[i].Status = Failed
				item.Steps[i].CompletedAt = &now
				item.Steps[i].ErrorCode = "interrupted_after_restart"
				break
			}
		}
		item.Status = Failed
		item.UpdatedAt = time.Now().UTC()
		if err := store.persistLocked(item); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("persist interrupted workflow recovery: %w", err)
		}
		store.items[id] = cloneWorkflow(item)
	}
	return store, nil
}

func (s *Store) loadAndVerify() error {
	if _, err := s.file.Seek(0, 0); err != nil {
		return err
	}
	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 64*1024), maxWorkflowJournalLine)
	line := 0
	for scanner.Scan() {
		line++
		var record journalRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("workflow journal line %d is invalid: %w", line, err)
		}
		if record.Sequence != s.next+1 || record.PreviousHash != s.lastHash {
			return fmt.Errorf("workflow journal integrity failure at line %d: sequence or previous hash mismatch", line)
		}
		if err := validateWorkflow(record.Workflow); err != nil {
			return fmt.Errorf("workflow journal line %d has invalid workflow: %w", line, err)
		}
		expected, err := workflowRecordHash(record)
		if err != nil {
			return fmt.Errorf("hash workflow journal line %d: %w", line, err)
		}
		if record.Hash == "" || record.Hash != expected {
			return fmt.Errorf("workflow journal integrity failure at line %d: record hash mismatch", line)
		}
		if prior, exists := s.items[record.Workflow.ID]; exists {
			if !validWorkflowUpdate(prior, record.Workflow) {
				return fmt.Errorf("workflow journal integrity failure at line %d: invalid workflow update", line)
			}
		} else if record.Workflow.Status != Pending {
			return fmt.Errorf("workflow journal integrity failure at line %d: first state is not pending", line)
		}
		s.items[record.Workflow.ID] = cloneWorkflow(record.Workflow)
		s.next, s.lastHash = record.Sequence, record.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read workflow journal: %w", err)
	}
	_, err := s.file.Seek(0, 2)
	return err
}

func validateWorkflow(item Workflow) error {
	if item.ID == "" || item.TenantID == "" || item.OwnerID == "" || item.Name == "" ||
		len(item.Name) > 120 || len(item.Steps) == 0 || len(item.Steps) > 32 ||
		item.CreatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) {
		return errors.New("missing or invalid workflow fields")
	}
	switch item.Status {
	case Pending, Running, Succeeded, Failed, Cancelled:
	default:
		return errors.New("unknown workflow status")
	}
	seen := make(map[string]struct{}, len(item.Steps))
	running := 0
	for i, step := range item.Steps {
		if step.ID != fmt.Sprintf("step-%02d", i+1) || len(step.ToolID) < 2 ||
			len(step.ToolID) > 128 || step.Attempts < 0 {
			return fmt.Errorf("invalid step %d", i)
		}
		if _, ok := seen[step.ToolID]; ok {
			return errors.New("duplicate step tool ID")
		}
		seen[step.ToolID] = struct{}{}
		switch step.Status {
		case Pending, Running, Succeeded, Failed, Cancelled:
		default:
			return fmt.Errorf("invalid step status at %d", i)
		}
		if step.Status == Running {
			running++
			if step.StartedAt == nil || step.CompletedAt != nil {
				return fmt.Errorf("invalid running step timestamps at %d", i)
			}
		}
		if step.Status == Succeeded || step.Status == Failed || step.Status == Cancelled {
			if step.CompletedAt == nil {
				return fmt.Errorf("completed step lacks timestamp at %d", i)
			}
		}
	}
	if running > 1 || (item.Status == Running) != (running == 1) {
		return errors.New("workflow and running-step status disagree")
	}
	if item.Status == Succeeded && item.Steps[len(item.Steps)-1].Status != Succeeded {
		return errors.New("successful workflow has unfinished final step")
	}
	return nil
}

func validWorkflowUpdate(old, next Workflow) bool {
	if old.ID != next.ID || old.TenantID != next.TenantID || old.OwnerID != next.OwnerID ||
		old.Name != next.Name || !old.CreatedAt.Equal(next.CreatedAt) ||
		len(old.Steps) != len(next.Steps) {
		return false
	}
	for i := range old.Steps {
		a, b := old.Steps[i], next.Steps[i]
		if a.ID != b.ID || a.ToolID != b.ToolID || b.Attempts < a.Attempts {
			return false
		}
	}
	return true
}

func workflowRecordHash(record journalRecord) (string, error) {
	payload := journalPayload{Sequence: record.Sequence, PreviousHash: record.PreviousHash, Workflow: record.Workflow}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// persistLocked must be called while Store.mu is held. A failed write poisons
// the store, preventing later in-memory state from diverging from the journal.
func (s *Store) persistLocked(item Workflow) error {
	if s.closed {
		return errors.New("workflow store is closed")
	}
	if s.lastError != nil {
		return fmt.Errorf("workflow persistence unavailable: %w", s.lastError)
	}
	if s.file == nil {
		return nil
	}
	record := journalRecord{Sequence: s.next + 1, PreviousHash: s.lastHash, Workflow: item}
	hash, err := workflowRecordHash(record)
	if err != nil {
		s.lastError = err
		return fmt.Errorf("hash workflow transition: %w", err)
	}
	record.Hash = hash
	encoded, err := json.Marshal(record)
	if err != nil {
		s.lastError = err
		return fmt.Errorf("encode workflow transition: %w", err)
	}
	encoded = append(encoded, '\n')
	written := 0
	for written < len(encoded) {
		n, writeErr := s.file.Write(encoded[written:])
		written += n
		if writeErr != nil {
			s.lastError = writeErr
			return fmt.Errorf("append workflow transition: %w", writeErr)
		}
		if n == 0 {
			s.lastError = errors.New("short write to workflow journal")
			return s.lastError
		}
	}
	if err := s.file.Sync(); err != nil {
		s.lastError = err
		return fmt.Errorf("sync workflow transition: %w", err)
	}
	s.next, s.lastHash = record.Sequence, record.Hash
	return nil
}

// Close syncs and closes the journal. It is safe to call more than once.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.file == nil {
		return nil
	}
	err := s.file.Sync()
	closeErr := s.file.Close()
	s.file = nil
	if err != nil {
		return err
	}
	return closeErr
}

type Health struct {
	Persistent bool   `json:"persistent"`
	Healthy    bool   `json:"healthy"`
	Workflows  int    `json:"workflows"`
	Sequence   uint64 `json:"sequence"`
}

// Health omits local filesystem paths and underlying OS errors.
func (s *Store) Health() Health {
	if s == nil {
		return Health{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return Health{Persistent: s.file != nil, Healthy: !s.closed && s.lastError == nil, Workflows: len(s.items), Sequence: s.next}
}
