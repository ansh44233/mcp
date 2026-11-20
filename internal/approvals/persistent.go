package approvals

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

	"github.com/ansh44233/mcp/internal/tools"
)

const maxApprovalLine = 1 << 20

type journalRecord struct {
	Sequence     uint64  `json:"sequence"`
	PreviousHash string  `json:"previous_hash,omitempty"`
	Request      Request `json:"request"`
	Hash         string  `json:"hash"`
}

type journalPayload struct {
	Sequence     uint64  `json:"sequence"`
	PreviousHash string  `json:"previous_hash,omitempty"`
	Request      Request `json:"request"`
}

// NewFileStore opens a private append-only approval journal and verifies every
// record before making recovered requests available.
func NewFileStore(path string, maxItems int) (*Store, error) {
	if path == "" {
		return nil, errors.New("approval journal path is required")
	}
	if maxItems < 1 {
		maxItems = 10000
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create approval journal directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open approval journal: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure approval journal permissions: %w", err)
	}
	store := &Store{
		requests: make(map[string]Request), maxItems: maxItems,
		now: timeNow, newID: randomID, file: file,
	}
	if err := store.loadAndVerify(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if len(store.requests) > maxItems {
		_ = file.Close()
		return nil, errors.New("approval journal exceeds configured capacity")
	}
	return store, nil
}

func timeNow() time.Time { return time.Now() }

func (s *Store) loadAndVerify() error {
	if _, err := s.file.Seek(0, 0); err != nil {
		return err
	}
	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 64*1024), maxApprovalLine)
	line := 0
	for scanner.Scan() {
		line++
		var record journalRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("approval journal line %d is invalid: %w", line, err)
		}
		if record.Sequence != s.next+1 || record.PreviousHash != s.lastHash {
			return fmt.Errorf("approval journal integrity failure at line %d: sequence or previous hash mismatch", line)
		}
		if err := validateRequest(record.Request); err != nil {
			return fmt.Errorf("approval journal line %d has invalid request: %w", line, err)
		}
		expected, err := approvalRecordHash(record)
		if err != nil {
			return fmt.Errorf("hash approval journal line %d: %w", line, err)
		}
		if record.Hash == "" || record.Hash != expected {
			return fmt.Errorf("approval journal integrity failure at line %d: record hash mismatch", line)
		}
		if prior, exists := s.requests[record.Request.ID]; exists {
			if !validTransition(prior.Status, record.Request.Status) {
				return fmt.Errorf("approval journal integrity failure at line %d: invalid state transition", line)
			}
		} else if record.Request.Status != Pending {
			return fmt.Errorf("approval journal integrity failure at line %d: first state is not pending", line)
		}
		s.requests[record.Request.ID] = record.Request
		s.next, s.lastHash = record.Sequence, record.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read approval journal: %w", err)
	}
	_, err := s.file.Seek(0, 2)
	return err
}

func validateRequest(request Request) error {
	if request.ID == "" || request.TenantID == "" || request.RequesterID == "" ||
		request.ToolID == "" || request.Provider == "" || request.ArgumentsHash == "" ||
		request.CreatedAt.IsZero() || !request.ExpiresAt.After(request.CreatedAt) {
		return errors.New("missing required fields")
	}
	if len(request.ArgumentsHash) != sha256.Size*2 {
		return errors.New("invalid arguments digest")
	}
	if request.Risk != tools.RiskWrite && request.Risk != tools.RiskDestructive {
		return errors.New("invalid approval risk")
	}
	switch request.Status {
	case Pending:
		if request.ApproverID != "" || request.DecidedAt != nil || request.ConsumedAt != nil {
			return errors.New("pending request contains decision metadata")
		}
	case Approved, Rejected:
		if request.ApproverID == "" || request.DecidedAt == nil || request.ConsumedAt != nil {
			return errors.New("decided request has invalid metadata")
		}
	case Expired:
		if request.ConsumedAt != nil {
			return errors.New("expired request contains consumption metadata")
		}
	case Consumed:
		if request.ApproverID == "" || request.DecidedAt == nil || request.ConsumedAt == nil {
			return errors.New("consumed request has invalid metadata")
		}
	default:
		return errors.New("unknown request status")
	}
	return nil
}

func validTransition(from, to Status) bool {
	switch from {
	case Pending:
		return to == Approved || to == Rejected || to == Expired
	case Approved:
		return to == Consumed || to == Expired
	default:
		return false
	}
}

func approvalRecordHash(record journalRecord) (string, error) {
	payload := journalPayload{
		Sequence: record.Sequence, PreviousHash: record.PreviousHash,
		Request: record.Request,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// persistLocked must be called while Store.mu is held. A failed append poisons
// the store so no later transition can be committed on an uncertain journal.
func (s *Store) persistLocked(request Request) error {
	if s.closed {
		return errors.New("approval store is closed")
	}
	if s.lastError != nil {
		return fmt.Errorf("approval persistence unavailable: %w", s.lastError)
	}
	if s.file == nil {
		return nil
	}
	record := journalRecord{
		Sequence: s.next + 1, PreviousHash: s.lastHash, Request: request,
	}
	hash, err := approvalRecordHash(record)
	if err != nil {
		s.lastError = err
		return fmt.Errorf("hash approval transition: %w", err)
	}
	record.Hash = hash
	encoded, err := json.Marshal(record)
	if err != nil {
		s.lastError = err
		return fmt.Errorf("encode approval transition: %w", err)
	}
	encoded = append(encoded, '\n')
	written := 0
	for written < len(encoded) {
		n, writeErr := s.file.Write(encoded[written:])
		written += n
		if writeErr != nil {
			s.lastError = writeErr
			return fmt.Errorf("append approval transition: %w", writeErr)
		}
		if n == 0 {
			s.lastError = errors.New("short write to approval journal")
			return s.lastError
		}
	}
	if err := s.file.Sync(); err != nil {
		s.lastError = err
		return fmt.Errorf("sync approval transition: %w", err)
	}
	s.next, s.lastHash = record.Sequence, record.Hash
	return nil
}

// Close syncs and closes the journal. In-memory stores require no cleanup.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		s.closed = true
		return nil
	}
	err := s.file.Sync()
	closeErr := s.file.Close()
	s.file = nil
	s.closed = true
	if err != nil {
		return err
	}
	return closeErr
}

// Health reports whether the store is backed by a journal and whether writes
// have remained healthy. It intentionally omits filesystem paths and errors.
type Health struct {
	Persistent bool   `json:"persistent"`
	Healthy    bool   `json:"healthy"`
	Requests   int    `json:"requests"`
	Sequence   uint64 `json:"sequence"`
}

func (s *Store) Health() Health {
	if s == nil {
		return Health{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return Health{Persistent: s.file != nil, Healthy: s.lastError == nil, Requests: len(s.requests), Sequence: s.next}
}
