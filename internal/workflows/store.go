// Package workflows provides a tenant-scoped workflow state machine.
// It coordinates metadata and checkpoints; it deliberately does not execute tools.
package workflows

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ansh44233/mcp/internal/security"
)

type Status string

const (
	Pending   Status = "pending"
	Running   Status = "running"
	Succeeded Status = "succeeded"
	Failed    Status = "failed"
	Cancelled Status = "cancelled"
)

var (
	ErrNotFound     = errors.New("workflow not found")
	ErrForbidden    = errors.New("workflow action is not permitted")
	ErrInvalidState = errors.New("invalid workflow state transition")
	ErrStepOrder    = errors.New("workflow steps must complete in order")
)

type Step struct {
	ID          string     `json:"id"`
	ToolID      string     `json:"tool_id"`
	Status      Status     `json:"status"`
	Attempts    int        `json:"attempts"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ErrorCode   string     `json:"error_code,omitempty"`
}

type Workflow struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	OwnerID   string    `json:"owner_id"`
	Name      string    `json:"name"`
	Status    Status    `json:"status"`
	Steps     []Step    `json:"steps"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	mu       sync.Mutex
	items    map[string]Workflow
	maxItems int
	now      func() time.Time
	newID    func() (string, error)
}

func NewStore(maxItems int) *Store {
	if maxItems < 1 {
		maxItems = 1000
	}
	return &Store{items: make(map[string]Workflow), maxItems: maxItems, now: time.Now, newID: randomID}
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func actor(ctx context.Context) (security.Principal, error) {
	p, ok := security.PrincipalFromContext(ctx)
	if !ok || p.Validate() != nil || !p.Authenticated {
		return security.Principal{}, ErrForbidden
	}
	return p, nil
}

func (s *Store) Create(ctx context.Context, name string, toolIDs []string) (Workflow, error) {
	p, err := actor(ctx)
	if err != nil {
		return Workflow{}, err
	}
	if name == "" || len(name) > 120 || len(toolIDs) == 0 || len(toolIDs) > 32 {
		return Workflow{}, errors.New("workflow name and 1-32 steps are required")
	}
	steps := make([]Step, len(toolIDs))
	seen := make(map[string]struct{}, len(toolIDs))
	for i, toolID := range toolIDs {
		if len(toolID) < 2 || len(toolID) > 128 {
			return Workflow{}, fmt.Errorf("invalid tool ID at step %d", i)
		}
		if _, exists := seen[toolID]; exists {
			return Workflow{}, fmt.Errorf("duplicate tool ID %q", toolID)
		}
		seen[toolID] = struct{}{}
		steps[i] = Step{ID: fmt.Sprintf("step-%02d", i+1), ToolID: toolID, Status: Pending}
	}
	id, err := s.newID()
	if err != nil {
		return Workflow{}, fmt.Errorf("generate workflow ID: %w", err)
	}
	now := s.now().UTC()
	item := Workflow{ID: id, TenantID: p.TenantID, OwnerID: p.ID, Name: name, Status: Pending, Steps: steps, CreatedAt: now, UpdatedAt: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) >= s.maxItems {
		return Workflow{}, errors.New("workflow store capacity reached")
	}
	if _, exists := s.items[id]; exists {
		return Workflow{}, errors.New("workflow ID collision")
	}
	s.items[id] = cloneWorkflow(item)
	return cloneWorkflow(item), nil
}

func (s *Store) Get(ctx context.Context, id string) (Workflow, error) {
	p, err := actor(ctx)
	if err != nil {
		return Workflow{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok || item.TenantID != p.TenantID {
		return Workflow{}, ErrNotFound
	}
	return cloneWorkflow(item), nil
}

func (s *Store) List(ctx context.Context, limit int) ([]Workflow, error) {
	p, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Workflow, 0)
	for _, item := range s.items {
		if item.TenantID == p.TenantID {
			out = append(out, cloneWorkflow(item))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// StartStep starts only the first pending step after all earlier steps succeeded.
func (s *Store) StartStep(ctx context.Context, id, stepID string) (Workflow, error) {
	p, err := actor(ctx)
	if err != nil {
		return Workflow{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok || item.TenantID != p.TenantID || item.OwnerID != p.ID {
		return Workflow{}, ErrNotFound
	}
	index := stepIndex(item.Steps, stepID)
	if index < 0 || item.Status == Cancelled || item.Status == Succeeded || item.Status == Failed {
		return Workflow{}, ErrInvalidState
	}
	for i := 0; i < index; i++ {
		if item.Steps[i].Status != Succeeded {
			return Workflow{}, ErrStepOrder
		}
	}
	if item.Steps[index].Status != Pending {
		return Workflow{}, ErrInvalidState
	}
	now := s.now().UTC()
	item.Steps[index].Status = Running
	item.Steps[index].Attempts++
	item.Steps[index].StartedAt = &now
	item.Steps[index].CompletedAt = nil
	item.Steps[index].ErrorCode = ""
	item.Status = Running
	item.UpdatedAt = now
	s.items[id] = cloneWorkflow(item)
	return cloneWorkflow(item), nil
}

// CompleteStep records a successful checkpoint. The next step remains pending.
func (s *Store) CompleteStep(ctx context.Context, id, stepID string) (Workflow, error) {
	return s.finishStep(ctx, id, stepID, true, "")
}

// FailStep records a bounded machine-readable error code, never raw error text.
func (s *Store) FailStep(ctx context.Context, id, stepID, errorCode string) (Workflow, error) {
	if len(errorCode) > 64 {
		return Workflow{}, errors.New("error code exceeds 64 characters")
	}
	return s.finishStep(ctx, id, stepID, false, errorCode)
}

func (s *Store) finishStep(ctx context.Context, id, stepID string, success bool, errorCode string) (Workflow, error) {
	p, err := actor(ctx)
	if err != nil {
		return Workflow{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok || item.TenantID != p.TenantID || item.OwnerID != p.ID {
		return Workflow{}, ErrNotFound
	}
	index := stepIndex(item.Steps, stepID)
	if index < 0 || item.Status != Running || item.Steps[index].Status != Running {
		return Workflow{}, ErrInvalidState
	}
	now := s.now().UTC()
	item.Steps[index].CompletedAt = &now
	if success {
		item.Steps[index].Status = Succeeded
		if index == len(item.Steps)-1 {
			item.Status = Succeeded
		}
	} else {
		item.Steps[index].Status = Failed
		item.Steps[index].ErrorCode = errorCode
		item.Status = Failed
	}
	item.UpdatedAt = now
	s.items[id] = cloneWorkflow(item)
	return cloneWorkflow(item), nil
}

// RetryStep explicitly requeues a failed step; callers decide when it is safe to retry.
func (s *Store) RetryStep(ctx context.Context, id, stepID string) (Workflow, error) {
	p, err := actor(ctx)
	if err != nil {
		return Workflow{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok || item.TenantID != p.TenantID || item.OwnerID != p.ID {
		return Workflow{}, ErrNotFound
	}
	index := stepIndex(item.Steps, stepID)
	if index < 0 || item.Status != Failed || item.Steps[index].Status != Failed {
		return Workflow{}, ErrInvalidState
	}
	item.Steps[index].Status = Pending
	item.Steps[index].StartedAt = nil
	item.Steps[index].CompletedAt = nil
	item.Steps[index].ErrorCode = ""
	item.Status = Pending
	item.UpdatedAt = s.now().UTC()
	s.items[id] = cloneWorkflow(item)
	return cloneWorkflow(item), nil
}

func (s *Store) Cancel(ctx context.Context, id string) (Workflow, error) {
	p, err := actor(ctx)
	if err != nil {
		return Workflow{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok || item.TenantID != p.TenantID || item.OwnerID != p.ID {
		return Workflow{}, ErrNotFound
	}
	if item.Status == Succeeded || item.Status == Failed || item.Status == Cancelled {
		return Workflow{}, ErrInvalidState
	}
	item.Status = Cancelled
	item.UpdatedAt = s.now().UTC()
	s.items[id] = cloneWorkflow(item)
	return cloneWorkflow(item), nil
}

func stepIndex(steps []Step, id string) int {
	for i := range steps {
		if steps[i].ID == id {
			return i
		}
	}
	return -1
}

func cloneWorkflow(item Workflow) Workflow {
	item.Steps = append([]Step(nil), item.Steps...)
	for i := range item.Steps {
		if item.Steps[i].StartedAt != nil {
			t := *item.Steps[i].StartedAt
			item.Steps[i].StartedAt = &t
		}
		if item.Steps[i].CompletedAt != nil {
			t := *item.Steps[i].CompletedAt
			item.Steps[i].CompletedAt = &t
		}
	}
	return item
}
