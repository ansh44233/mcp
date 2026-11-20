// Package approvals provides an in-memory, tenant-scoped approval gate for
// write-capable tool invocations. It stores only an argument digest, never raw
// arguments. The store is intentionally not wired to production write tools yet.
package approvals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/ansh44233/mcp/internal/security"
	"github.com/ansh44233/mcp/internal/tools"
)

type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Rejected Status = "rejected"
	Expired  Status = "expired"
	Consumed Status = "consumed"
)

var (
	ErrNotFound       = errors.New("approval request not found")
	ErrForbidden      = errors.New("approval action is not permitted")
	ErrInvalidState   = errors.New("approval request is not pending")
	ErrExpired        = errors.New("approval request expired")
	ErrArgumentChange = errors.New("tool arguments do not match approved request")
)

type Request struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	RequesterID   string     `json:"requester_id"`
	ApproverID    string     `json:"approver_id,omitempty"`
	ToolID        string     `json:"tool_id"`
	Provider      string     `json:"provider"`
	Risk          tools.Risk `json:"risk"`
	ArgumentsHash string     `json:"arguments_hash"`
	Status        Status     `json:"status"`
	Reason        string     `json:"reason,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	ConsumedAt    *time.Time `json:"consumed_at,omitempty"`
}

type Store struct {
	mu        sync.Mutex
	requests  map[string]Request
	maxItems  int
	now       func() time.Time
	newID     func() (string, error)
	file      *os.File
	next      uint64
	lastHash  string
	lastError error
	closed    bool
}

func NewStore(maxItems int) *Store {
	if maxItems < 1 {
		maxItems = 10000
	}
	return &Store{requests: make(map[string]Request), maxItems: maxItems, now: time.Now, newID: randomID}
}

func (s *Store) Create(ctx context.Context, definition tools.Definition, arguments json.RawMessage, ttl time.Duration) (Request, error) {
	principal, ok := security.PrincipalFromContext(ctx)
	if !ok {
		return Request{}, ErrForbidden
	}
	if err := principal.Validate(); err != nil || !principal.Authenticated {
		return Request{}, ErrForbidden
	}
	if definition.Risk != tools.RiskWrite && definition.Risk != tools.RiskDestructive {
		return Request{}, fmt.Errorf("approval requests require a write-capable tool")
	}
	if len(arguments) == 0 || !json.Valid(arguments) {
		return Request{}, fmt.Errorf("valid JSON arguments are required")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return Request{}, fmt.Errorf("approval TTL must be between 1ns and 24h")
	}
	id, err := s.newID()
	if err != nil {
		return Request{}, fmt.Errorf("generate approval ID: %w", err)
	}
	now := s.now().UTC()
	sum := sha256.Sum256(arguments)
	request := Request{
		ID: id, TenantID: principal.TenantID, RequesterID: principal.ID,
		ToolID: definition.ID, Provider: definition.Provider, Risk: definition.Risk,
		ArgumentsHash: hex.EncodeToString(sum[:]), Status: Pending,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) >= s.maxItems {
		return Request{}, fmt.Errorf("approval store capacity reached")
	}
	if _, exists := s.requests[id]; exists {
		return Request{}, fmt.Errorf("approval ID collision")
	}
	if err := s.persistLocked(request); err != nil {
		return Request{}, err
	}
	s.requests[id] = request
	return request, nil
}

// Decide requires a different, authenticated principal in the same tenant.
func (s *Store) Decide(ctx context.Context, id string, approve bool, reason string) (Request, error) {
	principal, ok := security.PrincipalFromContext(ctx)
	if !ok || !principal.Authenticated || principal.Validate() != nil {
		return Request{}, ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, exists := s.requests[id]
	if !exists || request.TenantID != principal.TenantID {
		return Request{}, ErrNotFound
	}
	if request.Status != Pending {
		return Request{}, ErrInvalidState
	}
	now := s.now().UTC()
	if !now.Before(request.ExpiresAt) {
		request.Status = Expired
		if err := s.persistLocked(request); err != nil {
			return Request{}, err
		}
		s.requests[id] = request
		return request, ErrExpired
	}
	if !principal.CanApprove || request.RequesterID == principal.ID || riskRank(principal.MaxRisk) < riskRank(request.Risk) {
		return Request{}, ErrForbidden
	}
	if len(principal.AllowedTools) > 0 {
		if _, ok := principal.AllowedTools[request.ToolID]; !ok {
			return Request{}, ErrForbidden
		}
	}
	if len(principal.AllowedProviders) > 0 {
		if _, ok := principal.AllowedProviders[request.Provider]; !ok {
			return Request{}, ErrForbidden
		}
	}
	request.ApproverID = principal.ID
	if len(reason) > 512 {
		reason = reason[:512]
	}
	request.Reason = reason
	request.Status = Rejected
	if approve {
		request.Status = Approved
	}
	request.DecidedAt = &now
	if err := s.persistLocked(request); err != nil {
		return Request{}, err
	}
	s.requests[id] = request
	return request, nil
}

// List returns the current tenant's requests newest-first. It never exposes
// another tenant's records and caps result size to keep operator views bounded.
func (s *Store) List(ctx context.Context, limit int) ([]Request, error) {
	principal, ok := security.PrincipalFromContext(ctx)
	if !ok || !principal.Authenticated || principal.Validate() != nil {
		return nil, ErrForbidden
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	requests := make([]Request, 0)
	for id, request := range s.requests {
		if request.TenantID != principal.TenantID {
			continue
		}
		if !principal.CanApprove && request.RequesterID != principal.ID {
			continue
		}
		if request.Status == Pending && !now.Before(request.ExpiresAt) {
			request.Status = Expired
			if err := s.persistLocked(request); err != nil {
				return nil, err
			}
			s.requests[id] = request
		}
		requests = append(requests, request)
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].CreatedAt.Equal(requests[j].CreatedAt) {
			return requests[i].ID > requests[j].ID
		}
		return requests[i].CreatedAt.After(requests[j].CreatedAt)
	})
	if len(requests) > limit {
		requests = requests[:limit]
	}
	return requests, nil
}

// Consume atomically spends an approved request for the original requester,
// exact tool identity and exact argument bytes. A request can be consumed once.
func (s *Store) Consume(ctx context.Context, id string, definition tools.Definition, arguments json.RawMessage) (Request, error) {
	principal, ok := security.PrincipalFromContext(ctx)
	if !ok || !principal.Authenticated || principal.Validate() != nil {
		return Request{}, ErrForbidden
	}
	sum := sha256.Sum256(arguments)
	digest := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	request, exists := s.requests[id]
	if !exists || request.TenantID != principal.TenantID {
		return Request{}, ErrNotFound
	}
	if request.Status != Approved {
		return Request{}, ErrInvalidState
	}
	now := s.now().UTC()
	if !now.Before(request.ExpiresAt) {
		request.Status = Expired
		if err := s.persistLocked(request); err != nil {
			return Request{}, err
		}
		s.requests[id] = request
		return request, ErrExpired
	}
	if request.RequesterID != principal.ID || request.ToolID != definition.ID ||
		request.Provider != definition.Provider || request.Risk != definition.Risk {
		return Request{}, ErrForbidden
	}
	if digest != request.ArgumentsHash {
		return Request{}, ErrArgumentChange
	}
	request.Status = Consumed
	request.ConsumedAt = &now
	if err := s.persistLocked(request); err != nil {
		return Request{}, err
	}
	s.requests[id] = request
	return request, nil
}

func (s *Store) Get(ctx context.Context, id string) (Request, error) {
	principal, ok := security.PrincipalFromContext(ctx)
	if !ok || !principal.Authenticated || principal.Validate() != nil {
		return Request{}, ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, exists := s.requests[id]
	if !exists || request.TenantID != principal.TenantID ||
		(!principal.CanApprove && request.RequesterID != principal.ID) {
		return Request{}, ErrNotFound
	}
	if request.Status == Pending && !s.now().Before(request.ExpiresAt) {
		request.Status = Expired
		if err := s.persistLocked(request); err != nil {
			return Request{}, err
		}
		s.requests[id] = request
	}
	return request, nil
}

func riskRank(risk tools.Risk) int {
	switch risk {
	case tools.RiskRead:
		return 1
	case tools.RiskWrite:
		return 2
	case tools.RiskDestructive:
		return 3
	default:
		return 0
	}
}
