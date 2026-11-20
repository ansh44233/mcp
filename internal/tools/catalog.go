package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync"
)

var toolIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,127}$`)

// Risk classifies the impact of invoking a tool. Unknown values are rejected
// so callers cannot accidentally register an unclassified capability.
type Risk string

const (
	RiskRead        Risk = "read"
	RiskWrite       Risk = "write"
	RiskDestructive Risk = "destructive"
)

// Definition is provider-neutral metadata for one discoverable MCP capability.
// InputSchema must be a JSON object describing the tool's arguments.
type Definition struct {
	ID          string          `json:"id"`
	Provider    string          `json:"provider"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Risk        Risk            `json:"risk"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Registry provides concurrency-safe tool registration and deterministic discovery.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Definition
}

func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]Definition)}
}

// Register validates metadata and schema before atomically adding a definition.
func (r *Registry) Register(def Definition) error {
	if !toolIDPattern.MatchString(def.ID) {
		return fmt.Errorf("invalid tool id %q", def.ID)
	}
	if !toolIDPattern.MatchString(def.Provider) {
		return fmt.Errorf("invalid provider id %q", def.Provider)
	}
	if def.Name == "" || def.Description == "" {
		return fmt.Errorf("tool %q must declare a name and description", def.ID)
	}
	switch def.Risk {
	case RiskRead, RiskWrite, RiskDestructive:
	default:
		return fmt.Errorf("tool %q has invalid risk %q", def.ID, def.Risk)
	}
	if err := validateObjectSchema(def.InputSchema); err != nil {
		return fmt.Errorf("tool %q input schema: %w", def.ID, err)
	}

	// Copy caller-owned bytes so later mutations cannot alter registered metadata.
	def.InputSchema = append(json.RawMessage(nil), def.InputSchema...)

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[def.ID]; exists {
		return fmt.Errorf("tool %q is already registered", def.ID)
	}
	r.tools[def.ID] = def
	return nil
}

func validateObjectSchema(schema json.RawMessage) error {
	if len(bytes.TrimSpace(schema)) == 0 {
		return fmt.Errorf("schema is required")
	}
	var value map[string]any
	if err := json.Unmarshal(schema, &value); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if value == nil {
		return fmt.Errorf("must be a JSON object")
	}
	if kind, ok := value["type"]; !ok || kind != "object" {
		return fmt.Errorf("root type must be object")
	}
	return nil
}

// Get returns a defensive copy of a registered definition.
func (r *Registry) Get(id string) (Definition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.tools[id]
	if !ok {
		return Definition{}, false
	}
	def.InputSchema = append(json.RawMessage(nil), def.InputSchema...)
	return def, true
}

// List returns registered definitions sorted by stable ID.
func (r *Registry) List() []Definition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.tools))
	for id := range r.tools {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	result := make([]Definition, 0, len(ids))
	for _, id := range ids {
		def := r.tools[id]
		def.InputSchema = append(json.RawMessage(nil), def.InputSchema...)
		result = append(result, def)
	}
	return result
}

// Unregister removes a tool definition. It does not affect a running invocation.
func (r *Registry) Unregister(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tools[id]; !ok {
		return false
	}
	delete(r.tools, id)
	return true
}
