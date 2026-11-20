package integrations

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
)

var connectorIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

// Registry provides concurrency-safe connector registration and discovery.
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]Connector
}

func NewRegistry() *Registry {
	return &Registry{connectors: make(map[string]Connector)}
}

// Register adds a connector. IDs are unique and validated before mutation.
func (r *Registry) Register(connector Connector) error {
	if connector == nil {
		return fmt.Errorf("connector is nil")
	}
	meta := connector.Metadata()
	if !connectorIDPattern.MatchString(meta.ID) {
		return fmt.Errorf("invalid connector id %q", meta.ID)
	}
	if meta.Name == "" || meta.Version == "" {
		return fmt.Errorf("connector %q must declare a name and version", meta.ID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.connectors[meta.ID]; exists {
		return fmt.Errorf("connector %q is already registered", meta.ID)
	}
	r.connectors[meta.ID] = connector
	return nil
}

// Get returns a registered connector by its stable ID.
func (r *Registry) Get(id string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	connector, ok := r.connectors[id]
	return connector, ok
}

// List returns connector metadata in deterministic ID order.
func (r *Registry) List() []Metadata {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.connectors))
	for id := range r.connectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	result := make([]Metadata, 0, len(ids))
	for _, id := range ids {
		result = append(result, r.connectors[id].Metadata())
	}
	return result
}

// Unregister removes a connector from discovery. Its lifecycle shutdown is
// deliberately explicit and must be handled by the caller before removal.
func (r *Registry) Unregister(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.connectors[id]; !ok {
		return false
	}
	delete(r.connectors, id)
	return true
}
