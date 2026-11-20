package integrations

import (
	"context"
	"fmt"
	"sync"
)

// Manager coordinates connector initialization, registration and shutdown.
// It serializes lifecycle mutations while Registry remains safe for concurrent reads.
type Manager struct {
	mu       sync.Mutex
	registry *Registry
	closed   bool
}

func NewManager(registry *Registry) *Manager {
	if registry == nil {
		registry = NewRegistry()
	}
	return &Manager{registry: registry}
}

// Register initializes a connector before publishing it to readers.
// If registration fails, the initialized connector is shut down.
func (m *Manager) Register(ctx context.Context, connector Connector, config Config) error {
	if connector == nil {
		return fmt.Errorf("connector is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("connector manager is closed")
	}
	if err := connector.Initialize(ctx, cloneConfig(config)); err != nil {
		return fmt.Errorf("initialize connector: %w", err)
	}
	if err := m.registry.Register(connector); err != nil {
		shutdownErr := connector.Shutdown(context.WithoutCancel(ctx))
		if shutdownErr != nil {
			return fmt.Errorf("register connector: %w (rollback shutdown: %v)", err, shutdownErr)
		}
		return fmt.Errorf("register connector: %w", err)
	}
	return nil
}

// Unregister shuts down a connector before removing it from discovery.
func (m *Manager) Unregister(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("connector manager is closed")
	}
	connector, ok := m.registry.Get(id)
	if !ok {
		return fmt.Errorf("connector %q is not registered", id)
	}
	if err := connector.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown connector %q: %w", id, err)
	}
	m.registry.Unregister(id)
	return nil
}

// Close shuts down all registered connectors. It attempts every shutdown and
// returns the first error; successful shutdowns are removed from the registry.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	var firstErr error
	metadata := m.registry.List()
	for i := len(metadata) - 1; i >= 0; i-- {
		id := metadata[i].ID
		connector, ok := m.registry.Get(id)
		if !ok {
			continue
		}
		if err := connector.Shutdown(ctx); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("shutdown connector %q: %w", id, err)
			}
			continue
		}
		m.registry.Unregister(id)
	}
	if firstErr == nil {
		m.closed = true
	}
	return firstErr
}

func (m *Manager) Registry() *Registry {
	return m.registry
}

func cloneConfig(config Config) Config {
	clone := make(Config, len(config))
	for key, value := range config {
		clone[key] = value
	}
	return clone
}
