package integrations

import (
	"context"
	"errors"
	"testing"
)

type lifecycleConnector struct {
	meta        Metadata
	initErr     error
	shutdownErr error
	initialized bool
	shutdowns   int
}

func (c *lifecycleConnector) Metadata() Metadata { return c.meta }

func (c *lifecycleConnector) Initialize(_ context.Context, _ Config) error {
	if c.initErr != nil {
		return c.initErr
	}
	c.initialized = true
	return nil
}

func (c *lifecycleConnector) HealthCheck(context.Context) error { return nil }

func (c *lifecycleConnector) Operations() []Operation { return nil }

func (c *lifecycleConnector) Shutdown(context.Context) error {
	c.shutdowns++
	if c.shutdownErr != nil {
		return c.shutdownErr
	}
	c.initialized = false
	return nil
}

func newLifecycleConnector(id string) *lifecycleConnector {
	return &lifecycleConnector{
		meta: Metadata{ID: id, Name: id, Version: "1.0.0"},
	}
}

func TestManagerInitializesBeforePublishing(t *testing.T) {
	registry := NewRegistry()
	manager := NewManager(registry)
	connector := newLifecycleConnector("github")
	if err := manager.Register(context.Background(), connector, Config{"mode": "test"}); err != nil {
		t.Fatal(err)
	}
	if !connector.initialized {
		t.Fatal("connector was published without initialization")
	}
	if _, ok := registry.Get("github"); !ok {
		t.Fatal("initialized connector was not registered")
	}
}

func TestManagerRollsBackFailedRegistration(t *testing.T) {
	registry := NewRegistry()
	existing := newLifecycleConnector("github")
	if err := registry.Register(existing); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(registry)
	duplicate := newLifecycleConnector("github")
	if err := manager.Register(context.Background(), duplicate, nil); err == nil {
		t.Fatal("expected duplicate registration error")
	}
	if duplicate.initialized || duplicate.shutdowns != 1 {
		t.Fatalf("failed registration was not rolled back: %+v", duplicate)
	}
}

func TestManagerDoesNotPublishInitializationFailure(t *testing.T) {
	registry := NewRegistry()
	manager := NewManager(registry)
	connector := newLifecycleConnector("github")
	connector.initErr = errors.New("bad credentials")
	if err := manager.Register(context.Background(), connector, nil); err == nil {
		t.Fatal("expected initialization error")
	}
	if _, ok := registry.Get("github"); ok {
		t.Fatal("connector with failed initialization was published")
	}
	if connector.shutdowns != 0 {
		t.Fatal("shutdown called for connector that never initialized")
	}
}

func TestManagerUnregisterShutsDownBeforeRemoval(t *testing.T) {
	registry := NewRegistry()
	manager := NewManager(registry)
	connector := newLifecycleConnector("github")
	if err := manager.Register(context.Background(), connector, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Unregister(context.Background(), "github"); err != nil {
		t.Fatal(err)
	}
	if connector.initialized || connector.shutdowns != 1 {
		t.Fatalf("connector was not shut down: %+v", connector)
	}
	if _, ok := registry.Get("github"); ok {
		t.Fatal("connector remained registered after shutdown")
	}
}

func TestManagerCloseAttemptsAllAndCanRetry(t *testing.T) {
	registry := NewRegistry()
	manager := NewManager(registry)
	first := newLifecycleConnector("alpha")
	second := newLifecycleConnector("beta")
	second.shutdownErr = errors.New("temporary shutdown failure")
	if err := manager.Register(context.Background(), first, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(context.Background(), second, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(context.Background()); err == nil {
		t.Fatal("expected shutdown error")
	}
	if _, ok := registry.Get("alpha"); ok {
		t.Fatal("successfully shut down connector remains registered")
	}
	if _, ok := registry.Get("beta"); !ok {
		t.Fatal("connector with failed shutdown was removed")
	}
	second.shutdownErr = nil
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(registry.List()) != 0 {
		t.Fatal("registry not empty after successful close")
	}
	if err := manager.Register(context.Background(), newLifecycleConnector("gamma"), nil); err == nil {
		t.Fatal("closed manager accepted a connector")
	}
}
