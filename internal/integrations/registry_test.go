package integrations

import (
	"context"
	"testing"
)

type testConnector struct {
	meta Metadata
}

func (c *testConnector) Metadata() Metadata                       { return c.meta }
func (c *testConnector) Initialize(context.Context, Config) error { return nil }
func (c *testConnector) HealthCheck(context.Context) error        { return nil }
func (c *testConnector) Operations() []Operation                  { return nil }
func (c *testConnector) Shutdown(context.Context) error           { return nil }

func TestRegistryRegisterGetAndList(t *testing.T) {
	r := NewRegistry()
	beta := &testConnector{meta: Metadata{ID: "beta", Name: "Beta", Version: "1.0.0"}}
	alpha := &testConnector{meta: Metadata{ID: "alpha", Name: "Alpha", Version: "1.0.0"}}

	if err := r.Register(beta); err != nil {
		t.Fatalf("register beta: %v", err)
	}
	if err := r.Register(alpha); err != nil {
		t.Fatalf("register alpha: %v", err)
	}
	got, ok := r.Get("alpha")
	if !ok || got.Metadata().Name != "Alpha" {
		t.Fatalf("Get(alpha) = (%v, %v)", got, ok)
	}

	list := r.List()
	if len(list) != 2 || list[0].ID != "alpha" || list[1].ID != "beta" {
		t.Fatalf("List() is not stable and sorted: %+v", list)
	}
}

func TestRegistryRejectsInvalidAndDuplicateConnectors(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&testConnector{meta: Metadata{ID: "../unsafe", Name: "Bad", Version: "1"}}); err == nil {
		t.Fatal("expected invalid connector ID to be rejected")
	}
	connector := &testConnector{meta: Metadata{ID: "github", Name: "GitHub", Version: "1.0.0"}}
	if err := r.Register(connector); err != nil {
		t.Fatalf("register connector: %v", err)
	}
	if err := r.Register(connector); err == nil {
		t.Fatal("expected duplicate connector ID to be rejected")
	}
}

func TestRegistryUnregister(t *testing.T) {
	r := NewRegistry()
	connector := &testConnector{meta: Metadata{ID: "github", Name: "GitHub", Version: "1.0.0"}}
	if err := r.Register(connector); err != nil {
		t.Fatal(err)
	}
	if !r.Unregister("github") {
		t.Fatal("expected connector to be unregistered")
	}
	if _, ok := r.Get("github"); ok {
		t.Fatal("connector remains registered")
	}
	if r.Unregister("github") {
		t.Fatal("unregister should return false for missing connector")
	}
}
