package tools

import (
	"encoding/json"
	"strings"
	"testing"
)

func validDefinition(id string) Definition {
	return Definition{
		ID: id, Provider: "github", Name: "Get repository",
		Description: "Read repository metadata.",
		Risk: RiskRead, InputSchema: json.RawMessage(`{"type":"object","properties":{"owner":{"type":"string"}}}`),
	}
}

func TestRegistryRegisterGetAndList(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(validDefinition("github_repo_get")); err != nil { t.Fatal(err) }
	if err := r.Register(validDefinition("github_issue_get")); err != nil { t.Fatal(err) }

	got, ok := r.Get("github_repo_get")
	if !ok || got.Risk != RiskRead { t.Fatalf("unexpected lookup: %#v, %v", got, ok) }
	list := r.List()
	if len(list) != 2 || list[0].ID != "github_issue_get" || list[1].ID != "github_repo_get" {
		t.Fatalf("list is not stable and sorted: %#v", list)
	}
}

func TestRegistryRejectsInvalidDefinitions(t *testing.T) {
	tests := []struct{name string; mutate func(*Definition)}{
		{"invalid id", func(d *Definition) { d.ID = "Bad ID" }},
		{"invalid provider", func(d *Definition) { d.Provider = "../github" }},
		{"missing description", func(d *Definition) { d.Description = "" }},
		{"unknown risk", func(d *Definition) { d.Risk = "unknown" }},
		{"invalid json", func(d *Definition) { d.InputSchema = json.RawMessage("{") }},
		{"non object schema", func(d *Definition) { d.InputSchema = json.RawMessage("[]") }},
		{"wrong schema root", func(d *Definition) { d.InputSchema = json.RawMessage(`{"type":"string"}`) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := validDefinition("github_repo_get")
			tt.mutate(&d)
			if err := NewRegistry().Register(d); err == nil { t.Fatal("expected validation error") }
		})
	}
}

func TestRegistryRejectsDuplicatesAndDefendsSchemaCopies(t *testing.T) {
	r := NewRegistry()
	d := validDefinition("github_repo_get")
	if err := r.Register(d); err != nil { t.Fatal(err) }
	d.InputSchema[2] = 'x'
	got, _ := r.Get(d.ID)
	if strings.Contains(string(got.InputSchema), "xype") { t.Fatal("registry retained caller-owned schema bytes") }
	if err := r.Register(validDefinition(d.ID)); err == nil { t.Fatal("expected duplicate error") }
	got.InputSchema[2] = 'x'
	again, _ := r.Get(d.ID)
	if strings.Contains(string(again.InputSchema), "xype") { t.Fatal("Get exposed registry-owned schema bytes") }
}

func TestRegistryUnregister(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(validDefinition("github_repo_get")); err != nil { t.Fatal(err) }
	if !r.Unregister("github_repo_get") || r.Unregister("github_repo_get") {
		t.Fatal("unexpected unregister result")
	}
	if len(r.List()) != 0 { t.Fatal("tool remains registered") }
}
