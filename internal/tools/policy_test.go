package tools

import (
	"strings"
	"testing"
)

func TestReadOnlyPolicyAllowsReadAndDeniesWrites(t *testing.T) {
	policy := ReadOnlyPolicy()
	if err := policy.Authorize(Definition{ID: "repo_read", Risk: RiskRead}); err != nil {
		t.Fatalf("read tool rejected: %v", err)
	}
	for _, risk := range []Risk{RiskWrite, RiskDestructive} {
		err := policy.Authorize(Definition{ID: "mutating_tool", Risk: risk})
		if err == nil || !strings.Contains(err.Error(), "exceeds policy maximum") {
			t.Errorf("risk %q should be denied, got %v", risk, err)
		}
	}
}

func TestPolicyToolAllowlist(t *testing.T) {
	policy := Policy{
		MaxRisk: RiskRead,
		AllowedTools: map[string]struct{}{
			"repo_read": {},
		},
	}
	if err := policy.Authorize(Definition{ID: "repo_read", Risk: RiskRead}); err != nil {
		t.Fatalf("allowlisted tool rejected: %v", err)
	}
	if err := policy.Authorize(Definition{ID: "other_read", Risk: RiskRead}); err == nil {
		t.Fatal("tool outside allowlist was permitted")
	}
}

func TestPolicyRejectsUnknownRisk(t *testing.T) {
	err := ReadOnlyPolicy().Authorize(Definition{ID: "unclassified", Risk: "unknown"})
	if err == nil || !strings.Contains(err.Error(), "unknown risk") {
		t.Fatalf("expected unknown risk rejection, got %v", err)
	}
}
