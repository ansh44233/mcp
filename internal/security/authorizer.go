package security

import (
	"context"
	"fmt"

	"github.com/ansh44233/mcp/internal/tools"
)

// Authorizer evaluates a registered tool against a trusted request principal.
type Authorizer struct {
	// AllowLocalPrincipal permits only the explicit unauthenticated local identity
	// (ID and tenant "local", Authentication "local"). It is not remote auth.
	AllowLocalPrincipal bool
}

// Authorize requires a principal, validates its identity and tenant, then applies
// tool, provider and risk scopes. Empty scope maps mean unrestricted within the
// principal's tenant; MaxRisk is always enforced.
func (a Authorizer) Authorize(ctx context.Context, definition tools.Definition) error {
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		return fmt.Errorf("missing request principal")
	}
	if err := principal.Validate(); err != nil {
		return fmt.Errorf("invalid request principal: %w", err)
	}
	if !principal.Authenticated {
		if !a.AllowLocalPrincipal || principal.ID != "local" || principal.TenantID != "local" || principal.Authentication != "local" {
			return fmt.Errorf("unauthenticated principal is not permitted")
		}
	}
	if len(principal.AllowedTools) > 0 {
		if _, ok := principal.AllowedTools[definition.ID]; !ok {
			return fmt.Errorf("tool %q is outside principal tool scope", definition.ID)
		}
	}
	if len(principal.AllowedProviders) > 0 {
		if _, ok := principal.AllowedProviders[definition.Provider]; !ok {
			return fmt.Errorf("provider %q is outside principal provider scope", definition.Provider)
		}
	}
	if riskRank(definition.Risk) == 0 {
		return fmt.Errorf("tool %q has unknown risk classification", definition.ID)
	}
	if riskRank(definition.Risk) > riskRank(principal.MaxRisk) {
		return fmt.Errorf("tool %q risk %q exceeds principal maximum %q", definition.ID, definition.Risk, principal.MaxRisk)
	}
	return nil
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
