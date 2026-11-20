package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
	return a.AuthorizeRequest(ctx, definition, nil)
}

// AuthorizeRequest applies identity, capability and provider-resource scopes
// after the MCP SDK has validated the tool arguments.
func (a Authorizer) AuthorizeRequest(ctx context.Context, definition tools.Definition, arguments json.RawMessage) error {
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
	if principal.AllowedResources != nil {
		resource, err := resourceID(definition.Provider, arguments)
		if err != nil {
			return err
		}
		allowed, providerScoped := principal.AllowedResources[definition.Provider]
		if !providerScoped {
			return fmt.Errorf("provider %q has no resource scope", definition.Provider)
		}
		if _, ok := allowed[resource]; !ok {
			return fmt.Errorf("resource %q is outside principal resource scope", resource)
		}
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

func resourceID(provider string, arguments json.RawMessage) (string, error) {
	if provider != "github" {
		return "", fmt.Errorf("resource scoping is not implemented for provider %q", provider)
	}
	var input struct {
		Owner string `json:"owner"`
		Repo  string `json:"repo"`
	}
	if len(arguments) == 0 || json.Unmarshal(arguments, &input) != nil {
		return "", fmt.Errorf("cannot determine GitHub resource from tool arguments")
	}
	owner, repo := strings.ToLower(strings.TrimSpace(input.Owner)), strings.ToLower(strings.TrimSpace(input.Repo))
	if owner == "" || repo == "" || strings.Contains(owner, "/") || strings.Contains(repo, "/") {
		return "", fmt.Errorf("invalid GitHub resource identity")
	}
	return owner + "/" + repo, nil
}
