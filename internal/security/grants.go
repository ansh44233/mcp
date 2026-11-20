package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ansh44233/mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const maxPrincipalGrantsBytes = 1 << 20

// PrincipalGrant is a trusted, server-side authorization assignment keyed by
// the exact subject returned by the configured identity provider.
type PrincipalGrant struct {
	TenantID         string              `json:"tenant_id"`
	MaxRisk          tools.Risk          `json:"max_risk"`
	CanApprove       bool                `json:"can_approve"`
	AllowedTools     []string            `json:"allowed_tools"`
	AllowedProviders []string            `json:"allowed_providers"`
	AllowedResources map[string][]string `json:"allowed_resources"`
}

// LoadPrincipalGrants reads a bounded JSON subject-to-scope map. Unknown fields
// and trailing JSON are rejected so configuration mistakes fail at startup.
func LoadPrincipalGrants(path string) (map[string]PrincipalGrant, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("principal grants path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open principal grants: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat principal grants: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("principal grants must be a regular file")
	}
	if info.Size() > maxPrincipalGrantsBytes {
		return nil, fmt.Errorf("principal grants exceed %d-byte limit", maxPrincipalGrantsBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxPrincipalGrantsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read principal grants: %w", err)
	}
	if len(data) > maxPrincipalGrantsBytes {
		return nil, fmt.Errorf("principal grants exceed %d-byte limit", maxPrincipalGrantsBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var grants map[string]PrincipalGrant
	if err := decoder.Decode(&grants); err != nil {
		return nil, fmt.Errorf("decode principal grants: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("principal grants contain trailing JSON")
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf("principal grants must contain at least one subject")
	}
	if _, err := NewStaticPrincipalResolver(grants); err != nil {
		return nil, fmt.Errorf("validate principal grants: %w", err)
	}
	return grants, nil
}

// NewStaticPrincipalResolver builds a fail-closed resolver from trusted
// operator configuration. It never reads tenant or scope values from a request.
func NewStaticPrincipalResolver(grants map[string]PrincipalGrant) (PrincipalResolver, error) {
	if len(grants) == 0 {
		return nil, fmt.Errorf("at least one principal grant is required")
	}

	resolved := make(map[string]Principal, len(grants))
	for subject, grant := range grants {
		if strings.TrimSpace(subject) == "" {
			return nil, fmt.Errorf("principal grant contains an empty subject")
		}
		if strings.TrimSpace(grant.TenantID) == "" {
			return nil, fmt.Errorf("principal %q has no tenant ID", subject)
		}
		if len(grant.AllowedTools) == 0 || len(grant.AllowedProviders) == 0 || len(grant.AllowedResources) == 0 {
			return nil, fmt.Errorf("principal %q must define tool, provider and resource scopes", subject)
		}

		allowedTools, err := strictScopeSet(grant.AllowedTools, "tool")
		if err != nil {
			return nil, fmt.Errorf("principal %q: %w", subject, err)
		}
		allowedProviders, err := strictScopeSet(grant.AllowedProviders, "provider")
		if err != nil {
			return nil, fmt.Errorf("principal %q: %w", subject, err)
		}
		principal := Principal{
			ID:               subject,
			TenantID:         grant.TenantID,
			Authenticated:    true,
			Authentication:   "bearer",
			MaxRisk:          grant.MaxRisk,
			CanApprove:       grant.CanApprove,
			AllowedTools:     allowedTools,
			AllowedProviders: allowedProviders,
			AllowedResources: make(map[string]map[string]struct{}, len(grant.AllowedResources)),
		}
		for provider, resources := range grant.AllowedResources {
			if strings.TrimSpace(provider) == "" || provider != strings.TrimSpace(provider) || len(resources) == 0 {
				return nil, fmt.Errorf("principal %q has an invalid resource scope for provider %q", subject, provider)
			}
			if _, ok := allowedProviders[provider]; !ok {
				return nil, fmt.Errorf("principal %q has resource scopes for provider %q without allowing that provider", subject, provider)
			}
			resourceSet, err := strictScopeSet(resources, "resource")
			if err != nil {
				return nil, fmt.Errorf("principal %q provider %q: %w", subject, provider, err)
			}
			if provider == "github" {
				canonical := make(map[string]struct{}, len(resourceSet))
				for resource := range resourceSet {
					canonical[strings.ToLower(resource)] = struct{}{}
				}
				resourceSet = canonical
			}
			principal.AllowedResources[provider] = resourceSet
		}
		if err := principal.Validate(); err != nil {
			return nil, fmt.Errorf("principal %q is invalid: %w", subject, err)
		}
		resolved[subject] = principal
	}

	return func(_ context.Context, tokenInfo *auth.TokenInfo) (Principal, error) {
		if tokenInfo == nil || strings.TrimSpace(tokenInfo.UserID) == "" {
			return Principal{}, fmt.Errorf("verified token subject is required")
		}
		principal, ok := resolved[tokenInfo.UserID]
		if !ok {
			return Principal{}, fmt.Errorf("subject is not provisioned")
		}
		principal.AllowedTools = cloneSet(principal.AllowedTools)
		principal.AllowedProviders = cloneSet(principal.AllowedProviders)
		principal.AllowedResources = cloneResourceSets(principal.AllowedResources)
		return principal, nil
	}, nil
}

func strictScopeSet(values []string, kind string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one %s scope is required", kind)
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || trimmed != value {
			return nil, fmt.Errorf("%s scopes must be non-empty and have no surrounding whitespace", kind)
		}
		if _, exists := set[trimmed]; exists {
			return nil, fmt.Errorf("duplicate %s scope %q", kind, trimmed)
		}
		set[trimmed] = struct{}{}
	}
	return set, nil
}
