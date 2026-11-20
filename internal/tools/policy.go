package tools

import "fmt"

// Policy is an execution-time authorization policy for catalog tools.
// An empty AllowedTools map means no tool-specific restriction; MaxRisk still applies.
type Policy struct {
	AllowedTools map[string]struct{}
	MaxRisk      Risk
}

// ReadOnlyPolicy permits read tools and denies all write-capable tools.
func ReadOnlyPolicy() Policy {
	return Policy{MaxRisk: RiskRead}
}

// Authorize checks the registered definition immediately before execution.
func (p Policy) Authorize(definition Definition) error {
	if len(p.AllowedTools) > 0 {
		if _, ok := p.AllowedTools[definition.ID]; !ok {
			return fmt.Errorf("tool %q is not allowed by policy", definition.ID)
		}
	}
	if riskRank(definition.Risk) > riskRank(p.MaxRisk) {
		return fmt.Errorf("tool %q risk %q exceeds policy maximum %q", definition.ID, definition.Risk, p.MaxRisk)
	}
	if riskRank(definition.Risk) == 0 {
		return fmt.Errorf("tool %q has unknown risk classification", definition.ID)
	}
	return nil
}

func riskRank(risk Risk) int {
	switch risk {
	case RiskRead:
		return 1
	case RiskWrite:
		return 2
	case RiskDestructive:
		return 3
	default:
		return 0
	}
}
