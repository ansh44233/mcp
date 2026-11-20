package integrations

import "context"

// Config contains connector configuration values. Secret material must be
// supplied through a secret provider at runtime, not committed to source.
type Config map[string]string

// Metadata is the stable, non-secret identity of a provider connector.
type Metadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// Operation describes one capability exposed by a connector.
type Operation struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	ReadOnly    bool   `json:"read_only"`
}

// Connector is the lifecycle contract implemented by provider adapters.
// Implementations must be safe for concurrent health checks and operations.
type Connector interface {
	Metadata() Metadata
	Initialize(context.Context, Config) error
	HealthCheck(context.Context) error
	Operations() []Operation
	Shutdown(context.Context) error
}
