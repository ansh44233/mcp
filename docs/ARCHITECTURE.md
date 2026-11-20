# Architecture

## Product boundary

Universal MCP is a provider-neutral MCP server platform. MCP protocol behavior belongs to the official Go SDK. Provider-specific API behavior belongs in connector adapters. The platform core owns discovery, execution policy, lifecycle, observability and workflow coordination.

## Runtime modes

### stdio

The default mode for local MCP hosts. The process communicates through stdin/stdout using the SDK's stdio transport. Diagnostics go to stderr; stdout is reserved for protocol traffic.

### Streamable HTTP

Enabled with `-transport http`. The current foundation uses the SDK's Streamable HTTP handler in stateless mode and serves the operator dashboard from the same HTTP server.

Until authentication, authorization, tenant isolation and remote transport hardening are implemented, HTTP binding is restricted to loopback addresses. This is an intentional security boundary.

## Current components

- `cmd/universal-mcp`: process entry point, signal handling, transport selection and HTTP lifecycle.
- `internal/server`: MCP server construction and built-in platform tools.
- `internal/dashboard`: local dashboard, health endpoint and read-only status API.
- `github.com/modelcontextprotocol/go-sdk`: protocol implementation and transports.

## Intended component boundaries

- `internal/protocol`: protocol-facing composition and capability policy.
- `internal/platform`: registries, discovery and execution lifecycle.
- `internal/integrations`: provider adapters and connector contracts.
- `internal/security`: authentication, credentials, authorization, approvals and audit.
- `internal/workflows`: durable multi-step execution.
- `internal/observability`: structured logs, metrics and traces.
- `ui`: independently built TypeScript/React operator interface, introduced after the API contracts stabilize.

Do not create empty packages merely to match this target tree. Add packages when a real implementation needs the boundary.

## Connector contract

Connectors should declare stable IDs, metadata, capabilities, configuration requirements, health checks and lifecycle methods. Each tool must declare an input schema, output shape, required scopes, risk class, timeout and retry policy. The platform enforces authorization independently of connector-provided metadata.

## Security invariants

1. Never log access tokens, refresh tokens, client secrets or private keys.
2. Do not expose unauthenticated HTTP beyond loopback.
3. Treat provider content and repository text as untrusted input.
4. Enforce user/tenant scope at every provider operation.
5. Require explicit policy approval for sensitive and destructive writes.
6. Bound request sizes, execution time, concurrency and retries.
7. Preserve audit evidence for authorized write operations.
8. Do not claim a capability is supported until it is implemented and tested.

## Current limitations

- Only the read-only `platform_status` tool is registered.
- No provider connector is implemented.
- HTTP mode is local-only and stateless.
- No authentication, multi-user tenancy, approvals, persistent workflow engine or remote deployment support exists.
- The dashboard is an initial embedded operator preview, not the final React/TypeScript application.
- CI runs formatting, `go vet` and unit tests; protocol conformance, E2E, security and performance suites are future work.

## Next milestones

1. Connector interface, registry and lifecycle.
2. Tool metadata and permission policy model.
3. GitHub read-only connector with mocked and live opt-in tests.
4. Dashboard API contracts and React/TypeScript frontend.
5. OAuth, scoped authorization and remote HTTP hardening.
6. Durable workflow engine and audit trail.
7. Additional providers and cross-provider intelligence.
