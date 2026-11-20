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

- `cmd/universal-mcp`: process entry point, signal handling, transport selection, HTTP lifecycle and bounded runtime shutdown.
- `internal/server.Runtime`: owns the MCP server and connector manager; `Close` shuts down managed connectors with the caller's deadline.
- `internal/server`: MCP server construction, built-in platform tools, catalog registration and provider tool dispatch.
- `internal/tools`: provider-neutral tool definitions, risk metadata, schema validation and MCP publication bridge.
- `internal/integrations`: connector lifecycle contract, concurrency-safe registry and serialized manager for initialization, rollback, unregister and graceful shutdown.
- `internal/providers/github`: read-only GitHub REST client and connector adapter.
- `internal/dashboard`: local operator console, health/status APIs, searchable tool catalog and connector inventory APIs.
- `github.com/modelcontextprotocol/go-sdk`: protocol implementation and transports.

## Tool registration and execution

Provider adapters expose typed, read-only operations. The server maps each operation to a provider-neutral tool definition containing a stable ID, provider ID, description, risk classification and JSON input schema. The catalog validates metadata and provides deterministic discovery. The MCP bridge publishes catalog entries through the official SDK and forwards validated arguments to an executor.

The server constructs providers through the connector manager, which initializes adapters before registry publication and rolls back failed registrations. On process termination, the entry point shuts down the transport and then closes the runtime with a bounded deadline. The manager attempts all connector shutdowns and retains failed entries so a caller can retry. The first GitHub adapter currently exposes repository metadata, branches, commits, issues, pull requests, individual text-file reads and recursive Git tree listing. File reads decode GitHub's base64 payload, reject binary encodings and enforce a 1 MiB decoded-file limit. Recursive tree responses preserve GitHub's `truncated` flag so callers can detect incomplete results. The REST client uses GET-only requests, bounded pagination, a request timeout, context cancellation and a response-size limit. Primary and secondary rate-limit responses are returned as typed errors with retry-after and reset metadata when supplied. `GITHUB_TOKEN` is optional and is read from the process environment; it is never stored in the repository.

The dashboard is built from the same runtime instance used by MCP execution: it receives tool metadata from the same `githubToolDefinitions` used by MCP catalog registration, and connector metadata/operations and health checks from the same managed connector registry. This avoids a second independently initialized GitHub connector in HTTP mode. It exposes read-only `/api/v1/tools` and `/api/v1/connectors` inventory endpoints, plus an explicit `POST /api/v1/connectors/{id}/health-check` action. Health checks have a 10-second context deadline and invoke only the registered connector's fixed health-check implementation; the GitHub check targets a fixed public repository rather than accepting an arbitrary URL. Tool search and provider filtering are client-side presentation over the catalog API. This keeps the UI inventory aligned with the capabilities published by the server, while avoiding claims that connectors can already be installed or configured through the dashboard.

The MCP bridge applies an execution-time risk policy after schema validation and before provider execution. The runtime uses a read-only policy: write, destructive and unknown-risk tools are rejected, and an optional tool allowlist can further restrict access. `internal/security` now defines a typed `Principal`, defensive context helpers and a fail-closed `Authorizer` that checks authentication state, tool/provider scopes and a per-principal risk ceiling. The MCP bridge also accepts an authorization callback so a transport layer can evaluate the trusted request context immediately before execution. These are tested building blocks, not end-to-end authentication: the production runtime does not yet install a trusted identity middleware or invoke this authorizer. The explicit local principal option is a local-development trust mode, not remote authentication. A tenant ID is currently validated as identity metadata only; provider resource isolation by tenant is not implemented. Only read-only GitHub operations are currently registered.

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

Connectors declare stable IDs, metadata, configuration, health checks, operations and lifecycle methods. Each published tool declares an input schema and risk class. Future connector/tool metadata should also include required scopes, output shape, timeout and retry policy. The platform must enforce authorization independently of connector-provided metadata.

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

- GitHub integration is read-only and currently supports seven repository operations.
- No provider write operations, OAuth flow, centralized secret provider, trusted transport authentication or end-to-end tenant authorization/approval engine exists. The principal and authorization packages are foundations only and are not wired into the production request path.
- The connector lifecycle contract and registry exist, but dynamic runtime installation and management are not implemented.
- HTTP mode is local-only and stateless.
- No multi-user tenancy, persistent workflow engine or remote deployment support exists.
- The dashboard is an embedded read-only operator console with a registry-backed tool catalog and connector inventory; it is not yet the final React/TypeScript management application.
- CI runs formatting, `go vet` and unit tests; protocol conformance, E2E, security and performance suites are future work.

## Next milestones

1. Add connector lifecycle management and runtime configuration.
2. Implement authentication, scoped authorization, approval policies and audit history before any write operations or remote HTTP exposure.
3. Stabilize dashboard API contracts and build the React/TypeScript operator UI.
4. Add bounded execution and durable workflow orchestration.
5. Add further providers, compatibility testing, security testing and performance benchmarks.
