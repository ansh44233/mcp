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
- `internal/execution`: reusable bounded operation runner with concurrency limits, cooperative deadlines, cancellation while waiting for capacity and explicitly idempotent, classifier-gated retries. The server wraps GitHub provider execution with this runner (16 concurrent calls, 20-second global maximum deadline). Trusted server-side policy assigns shorter per-tool deadlines: repository metadata 8 seconds, branch/commit/issue/pull-request lists 12 seconds, file reads 10 seconds and recursive trees 20 seconds. A per-operation value can only shorten, never extend, the runner's global maximum. Current provider operations have no retry classifier configured, so they are not retried; future retries require explicit transient-error semantics per operation.
- `internal/integrations`: connector lifecycle contract, concurrency-safe registry and serialized manager for initialization, rollback, unregister and graceful shutdown.
- `internal/providers/github`: read-only GitHub REST client and connector adapter.
- `internal/dashboard`: local operator console, health/status APIs, searchable tool catalog, connector inventory and audit-event APIs.
- `internal/approvals`: tenant-scoped, single-use approval requests bound to exact tool argument digests. Approval decisions require an authenticated principal with explicit `CanApprove` permission, a separate requester identity, matching tenant and sufficient risk/tool/provider scope. The store is currently in-memory, provides tenant-scoped newest-first listing with bounded results and lazy expiry, and is not connected to runtime write execution.
- `internal/audit`: bounded, concurrency-safe event store with optional append-only JSONL persistence, SHA-256 hash chaining and startup verification; stores actor/tenant IDs, tool/provider/risk metadata, outcome and duration, but never raw arguments or credentials.
- `github.com/modelcontextprotocol/go-sdk`: protocol implementation and transports.

## Tool registration and execution

Provider adapters expose typed, read-only operations. The server maps each operation to a provider-neutral tool definition containing a stable ID, provider ID, description, risk classification and JSON input schema. The catalog validates metadata and provides deterministic discovery. The MCP bridge publishes catalog entries through the official SDK and forwards validated arguments to an executor.

The server constructs providers through the connector manager, which initializes adapters before registry publication and rolls back failed registrations. On process termination, the entry point shuts down the transport and then closes the runtime with a bounded deadline. The manager attempts all connector shutdowns and retains failed entries so a caller can retry. The first GitHub adapter currently exposes repository metadata, branches, commits, issues, pull requests, individual text-file reads and recursive Git tree listing. File reads decode GitHub's base64 payload, reject binary encodings and enforce a 1 MiB decoded-file limit. Recursive tree responses preserve GitHub's `truncated` flag so callers can detect incomplete results. The REST client uses GET-only requests, bounded pagination, a request timeout, context cancellation and a response-size limit. Primary and secondary rate-limit responses are returned as typed errors with retry-after and reset metadata when supplied. `GITHUB_TOKEN` is optional and is read from the process environment; it is never stored in the repository.

The dashboard is built from the same runtime instance used by MCP execution: it receives tool metadata from the same `githubToolDefinitions` used for MCP catalog registration, and connector metadata/operations and health checks from the same managed connector registry. This avoids a second independently initialized GitHub connector in HTTP mode. It exposes read-only `/api/v1/tools` and `/api/v1/connectors` inventory endpoints, plus an explicit `POST /api/v1/connectors/{id}/health-check` action. Health checks have a 10-second context deadline and invoke only the registered connector's fixed health-check implementation; the GitHub check targets a fixed public repository rather than accepting an arbitrary URL. Tool search and provider filtering are client-side presentation over the catalog API. The dashboard also renders recent metadata-only audit events and audit persistence/integrity health.

The MCP bridge applies an execution-time risk policy after schema validation and before provider execution. The runtime uses a read-only policy: write, destructive and unknown-risk tools are rejected, and an optional tool allowlist can further restrict access. `internal/security` defines a typed `Principal`, defensive context helpers and a fail-closed `Authorizer` that checks authentication state, tool/provider scopes, a per-principal risk ceiling and optional provider-resource allowlists. The MCP authorization callback receives schema-validated arguments and enforces GitHub repository scopes using a case-insensitive `owner/repo` identity; a non-nil resource map fails closed for providers without a matching scope or a supported resource resolver. The MCP bridge also accepts an authorization callback so a transport layer can evaluate the trusted request context immediately before execution. An optional execution observer records `denied`, `failed`, `succeeded` and invalid-request outcomes; the runtime connects this observer to a durable local audit store by default and exposes newest-first events through `GET /api/v1/audit`; `GET /api/v1/audit/health` reports persistence and integrity status. The audit log is append-only JSONL with SHA-256 hash chaining and startup verification. Hash chaining detects modification of records within the existing chain, but cannot prevent a privileged attacker from rewriting the complete file and recomputing the hashes.

`internal/security.NewBearerMiddleware` composes the official Go SDK bearer-token verifier middleware with a server-side principal resolver, validates that the resolved principal matches the verified token user ID, and attaches it to the HTTP request context. The production runtime does not yet configure a token verifier/resolver or install this middleware. It invokes the principal authorizer for every catalog tool. Stdio and loopback HTTP requests receive an explicit unauthenticated local principal with a read-only risk ceiling; this is a local trust boundary, not remote authentication. A tenant ID is validated as identity metadata, not itself used as an authorization boundary. Tenant isolation depends on a trusted principal resolver assigning the correct provider-resource allowlists; the current GitHub scope mechanism is a foundation, not a complete multi-tenant identity or membership system. Only read-only GitHub operations are currently registered.

The new `internal/execution` runner is a standalone reusable primitive. It acquires a bounded concurrency slot with caller cancellation, creates a per-operation deadline, records attempt count/duration, and retries only when trusted server-side metadata marks an operation idempotent and a trusted error classifier approves the failure. The runner caps retry budgets and never retries non-idempotent operations. Provider functions must honor the supplied context for deadlines to stop work; Go cannot forcibly terminate a function that ignores cancellation. The runner is not yet connected to the MCP executor, so current GitHub execution still relies on the GitHub client's own request timeout and context handling.

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
7. Preserve audit evidence for tool execution decisions and authorized write operations. The executable uses `MCP_AUDIT_PATH` (default `./data/audit.jsonl`) for durable local records. Hash chaining is tamper-evident but not externally anchored.
8. Do not claim a capability is supported until it is implemented and tested.

## Current limitations

- GitHub integration is read-only and currently supports seven repository operations.
- No provider write operations, configured OAuth/token issuer, centralized secret provider, or end-to-end tenant authorization/approval engine exists. Approval storage is an isolated in-memory foundation; only principals explicitly granted `CanApprove` may decide requests, but the approval store is not yet durable or wired into tool execution. The bearer middleware adapter requires a host-supplied verifier and principal resolver and is not wired into the production request path. The principal tenant ID is metadata until provider/resource-level tenant isolation is implemented.
- The connector lifecycle contract and registry exist, but dynamic runtime installation and management are not implemented.
- HTTP mode is local-only and stateless.
- No multi-user tenancy, persistent workflow engine, or externally anchored/tamper-resistant audit backend exists.
- The dashboard is an embedded operator console with a registry-backed tool catalog, connector inventory and audit log; it is not yet the final React/TypeScript management application.
- The bounded execution runner is integrated into GitHub provider execution, but retry classifications, per-tool tuning and load benchmarks remain future work.
- CI runs formatting, `go vet` and unit tests; protocol conformance, E2E, security and performance suites are future work.

## Next milestones

1. Add trusted per-tool idempotency/retry classifications, then benchmark and tune the bounded executor.
2. Complete production authentication and tenant scope provisioning, add approval policies and durable external audit storage before any write operations or remote HTTP exposure.
3. Stabilize dashboard API contracts and build the React/TypeScript operator UI.
4. Add durable workflow orchestration.
5. Add further providers, compatibility testing, security testing and performance benchmarks.
