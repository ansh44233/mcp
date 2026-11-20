# Universal MCP

A Go-based, provider-neutral Model Context Protocol platform with a first-class operator dashboard.

> **Project status: early foundation.** The repository contains a runnable MCP server, a local dashboard, a provider-neutral tool catalog, an initial read-only GitHub connector, and optional OIDC bearer authentication for the local `/mcp` endpoint. The dashboard does not yet have browser authentication; remote HTTP exposure remains disabled. Workflow execution and interactive connector management are not implemented.

## Vision

Universal MCP connects MCP-compatible AI clients to developer platforms and business services through a consistent, secure connector architecture.

### Design principles

- **Protocol-first:** use the official MCP Go SDK rather than reimplementing MCP or JSON-RPC.
- **Provider-neutral core:** integrations are adapters, not hard-coded protocol features.
- **Secure by default:** least privilege, explicit authorization, bounded execution and auditable writes.
- **Observable:** structured logs, health signals and operational visibility.
- **Honest compatibility:** advertise only capabilities implemented and tested by this server.

## Implemented foundation

- Official MCP Go SDK pinned at `v1.8.0`.
- Go server with stdio and Streamable HTTP transports.
- Read-only `platform_status` MCP tool with structured output.
- Provider-neutral tool catalog with stable IDs, provider metadata, risk classification and JSON input-schema validation.
- Catalog-to-MCP bridge: registered definitions are discoverable and invokable through the official SDK.
- Execution-time risk policy: the default runtime permits read tools only, supports an explicit tool allowlist and rejects write/destructive or unknown-risk tools before the executor runs.
- Initial authorization primitives: typed request principals, defensive context propagation, fail-closed principal validation, tool/provider scopes, per-principal risk ceilings and provider-resource allowlists (GitHub owner/repository); authenticated principals without an explicit resource-scope map are denied by default, and the MCP bridge enforces resource authorization against schema-validated arguments before execution.
- Bearer middleware adapter: composes the official MCP Go SDK token middleware with a trusted server-side principal resolver. The HTTP executable can configure this adapter from OIDC issuer/audience/client credentials and a strict subject-to-tenant/tool/provider/resource grants file; partial configuration fails startup. The default local mode remains available when no OIDC settings are supplied.
- OIDC-discovered OAuth token-introspection verifier: uses the issuer metadata's RFC 7662 introspection endpoint with confidential-client authentication; requires an active token, exact issuer, configured audience, subject and future expiry; bounds token and response sizes, limits requests, rejects unsafe issuer/endpoint origins and redirects, and extracts scopes only from the authenticated introspection response.
- Static subject grant resolver: maps verified issuer subjects to operator-defined tenants and explicit tool/provider/resource allowlists. Grants are loaded from a bounded JSON file with unknown-field and trailing-data rejection; unprovisioned subjects fail closed.
- Initial GitHub read-only connector using the GitHub REST API:
  - Repository metadata
  - Branch listing
  - Commit listing
  - Issue listing (pull requests filtered out)
  - Pull-request listing
  - Single text-file reads (base64 decoded, 1 MiB maximum; binary files rejected)
  - Recursive Git tree listing, with GitHub's truncation flag preserved
- Bounded pagination, request timeout, response-size limit and context cancellation for GitHub API calls.
- Typed primary/secondary rate-limit errors with retry-after and reset metadata when provided by GitHub.
- Optional `GITHUB_TOKEN` environment variable for authenticated GitHub API access; public repository reads work without it.
- Mock HTTP tests for the GitHub client and lifecycle tests for the connector.
- Managed connector lifecycle: initialize-before-publish, rollback on registration failure, orderly unregister and retryable graceful shutdown.
- The process owns a runtime handle and closes managed provider connectors after stdio or HTTP transport shutdown.
- Local operator dashboard served by HTTP mode.
- Read-only `/healthz`, `/api/v1/status`, `/api/v1/tools`, `/api/v1/connectors` and audit endpoints, plus tenant-scoped approval review API routes.
- Dashboard tool inventory is generated from the same provider tool definitions used to publish MCP capabilities; supports text search and provider filtering.
- Connector inventory is sourced from the same managed connector registry used by MCP execution and offers an explicit, bounded health-check action for registered providers.
- Optional durable workflow checkpoint journal via `MCP_WORKFLOW_PATH` (disabled by default); when configured, the runtime verifies and recovers it at startup and closes it during graceful shutdown. Interrupted running steps are marked failed rather than automatically replayed. This stores workflow state only; it does not execute tools or expose workflow APIs. The journal is tenant-scoped at the store layer and uses a SHA-256 hash chain, but requires single-process ownership and has no external tamper anchor.
- Approval requests are owned by the runtime in memory by default; set `MCP_APPROVAL_PATH` to enable a private, append-only, hash-chained JSONL journal with startup verification and graceful shutdown. Approval requests store argument digests rather than raw arguments. The approval package includes `ExecuteApproved`, which consumes the exact tenant/requester/tool/argument-bound approval before calling an executor; failed or uncertain external operations do not make the approval reusable. The dashboard API now exposes authenticated, tenant-scoped request listing/detail and reviewer decision routes. Requesters can inspect only their own requests; reviewers must have explicit approval permission and matching risk/tool/provider scopes. These routes require a trusted authenticated principal in request context and are not yet reachable through the default local dashboard middleware. No production write-capable MCP tools use the approval gate yet.
- Durable append-only JSONL audit trail (enabled by default in the executable at `./data/audit.jsonl`) uses a SHA-256 hash chain, verifies it on startup and records denied, failed and successful MCP tool calls with actor/tenant identity, tool metadata, outcome and duration; raw arguments, credentials and raw errors are excluded.
- Read-only `/api/v1/audit` endpoint exposes newest-first audit events with a bounded result limit; `/api/v1/audit/health` reports persistence and integrity status.
- Approval API: `GET /api/v1/approvals` lists requests visible to the authenticated principal; `GET /api/v1/approvals/{id}` returns a visible request; `POST /api/v1/approvals/{id}/decision` accepts `{"approve":true|false,"reason":"..."}` from an authorized reviewer. The decision body is size-limited, rejects unknown fields and requires an explicit boolean. The executable configures bearer authentication for `/mcp` only when all OIDC settings and trusted grants are supplied. Dashboard approval routes still require a trusted authenticated principal, but browser login and middleware for these routes are not yet implemented.
- Graceful HTTP shutdown and structured server logs.
- HTTP mode restricted to loopback addresses because the dashboard and operator APIs do not yet have browser authentication.
- GitHub Actions checks for formatting, dependency resolution, vetting and tests.

## Planned capabilities

- More complete connector SDK, runtime status reporting and dynamic registration.
- GitHub write operations behind explicit authorization and approval policies.
- Support for identity providers that do not expose a compatible introspection endpoint, dynamic tenant membership and grant administration, secret-provider integration, and externally anchored/tamper-resistant audit storage. The local hash chain is tamper-evident but an attacker able to rewrite the entire file can recompute it. Resource allowlists are enforced from trusted server-side grants; tenant IDs alone do not imply isolation.
- Workflow execution, worker scheduling, authenticated workflow APIs, and dashboard workflow controls. The optional journal persists workflow metadata/checkpoints only; it does not execute tools.
- Full dashboard management views for connectors, sessions, workflows, approvals, logs and security; approval review APIs exist, but the frontend review panel and production authentication integration remain outstanding.
- Additional providers and cross-provider search.
- MCP compatibility, security, performance and reliability benchmarks.

## Requirements

- Go 1.25 or newer.
- Git.

## Run locally

Install dependencies:

```bash
go mod tidy
```

Run as an MCP stdio server (the default for local MCP clients):

```bash
go run ./cmd/universal-mcp
```

For authenticated GitHub API access, set `GITHUB_TOKEN` in the process environment before starting the server. Use a least-privilege token; never commit it or paste it into source files.

Run the local dashboard and Streamable HTTP MCP endpoint:

```bash
go run ./cmd/universal-mcp -transport http
```

Then open:

- Dashboard: http://127.0.0.1:8080/
- Health: http://127.0.0.1:8080/healthz
- Status API: http://127.0.0.1:8080/api/v1/status
- Tool catalog API: http://127.0.0.1:8080/api/v1/tools
- Connector inventory API: http://127.0.0.1:8080/api/v1/connectors
- Connector health check: POST http://127.0.0.1:8080/api/v1/connectors/github/health-check
- MCP endpoint: http://127.0.0.1:8080/mcp

HTTP mode intentionally binds to loopback only. When all OIDC settings are configured, the `/mcp` endpoint requires a bearer access token validated through the issuer's introspection endpoint and a matching subject grant. With no OIDC settings, local loopback mode uses the explicit read-only local principal. Partial OIDC configuration fails closed. The dashboard and operator APIs do not yet have browser login/authentication, so remote binding remains disabled.

### Optional OIDC authentication for the local HTTP MCP endpoint

Configure all five variables to require bearer-token introspection on `/mcp`:

- `MCP_OIDC_ISSUER`: exact issuer URL from the provider's discovery metadata.
- `MCP_OIDC_AUDIENCE`: audience expected by this MCP resource server.
- `MCP_OIDC_CLIENT_ID` and `MCP_OIDC_CLIENT_SECRET`: confidential client credentials for the introspection endpoint.
- `MCP_AUTHZ_GRANTS_FILE`: path to a trusted JSON file mapping verified token subjects to tenant and resource scopes.

Example grants file:

```json
{
  "provider-subject-123": {
    "tenant_id": "engineering",
    "max_risk": "read",
    "allowed_tools": ["github_repository_get", "github_branches_list"],
    "allowed_providers": ["github"],
    "allowed_resources": {
      "github": ["acme/demo", "acme/platform"]
    }
  }
}
```

The provider must publish an `introspection_endpoint` in its discovery metadata and return active status, issuer, audience, subject and expiry for access tokens. Keep the grants file and client secret under operator control; never accept tenant or resource scopes from MCP arguments. Only subjects explicitly listed in the grants file are admitted. The current server still binds to loopback because dashboard browser authentication is not implemented.

## Operator dashboard frontend

The React + TypeScript dashboard source lives in `dashboard/` and is built with Vite:

```bash
cd dashboard
npm install
npm run dev
```

The Vite development server proxies `/api` and `/healthz` to the local Go server at `127.0.0.1:8080`. Run the Go server in HTTP mode in a separate terminal. Production assets are currently built to `dashboard/dist`; the Go server still serves the existing embedded dashboard until the static-asset integration milestone is completed.

The dashboard build has its own GitHub Actions type-check/build workflow.

For HTTP-mode deployments, build the frontend before starting the Go server:

```bash
cd dashboard
npm install
npm run build
cd ..
go run ./cmd/universal-mcp -transport http
```

The server serves `dashboard/dist` when present. Set `MCP_DASHBOARD_DIR` to use another built-asset directory. If the directory or its `index.html` is absent, the embedded fallback console remains available. API endpoints continue to be served by the Go runtime.

## GitHub MCP tools

The server currently advertises these read-only tools:

| Tool | Required arguments | Optional arguments |
|---|---|---|
| `github_repository_get` | `owner`, `repo` | — |
| `github_branches_list` | `owner`, `repo` | `page`, `per_page` |
| `github_commits_list` | `owner`, `repo` | `page`, `per_page` |
| `github_issues_list` | `owner`, `repo` | `state`, `page`, `per_page` |
| `github_pull_requests_list` | `owner`, `repo` | `state`, `page`, `per_page` |
| `github_file_get` | `owner`, `repo`, `path` | `ref` |
| `github_tree_get` | `owner`, `repo`, `ref` | — |

All operations use HTTP GET. This first connector release does not create, edit, merge or delete GitHub resources.

## Quality checks

```bash
gofmt -w ./cmd ./internal
go vet ./...
go test ./...
```

### Performance benchmarks

Run the catalog and execution benchmarks locally:

```bash
go test -run '^

- `cmd/universal-mcp`: executable entry point.
- `internal/server`: MCP server, built-in tools and provider tool registration.
- `internal/tools`: provider-neutral tool metadata catalog and MCP bridge.
- `internal/integrations`: connector lifecycle contract and registry.
- `internal/providers/github`: read-only GitHub REST client and connector adapter.
- `internal/dashboard`: local operator dashboard and read-only API.
- `internal/audit`: bounded, concurrency-safe, metadata-only in-memory audit event store.
- `docs`: architecture and operational documentation.
- `.github/workflows`: CI automation.

Implementation details stay under `internal/`. Public Go packages will be added only when we have stable APIs intended for reuse.

## Security

Never commit access tokens, OAuth client secrets, private keys or production credentials. GitHub access is read-only in this release. The HTTP listener remains loopback-only. The `/mcp` route supports optional OIDC bearer-token introspection with trusted subject grants; the dashboard and operator APIs do not yet have browser authentication, so remote exposure is blocked.

## Project commitments

- All accepted development commits land directly on `main`, per the repository owner's workflow preference.
- Commits represent meaningful, reviewable work; no artificial history inflation.
- A feature is not called complete until tests and documentation support that claim.
- Production readiness requires protocol, security, compatibility and operational validation.

## License

License selection is pending. Do not assume this project is licensed for redistribution until a license file is added.
 -bench '^(BenchmarkRegistry|BenchmarkRunner)' -benchmem -benchtime=300ms -count=3 ./internal/tools ./internal/execution
```

GitHub Actions also runs the benchmark suite on a weekly schedule or manual dispatch and uploads `benchmark-results.txt` as a 30-day artifact. Results are measurements for the runner environment, not universal performance guarantees.

## Repository layout

- `cmd/universal-mcp`: executable entry point.
- `internal/server`: MCP server, built-in tools and provider tool registration.
- `internal/tools`: provider-neutral tool metadata catalog and MCP bridge.
- `internal/integrations`: connector lifecycle contract and registry.
- `internal/providers/github`: read-only GitHub REST client and connector adapter.
- `internal/dashboard`: local operator dashboard and read-only API.
- `internal/audit`: bounded, concurrency-safe, metadata-only in-memory audit event store.
- `docs`: architecture and operational documentation.
- `.github/workflows`: CI automation.

Implementation details stay under `internal/`. Public Go packages will be added only when we have stable APIs intended for reuse.

## Security

Never commit access tokens, OAuth client secrets, private keys or production credentials. GitHub access is read-only in this release. The current HTTP endpoint is local-only and unauthenticated. Remote exposure is intentionally blocked until authentication, authorization and transport security are implemented and tested.

## Project commitments

- All accepted development commits land directly on `main`, per the repository owner's workflow preference.
- Commits represent meaningful, reviewable work; no artificial history inflation.
- A feature is not called complete until tests and documentation support that claim.
- Production readiness requires protocol, security, compatibility and operational validation.

## License

License selection is pending. Do not assume this project is licensed for redistribution until a license file is added.
