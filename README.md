# Universal MCP

A Go-based, provider-neutral Model Context Protocol platform with a first-class operator dashboard.

> **Project status: early foundation.** The repository contains a runnable MCP server, a local dashboard, a provider-neutral tool catalog, and an initial read-only GitHub connector. Authentication beyond an optional GitHub token, remote HTTP access, workflow execution and connector management are not implemented. The current dashboard includes a registry-backed read-only tool catalog.

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
- Read-only `/healthz`, `/api/v1/status`, `/api/v1/tools` and `/api/v1/connectors` endpoints.
- Dashboard tool inventory is generated from the same provider tool definitions used to publish MCP capabilities; supports text search and provider filtering.
- Connector inventory is sourced from the same managed connector registry used by MCP execution and offers an explicit, bounded health-check action for registered providers.
- Graceful HTTP shutdown and structured server logs.
- HTTP mode restricted to loopback addresses until remote authentication and authorization are implemented.
- GitHub Actions checks for formatting, dependency resolution, vetting and tests.

## Planned capabilities

- More complete connector SDK, runtime status reporting and dynamic registration.
- GitHub write operations behind explicit authorization and approval policies.
- Authentication, authorization, secret-provider integration, tenant isolation and audit history.
- Workflow execution, retries and durable checkpoints.
- Full dashboard management views for connectors, sessions, workflows, approvals, logs and security; current connector/tool views are read-only.
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

HTTP mode intentionally binds to loopback only. Do not expose it to a network: remote authentication, authorization and tenant isolation are not implemented yet.

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

## Repository layout

- `cmd/universal-mcp`: executable entry point.
- `internal/server`: MCP server, built-in tools and provider tool registration.
- `internal/tools`: provider-neutral tool metadata catalog and MCP bridge.
- `internal/integrations`: connector lifecycle contract and registry.
- `internal/providers/github`: read-only GitHub REST client and connector adapter.
- `internal/dashboard`: local operator dashboard and read-only API.
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
