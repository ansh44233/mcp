# Universal MCP

A Go-based, provider-neutral Model Context Protocol platform with a first-class operator dashboard.

> **Project status: early foundation.** The repository contains a runnable MCP server foundation, a local operator dashboard, a status tool and initial CI checks. Provider integrations, remote authentication, workflow execution and the full management UI are not implemented yet.

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
- Local operator dashboard served by the HTTP mode.
- Read-only `/healthz` and `/api/v1/status` endpoints.
- Graceful HTTP shutdown and structured server logs.
- HTTP mode restricted to loopback addresses until authentication and authorization are implemented.
- Initial GitHub Actions checks for formatting, vetting and tests.

## Planned capabilities

- Connector SDK and registry.
- GitHub as the first integration, followed by additional providers.
- Authentication, authorization, approval policies and audit history.
- Workflow execution, retries and durable checkpoints.
- Dashboard views for connectors, tools, sessions, workflows, approvals, logs and security.
- Cross-provider search and context intelligence.

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

Run the local dashboard and Streamable HTTP MCP endpoint:

```bash
go run ./cmd/universal-mcp -transport http
```

Then open:

- Dashboard: http://127.0.0.1:8080/
- Health: http://127.0.0.1:8080/healthz
- Status API: http://127.0.0.1:8080/api/v1/status
- MCP endpoint: http://127.0.0.1:8080/mcp

HTTP mode intentionally binds to loopback only. Do not expose it to a network: remote authentication, authorization and tenant isolation are not implemented yet.

## Quality checks

```bash
gofmt -w ./cmd ./internal
go vet ./...
go test ./...
```

## Repository layout

- `cmd/universal-mcp`: executable entry point.
- `internal/server`: MCP server and built-in platform tools.
- `internal/dashboard`: local operator dashboard and read-only API.
- `docs`: architecture and operational documentation (being expanded).
- `.github/workflows`: CI automation.

Implementation details stay under `internal/`. Public Go packages will be added only when we have stable APIs intended for reuse.

## Security

Never commit access tokens, OAuth client secrets, private keys or production credentials. The current HTTP endpoint is local-only and unauthenticated. Remote exposure is intentionally blocked until authentication, authorization and transport security are implemented and tested.

## Project commitments

- All accepted development commits land directly on `main`, per the repository owner's workflow preference.
- Commits represent meaningful, reviewable work; no artificial history inflation.
- A feature is not called complete until tests and documentation support that claim.
- Production readiness requires protocol, security, compatibility and operational validation.

## License

License selection is pending. Do not assume this project is licensed for redistribution until a license file is added.
