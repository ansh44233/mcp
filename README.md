# Universal MCP

A Go-based, provider-neutral Model Context Protocol platform with a first-class operator dashboard.

> **Project status: foundation in development.** This repository is being built incrementally. Features are documented as planned until their implementation and tests land.

## Vision

Universal MCP connects MCP-compatible AI clients to developer platforms and business services through a consistent, secure connector architecture.

### Design principles

- **Protocol-first:** use the official MCP Go SDK rather than reimplementing MCP or JSON-RPC.
- **Provider-neutral core:** integrations are adapters, not hard-coded protocol features.
- **Secure by default:** least privilege, explicit authorization, bounded execution and auditable writes.
- **Observable:** structured logs, health signals and operational visibility.
- **Honest compatibility:** advertise only capabilities implemented and tested by this server.

## Planned capabilities

- MCP server runtime: stdio first, Streamable HTTP after transport and security validation.
- Tools, resources and prompts with schema validation.
- Connector SDK and registry.
- GitHub as the first integration, followed by additional providers.
- Authentication, authorization, approval policies and audit history.
- Workflow execution, retries and durable checkpoints.
- Operator dashboard for server health, connectors, tools, sessions, workflows, approvals and logs.

## Repository layout

The codebase will be organized around protocol/runtime, platform services, connectors, security, workflows, observability, dashboard and tests. Public Go packages will be kept intentionally small; implementation details stay under `internal/`.

## Development

Requirements:
- Go 1.25 or newer (the selected MCP SDK release requires Go 1.25).
- Git.

Initial commands (as implementation lands):

```bash
go test ./...
go vet ./...
go run ./cmd/universal-mcp
```

## Security

Never commit access tokens, OAuth client secrets, private keys or production credentials. Report vulnerabilities privately through GitHub's security reporting process when enabled.

## Project commitments

- All accepted development commits land directly on `main`, per the repository owner's workflow preference.
- Commits represent meaningful, reviewable work; no artificial history inflation.
- A feature is not called complete until tests and documentation support that claim.
- Production readiness requires protocol, security, compatibility and operational validation.

## License

License selection is pending. Do not assume this project is licensed for redistribution until a license file is added.
