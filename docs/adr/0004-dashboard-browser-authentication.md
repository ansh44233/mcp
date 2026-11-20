# ADR 0004: Browser authentication for the operator dashboard

- Status: Accepted
- Date: 2026-11-21
- Decision owners: Universal MCP maintainers

## Context

The HTTP runtime can validate bearer tokens for MCP and dashboard API requests through the configured issuer's RFC 7662 introspection endpoint. The React dashboard currently calls its APIs without an Authorization header, so enabling OIDC bearer middleware makes the APIs inaccessible to an ordinary browser session. Storing access tokens in localStorage or sessionStorage would expose reusable credentials to JavaScript and increase the impact of an XSS bug.

The dashboard also displays tenant-scoped audit data and can perform operator actions such as connector health checks and approval decisions. Browser authentication must therefore establish the same trusted server-side principal used by MCP authorization; it must not accept tenant IDs or authorization scopes from browser input.

## Decision

Implement a server-side OAuth 2.0 Authorization Code flow with PKCE (S256) for the dashboard, using the already configured identity provider and its discovered authorization and token endpoints.

The browser will receive only an opaque session cookie and a CSRF token. Access and refresh tokens, if issued, remain server-side and are never returned to frontend JavaScript.

### Login and callback

1. `GET /auth/login` creates cryptographically random state, nonce, and PKCE verifier values; stores a short-lived, single-use authorization transaction; and redirects to the issuer's authorization endpoint.
2. The authorization request uses the configured client ID, exact registered callback URI, `response_type=code`, `code_challenge_method=S256`, and the configured scopes.
3. `GET /auth/callback` validates and consumes state before exchanging the code at the discovered token endpoint. The exchange includes the PKCE verifier and uses confidential-client authentication where configured.
4. The server validates the returned identity using the configured issuer's supported token-validation mechanism, including issuer, audience, subject, expiry, and nonce when an ID token is used. It then resolves the subject through the trusted static grants mapping. No request header or browser field can select a tenant or grant.
5. The server creates a fresh opaque session identifier and rotates away the pre-authentication transaction. The session is stored server-side with bounded lifetime and expiry.

### Session and API protection

- Session cookie: HttpOnly, SameSite=Strict, Path=/, no Domain attribute, Secure on HTTPS deployments. Local HTTP development is restricted to loopback and must use a clearly separate non-Secure development setting.
- No bearer token, refresh token, client secret, or session identifier is placed in localStorage, sessionStorage, URLs, or logs.
- `GET /auth/session` returns only safe display metadata and a CSRF token; it never returns OAuth credentials.
- Every dashboard API request resolves the opaque cookie to a server-side principal and attaches it to the request context.
- State-changing requests require a matching CSRF header and same-origin Origin validation. SameSite cookies are defense in depth, not the only CSRF control.
- Logout is a CSRF-protected POST that revokes the server-side session and expires the cookie.
- Session lookup, state transactions, and token data have strict size and lifetime limits. Session storage is in-memory initially; process restart invalidates all sessions. A shared durable store is required before multi-instance deployment.
- Authentication failures return generic responses. Tokens, authorization codes, PKCE verifiers, and client secrets are never logged.

### Deployment boundaries

- Remote HTTP binding remains disabled until login, callback, session, CSRF, tenant isolation, and security headers are implemented and tested end to end.
- Existing bearer authentication for the MCP `/mcp` endpoint remains independent. The browser session is not accepted as an MCP bearer token.
- The local no-OIDC loopback mode remains explicit and does not imply remote authentication.
- The dashboard must fail closed if OIDC is partially configured or the issuer metadata is inconsistent.

## Security requirements and acceptance tests

- State mismatch, replay, expired transaction, missing code, invalid token, wrong issuer/audience, unprovisioned subject, and invalid nonce are rejected.
- PKCE uses S256 and a cryptographically random verifier.
- Redirect URIs are exact configured values; arbitrary return URLs are not accepted.
- Discovery and token endpoints are HTTPS and pinned to the configured issuer's allowed origin; redirects are not followed for credential-bearing requests.
- Session cookies are HttpOnly and SameSite=Strict; Secure is enabled for HTTPS.
- Missing/invalid session is rejected for all dashboard APIs when browser auth is enabled.
- Missing/invalid CSRF token or cross-origin state-changing request is rejected.
- Logout invalidates the session; expired sessions cannot be reused.
- Tenant-scoped audit and approval APIs use the principal from the server-side session.
- Tests assert that access tokens and client secrets never appear in browser responses, cookies, logs, or error bodies.

## Consequences

The browser no longer needs direct access to OAuth access tokens. The backend owns login, token validation, session lifecycle, and CSRF protection. This adds server-side state and operational complexity; an in-memory session store is suitable only for a single process and must not be described as horizontally scalable or production-ready for multi-instance deployments.
