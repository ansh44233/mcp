package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const maxOIDCTokenBytes = 16 << 10

// NewOIDCTokenVerifier discovers a pinned OIDC issuer and returns an MCP SDK
// bearer-token verifier. The expected audience is mandatory. The verifier
// validates the token signature, issuer, audience and expiry using the issuer's
// discovery metadata and rotating JWKS. The returned identity is the verified
// subject; tenant and resource scopes must still come from PrincipalResolver.
//
// Plain HTTP issuers are accepted only for loopback hosts to support local
// development and tests. Production issuers must use HTTPS.
func NewOIDCTokenVerifier(
	ctx context.Context,
	issuer string,
	audience string,
	client *http.Client,
) (auth.TokenVerifier, error) {
	if ctx == nil {
		return nil, fmt.Errorf("OIDC context is required")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, fmt.Errorf("OIDC audience is required")
	}
	if err := validateOIDCIssuer(issuer); err != nil {
		return nil, err
	}
	if client != nil {
		ctx = oidc.ClientContext(ctx, client)
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("initialize OIDC provider: %w", err)
	}
	verifier := provider.VerifierContext(ctx, &oidc.Config{ClientID: audience})

	return func(ctx context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
		if len(rawToken) == 0 || len(rawToken) > maxOIDCTokenBytes {
			return nil, auth.ErrInvalidToken
		}
		idToken, err := verifier.Verify(ctx, rawToken)
		if err != nil {
			return nil, auth.ErrInvalidToken
		}
		if idToken.Subject == "" || idToken.Expiry.IsZero() {
			return nil, auth.ErrInvalidToken
		}

		var claims struct {
			Scope string `json:"scope"`
		}
		if err := idToken.Claims(&claims); err != nil {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{
			UserID:     idToken.Subject,
			Expiration: idToken.Expiry,
			Scopes:     strings.Fields(claims.Scope),
			Extra: map[string]any{
				"issuer": idToken.Issuer,
			},
		}, nil
	}, nil
}

func validateOIDCIssuer(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("OIDC issuer must be an absolute URL without credentials, query or fragment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("OIDC issuer must use HTTPS except for loopback development")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
