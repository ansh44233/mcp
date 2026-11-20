package security

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// BuildOIDCAuthorizationURL constructs an Authorization Code + PKCE request
// from issuer-pinned discovery metadata and a server-side transaction.
func BuildOIDCAuthorizationURL(
	endpoints OIDCAuthorizationEndpoints,
	clientID string,
	redirectURI string,
	scopes []string,
	transaction OAuthTransaction,
) (string, error) {
	if strings.TrimSpace(clientID) == "" || clientID != strings.TrimSpace(clientID) {
		return "", fmt.Errorf("OIDC client ID is required")
	}
	if endpoints.Issuer == "" {
		return "", fmt.Errorf("OIDC issuer is required")
	}
	issuer, err := validateOIDCIssuer(endpoints.Issuer)
	if err != nil {
		return "", err
	}
	authorizationEndpoint, err := validateOIDCEndpoint(endpoints.AuthorizationEndpoint, issuer, "authorization")
	if err != nil {
		return "", err
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil || !redirect.IsAbs() || redirect.Host == "" || redirect.User != nil ||
		redirect.Fragment != "" || redirect.Opaque != "" {
		return "", fmt.Errorf("OIDC redirect URI must be an absolute URL without credentials or fragment")
	}
	if redirect.Scheme != "https" && !(redirect.Scheme == "http" && isLoopbackHost(redirect.Hostname())) {
		return "", fmt.Errorf("OIDC redirect URI must use HTTPS except for loopback development")
	}
	if !validOpaqueToken(transaction.State, oauthStateBytes) ||
		!validOpaqueToken(transaction.Nonce, oauthNonceBytes) ||
		!validOpaqueToken(transaction.CodeVerifier, pkceVerifierBytes) {
		return "", fmt.Errorf("valid server-side OAuth transaction is required")
	}
	challengeDigest := sha256Sum([]byte(transaction.CodeVerifier))
	expectedChallenge := base64URL(challengeDigest)
	if transaction.CodeChallenge != expectedChallenge {
		return "", fmt.Errorf("OAuth transaction has an invalid PKCE challenge")
	}
	scopeSet := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "" || scope != strings.TrimSpace(scope) {
			return "", fmt.Errorf("OIDC scopes must be non-empty and trimmed")
		}
		if _, exists := scopeSet[scope]; exists {
			return "", fmt.Errorf("duplicate OIDC scope %q", scope)
		}
		scopeSet[scope] = struct{}{}
	}
	if _, ok := scopeSet["openid"]; !ok {
		return "", fmt.Errorf("OIDC authorization requires the openid scope")
	}

	parsed, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse OIDC authorization endpoint: %w", err)
	}
	query := parsed.Query()
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirect.String())
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", transaction.State)
	query.Set("nonce", transaction.Nonce)
	query.Set("code_challenge", transaction.CodeChallenge)
	query.Set("code_challenge_method", "S256")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// Small wrappers keep the authorization URL builder's cryptographic
// derivation identical to the transaction store's PKCE S256 construction.
func sha256Sum(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func base64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
