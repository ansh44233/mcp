package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OIDCAuthorizationEndpoints contains issuer-pinned endpoints required by the
// OAuth 2.0 authorization-code flow. It contains no client credentials.
type OIDCAuthorizationEndpoints struct {
	Issuer               string
	AuthorizationEndpoint string
	TokenEndpoint        string
}

// DiscoverOIDCAuthorizationEndpoints loads OIDC discovery metadata and validates
// both browser authorization and back-channel token endpoints before use.
func DiscoverOIDCAuthorizationEndpoints(ctx context.Context, issuer string, client *http.Client) (OIDCAuthorizationEndpoints, error) {
	if ctx == nil {
		return OIDCAuthorizationEndpoints{}, fmt.Errorf("OIDC context is required")
	}
	issuerURL, err := validateOIDCIssuer(issuer)
	if err != nil {
		return OIDCAuthorizationEndpoints{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
	defer cancel()
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	request, err := http.NewRequestWithContext(discoveryCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return OIDCAuthorizationEndpoints{}, fmt.Errorf("create OIDC discovery request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := clientCopy.Do(request)
	if err != nil {
		return OIDCAuthorizationEndpoints{}, fmt.Errorf("discover OIDC authorization endpoints: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return OIDCAuthorizationEndpoints{}, fmt.Errorf("OIDC discovery returned HTTP %d", response.StatusCode)
	}
	body, err := readBounded(response.Body, maxOIDCMetadataBytes)
	if err != nil {
		return OIDCAuthorizationEndpoints{}, fmt.Errorf("read OIDC discovery: %w", err)
	}
	var metadata struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return OIDCAuthorizationEndpoints{}, fmt.Errorf("decode OIDC discovery: %w", err)
	}
	if metadata.Issuer != issuer {
		return OIDCAuthorizationEndpoints{}, fmt.Errorf("OIDC discovery issuer does not match configured issuer")
	}
	authorizationEndpoint, err := validateOIDCEndpoint(metadata.AuthorizationEndpoint, issuerURL, "authorization")
	if err != nil {
		return OIDCAuthorizationEndpoints{}, err
	}
	tokenEndpoint, err := validateOIDCEndpoint(metadata.TokenEndpoint, issuerURL, "token")
	if err != nil {
		return OIDCAuthorizationEndpoints{}, err
	}
	return OIDCAuthorizationEndpoints{
		Issuer: issuer, AuthorizationEndpoint: authorizationEndpoint, TokenEndpoint: tokenEndpoint,
	}, nil
}

func validateOIDCEndpoint(raw string, issuer *url.URL, kind string) (string, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || !endpoint.IsAbs() || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return "", fmt.Errorf("OIDC discovery contains an invalid %s endpoint", kind)
	}
	if endpoint.Scheme != issuer.Scheme || !strings.EqualFold(endpoint.Hostname(), issuer.Hostname()) {
		return "", fmt.Errorf("OIDC %s endpoint must use the issuer scheme and hostname", kind)
	}
	if endpoint.Scheme == "https" || (endpoint.Scheme == "http" && isLoopbackHost(endpoint.Hostname())) {
		return endpoint.String(), nil
	}
	return "", fmt.Errorf("OIDC %s endpoint must use HTTPS except for loopback development", kind)
}
