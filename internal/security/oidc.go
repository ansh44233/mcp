package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	maxOIDCTokenBytes     = 16 << 10
	maxOIDCMetadataBytes  = 64 << 10
	maxIntrospectionBytes = 64 << 10
	oidcRequestTimeout    = 5 * time.Second
)

// OIDCIntrospectionConfig configures OAuth 2.0 token introspection discovered
// from a pinned OpenID Connect issuer. Client credentials authenticate this
// server to the introspection endpoint; they are never returned to callers.
type OIDCIntrospectionConfig struct {
	Issuer       string
	Audience     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

// NewOIDCIntrospectionVerifier discovers the pinned issuer's OAuth metadata
// and returns an MCP SDK bearer-token verifier backed by RFC 7662 introspection.
// It requires an active token with matching issuer and audience, a subject and
// a future expiry. Tenant and provider-resource scopes must still be assigned
// by a trusted PrincipalResolver.
//
// The introspection endpoint must be HTTPS and share the issuer's hostname.
// Plain HTTP is accepted only for loopback development and tests.
func NewOIDCIntrospectionVerifier(ctx context.Context, config OIDCIntrospectionConfig) (auth.TokenVerifier, error) {
	if ctx == nil {
		return nil, fmt.Errorf("OIDC context is required")
	}
	if strings.TrimSpace(config.Audience) == "" || strings.TrimSpace(config.ClientID) == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("OIDC audience and introspection client credentials are required")
	}
	issuerURL, err := validateOIDCIssuer(config.Issuer)
	if err != nil {
		return nil, err
	}

	baseClient := config.HTTPClient
	if baseClient == nil {
		baseClient = http.DefaultClient
	}
	// Discovery and introspection endpoints are pinned during initialization.
	// Never follow redirects, especially for requests carrying client credentials.
	clientCopy := *baseClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client := &clientCopy

	discoveryURL := strings.TrimRight(config.Issuer, "/") + "/.well-known/openid-configuration"
	discoveryCtx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
	defer cancel()
	discoveryRequest, err := http.NewRequestWithContext(discoveryCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create OIDC discovery request: %w", err)
	}
	discoveryRequest.Header.Set("Accept", "application/json")
	discoveryResponse, err := client.Do(discoveryRequest)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer: %w", err)
	}
	defer discoveryResponse.Body.Close()
	if discoveryResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned HTTP %d", discoveryResponse.StatusCode)
	}
	discoveryBody, err := readBounded(discoveryResponse.Body, maxOIDCMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read OIDC discovery: %w", err)
	}
	var metadata struct {
		Issuer                string `json:"issuer"`
		IntrospectionEndpoint string `json:"introspection_endpoint"`
	}
	if err := json.Unmarshal(discoveryBody, &metadata); err != nil {
		return nil, fmt.Errorf("decode OIDC discovery: %w", err)
	}
	if metadata.Issuer != config.Issuer {
		return nil, fmt.Errorf("OIDC discovery issuer does not match configured issuer")
	}
	endpoint, err := validateIntrospectionEndpoint(metadata.IntrospectionEndpoint, issuerURL)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
		if len(rawToken) == 0 || len(rawToken) > maxOIDCTokenBytes {
			return nil, auth.ErrInvalidToken
		}
		requestCtx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
		defer cancel()

		form := url.Values{"token": {rawToken}, "token_type_hint": {"access_token"}}
		request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, auth.ErrInvalidToken
		}
		request.SetBasicAuth(config.ClientID, config.ClientSecret)
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		response, err := client.Do(request)
		if err != nil {
			return nil, auth.ErrInvalidToken
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, auth.ErrInvalidToken
		}
		body, err := readBounded(response.Body, maxIntrospectionBytes)
		if err != nil {
			return nil, auth.ErrInvalidToken
		}

		var claims introspectionClaims
		if err := json.Unmarshal(body, &claims); err != nil {
			return nil, auth.ErrInvalidToken
		}
		now := time.Now()
		if !claims.Active || claims.Subject == "" || claims.Issuer != config.Issuer ||
			!claims.Audience.Contains(config.Audience) || claims.Expiry <= now.Unix() {
			return nil, auth.ErrInvalidToken
		}
		if claims.NotBefore != 0 && claims.NotBefore > now.Unix() {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{
			UserID:     claims.Subject,
			Expiration: time.Unix(claims.Expiry, 0),
			Scopes:     strings.Fields(claims.Scope),
			Extra: map[string]any{
				"issuer": claims.Issuer,
			},
		}, nil
	}, nil
}

type introspectionClaims struct {
	Active    bool      `json:"active"`
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  audiences `json:"aud"`
	Expiry    int64     `json:"exp"`
	NotBefore int64     `json:"nbf"`
	Scope     string    `json:"scope"`
}

type audiences []string

func (a *audiences) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return fmt.Errorf("audience must be a string or string array")
	}
	*a = multiple
	return nil
}

func (a audiences) Contains(expected string) bool {
	for _, audience := range a {
		if audience == expected {
			return true
		}
	}
	return false
}

func validateOIDCIssuer(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("OIDC issuer must be an absolute URL without credentials, query or fragment")
	}
	if parsed.Scheme == "https" || (parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return parsed, nil
	}
	return nil, fmt.Errorf("OIDC issuer must use HTTPS except for loopback development")
}

func validateIntrospectionEndpoint(raw string, issuer *url.URL) (string, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || !endpoint.IsAbs() || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return "", fmt.Errorf("OIDC discovery contains an invalid introspection endpoint")
	}
	if endpoint.Scheme != issuer.Scheme || !strings.EqualFold(endpoint.Host, issuer.Host) {
		return "", fmt.Errorf("OIDC introspection endpoint must use the issuer origin")
	}
	if endpoint.Scheme == "https" || (endpoint.Scheme == "http" && isLoopbackHost(endpoint.Hostname())) {
		return endpoint.String(), nil
	}
	return "", fmt.Errorf("OIDC introspection endpoint must use HTTPS except for loopback development")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d-byte limit", limit)
	}
	return body, nil
}
