package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestOIDCIntrospectionVerifierValidatesTokenAndIdentityClaims(t *testing.T) {
	issuer := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 issuer,
				"introspection_endpoint": issuer + "/introspect",
			})
		case "/introspect":
			user, password, ok := r.BasicAuth()
			if !ok || user != "mcp-client" || password != "test-secret" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("token_type_hint") != "access_token" {
				http.Error(w, "bad token hint", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			claims := map[string]any{
				"active": true,
				"iss":    issuer,
				"sub":    "user-123",
				"aud":    []string{"universal-mcp", "other-api"},
				"exp":    time.Now().Add(time.Hour).Unix(),
				"scope":  "mcp:read repositories:read",
			}
			switch r.Form.Get("token") {
			case "inactive":
				claims["active"] = false
			case "expired":
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			case "wrong-audience":
				claims["aud"] = "other-api"
			case "wrong-issuer":
				claims["iss"] = "https://attacker.example"
			case "not-yet-valid":
				claims["nbf"] = time.Now().Add(time.Minute).Unix()
			}
			_ = json.NewEncoder(w).Encode(claims)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	verifier, err := NewOIDCIntrospectionVerifier(context.Background(), OIDCIntrospectionConfig{
		Issuer:       issuer,
		Audience:     "universal-mcp",
		ClientID:     "mcp-client",
		ClientSecret: "test-secret",
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatalf("create OIDC introspection verifier: %v", err)
	}

	info, err := verifier(context.Background(), "valid-token", nil)
	if err != nil {
		t.Fatalf("verify active token: %v", err)
	}
	if info.UserID != "user-123" {
		t.Fatalf("unexpected subject: %q", info.UserID)
	}
	if !info.Expiration.After(time.Now()) {
		t.Fatalf("expected future expiration, got %v", info.Expiration)
	}
	if len(info.Scopes) != 2 || info.Scopes[0] != "mcp:read" || info.Scopes[1] != "repositories:read" {
		t.Fatalf("unexpected scopes: %#v", info.Scopes)
	}
	if info.Extra["issuer"] != issuer {
		t.Fatalf("unexpected issuer: %#v", info.Extra["issuer"])
	}

	for _, token := range []string{"inactive", "expired", "wrong-audience", "wrong-issuer", "not-yet-valid"} {
		t.Run(token, func(t *testing.T) {
			if _, err := verifier(context.Background(), token, nil); !errorsIsInvalidToken(err) {
				t.Fatalf("expected invalid token error, got %v", err)
			}
		})
	}
	if _, err := verifier(context.Background(), strings.Repeat("x", maxOIDCTokenBytes+1), nil); !errorsIsInvalidToken(err) {
		t.Fatalf("oversized token should be rejected, got %v", err)
	}
}

func TestNewOIDCIntrospectionVerifierRejectsUnsafeConfiguration(t *testing.T) {
	for _, issuer := range []string{
		"http://issuer.example.com",
		"http://localhost.attacker.example",
		"https://user:password@issuer.example.com",
		"https://issuer.example.com?tenant=untrusted",
		"https://issuer.example.com#fragment",
	} {
		t.Run(issuer, func(t *testing.T) {
			_, err := NewOIDCIntrospectionVerifier(context.Background(), OIDCIntrospectionConfig{
				Issuer: issuer, Audience: "audience", ClientID: "client", ClientSecret: "secret",
			})
			if err == nil {
				t.Fatalf("expected unsafe issuer %q to be rejected", issuer)
			}
		})
	}
	for _, config := range []OIDCIntrospectionConfig{
		{Issuer: "https://issuer.example.com", ClientID: "client", ClientSecret: "secret"},
		{Issuer: "https://issuer.example.com", Audience: "audience", ClientSecret: "secret"},
		{Issuer: "https://issuer.example.com", Audience: "audience", ClientID: "client"},
	} {
		if _, err := NewOIDCIntrospectionVerifier(context.Background(), config); err == nil {
			t.Fatal("expected missing required OIDC configuration to be rejected")
		}
	}
	if _, err := NewOIDCIntrospectionVerifier(nil, OIDCIntrospectionConfig{
		Issuer: "https://issuer.example.com", Audience: "audience", ClientID: "client", ClientSecret: "secret",
	}); err == nil {
		t.Fatal("expected nil context to be rejected")
	}
}

func TestOIDCDiscoveryRejectsIssuerAndEndpointMismatch(t *testing.T) {
	for name, discovery := range map[string]map[string]string{
		"issuer mismatch": {
			"issuer": "https://other.example", "introspection_endpoint": "https://issuer.example/introspect",
		},
		"endpoint host mismatch": {
			"issuer": "https://issuer.example", "introspection_endpoint": "https://attacker.example/introspect",
		},
		"endpoint scheme mismatch": {
			"issuer": "https://issuer.example", "introspection_endpoint": "http://issuer.example/introspect",
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(discovery)
			}))
			defer server.Close()
			_, err := NewOIDCIntrospectionVerifier(context.Background(), OIDCIntrospectionConfig{
				Issuer: server.URL, Audience: "audience", ClientID: "client", ClientSecret: "secret", HTTPClient: server.Client(),
			})
			if err == nil {
				t.Fatal("expected discovery mismatch to be rejected")
			}
		})
	}
}

func errorsIsInvalidToken(err error) bool {
	return err == auth.ErrInvalidToken
}

func TestIntrospectionAudienceAcceptsStringAndArray(t *testing.T) {
	for _, raw := range []string{`"api"`, `["api","other"]`} {
		var audience audiences
		if err := json.Unmarshal([]byte(raw), &audience); err != nil {
			t.Fatalf("decode audience %s: %v", raw, err)
		}
		if !audience.Contains("api") {
			t.Fatalf("audience %s should contain api", raw)
		}
	}
	var invalid audiences
	if err := json.Unmarshal([]byte(fmt.Sprintf("%q", url.Values{})), &invalid); err == nil {
		t.Fatal("expected malformed audience to fail")
	}
}
