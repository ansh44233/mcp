package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestDiscoverOIDCAuthorizationEndpoints(t *testing.T) {
	issuer := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
		})
	}))
	defer server.Close()
	issuer = server.URL
	endpoints, err := DiscoverOIDCAuthorizationEndpoints(context.Background(), issuer, server.Client())
	if err != nil {
		t.Fatalf("discover authorization endpoints: %v", err)
	}
	if endpoints.Issuer != issuer || endpoints.AuthorizationEndpoint != issuer+"/authorize" || endpoints.TokenEndpoint != issuer+"/token" {
		t.Fatalf("unexpected endpoints: %#v", endpoints)
	}
}

func TestDiscoverOIDCAuthorizationEndpointsRejectsUntrustedMetadata(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		authorization string
		token         string
	}{
		{name: "authorization host", authorization: "https://attacker.example/authorize", token: "/token"},
		{name: "token host", authorization: "/authorize", token: "https://attacker.example/token"},
		{name: "authorization credentials", authorization: "https://user@issuer.example/authorize", token: "/token"},
		{name: "missing token", authorization: "/authorize", token: ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			issuer := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":                 issuer,
					"authorization_endpoint": testCase.authorization,
					"token_endpoint":         testCase.token,
				})
			}))
			defer server.Close()
			issuer = server.URL
			if _, err := DiscoverOIDCAuthorizationEndpoints(context.Background(), issuer, server.Client()); err == nil {
				t.Fatal("expected untrusted or incomplete endpoint metadata to be rejected")
			}
		})
	}
}

func TestValidateOIDCEndpointRequiresExactIssuerOrigin(t *testing.T) {
	issuer, err := url.Parse("https://issuer.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{
		"https://issuer.example:9443/token",
		"https://attacker.example:8443/token",
		"http://issuer.example:8443/token",
	} {
		if _, err := validateOIDCEndpoint(endpoint, issuer, "token"); err == nil {
			t.Fatalf("expected endpoint %q to be rejected", endpoint)
		}
	}
	if got, err := validateOIDCEndpoint("https://issuer.example:8443/token", issuer, "token"); err != nil || got != "https://issuer.example:8443/token" {
		t.Fatalf("expected exact issuer origin to pass, got %q, %v", got, err)
	}
}
