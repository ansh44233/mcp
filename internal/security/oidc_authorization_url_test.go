package security

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBuildOIDCAuthorizationURLUsesStateNonceAndPKCES256(t *testing.T) {
	store, err := NewOAuthTransactionStore(2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://identity.example"
	got, err := BuildOIDCAuthorizationURL(OIDCAuthorizationEndpoints{
		Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize",
	}, "universal-mcp", "https://app.example/oauth/callback", []string{"openid", "profile"}, transaction)
	if err != nil {
		t.Fatalf("build authorization URL: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	checks := map[string]string{
		"client_id":             "universal-mcp",
		"redirect_uri":          "https://app.example/oauth/callback",
		"response_type":         "code",
		"scope":                 "openid profile",
		"state":                 transaction.State,
		"nonce":                 transaction.Nonce,
		"code_challenge":        transaction.CodeChallenge,
		"code_challenge_method": "S256",
	}
	for key, want := range checks {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if strings.Contains(got, transaction.CodeVerifier) {
		t.Fatal("PKCE verifier must never be sent to the browser authorization endpoint")
	}
}

func TestBuildOIDCAuthorizationURLRejectsUnsafeInputs(t *testing.T) {
	store, err := NewOAuthTransactionStore(2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	endpoints := OIDCAuthorizationEndpoints{
		Issuer: "https://identity.example", AuthorizationEndpoint: "https://identity.example/authorize",
	}
	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		scopes      []string
		transaction OAuthTransaction
		endpoints   OIDCAuthorizationEndpoints
	}{
		{name: "missing openid", clientID: "client", redirectURI: "https://app.example/callback", scopes: []string{"profile"}, transaction: transaction, endpoints: endpoints},
		{name: "insecure redirect", clientID: "client", redirectURI: "http://app.example/callback", scopes: []string{"openid"}, transaction: transaction, endpoints: endpoints},
		{name: "redirect credentials", clientID: "client", redirectURI: "https://user@app.example/callback", scopes: []string{"openid"}, transaction: transaction, endpoints: endpoints},
		{name: "redirect fragment", clientID: "client", redirectURI: "https://app.example/callback#fragment", scopes: []string{"openid"}, transaction: transaction, endpoints: endpoints},
		{name: "empty client", clientID: " ", redirectURI: "https://app.example/callback", scopes: []string{"openid"}, transaction: transaction, endpoints: endpoints},
		{name: "invalid challenge", clientID: "client", redirectURI: "https://app.example/callback", scopes: []string{"openid"}, transaction: OAuthTransaction{State: transaction.State, Nonce: transaction.Nonce, CodeVerifier: transaction.CodeVerifier, CodeChallenge: "wrong"}, endpoints: endpoints},
		{name: "untrusted authorization endpoint", clientID: "client", redirectURI: "https://app.example/callback", scopes: []string{"openid"}, transaction: transaction, endpoints: OIDCAuthorizationEndpoints{Issuer: endpoints.Issuer, AuthorizationEndpoint: "https://attacker.example/authorize"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildOIDCAuthorizationURL(test.endpoints, test.clientID, test.redirectURI, test.scopes, test.transaction); err == nil {
				t.Fatal("expected unsafe authorization request to be rejected")
			}
		})
	}
}
