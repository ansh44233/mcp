package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestOIDCTokenVerifierValidatesSignatureIssuerAudienceAndExpiry(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{
			PublicKey: privateKey.Public(),
			KeyID:     "universal-mcp-test",
			Algorithm: oidc.RS256,
		}},
	}
	server := httptest.NewServer(issuer)
	defer server.Close()
	issuer.SetIssuer(server.URL)

	verifier, err := NewOIDCTokenVerifier(context.Background(), server.URL, "universal-mcp", server.Client())
	if err != nil {
		t.Fatalf("create OIDC verifier: %v", err)
	}

	now := time.Now()
	valid := signTestOIDCToken(t, privateKey, server.URL, "universal-mcp", "user-123", now.Add(time.Hour), now, "mcp:read repositories:read")
	info, err := verifier(context.Background(), valid, nil)
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	if info.UserID != "user-123" {
		t.Fatalf("unexpected subject: %q", info.UserID)
	}
	if !info.Expiration.After(now) {
		t.Fatalf("expected future expiration, got %v", info.Expiration)
	}
	if len(info.Scopes) != 2 || info.Scopes[0] != "mcp:read" || info.Scopes[1] != "repositories:read" {
		t.Fatalf("unexpected scopes: %#v", info.Scopes)
	}
	if info.Extra["issuer"] != server.URL {
		t.Fatalf("unexpected verified issuer: %#v", info.Extra["issuer"])
	}

	wrongAudience := signTestOIDCToken(t, privateKey, server.URL, "another-client", "user-123", now.Add(time.Hour), now, "")
	if _, err := verifier(context.Background(), wrongAudience, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("wrong audience should be rejected as invalid token, got %v", err)
	}

	expired := signTestOIDCToken(t, privateKey, server.URL, "universal-mcp", "user-123", now.Add(-time.Minute), now.Add(-time.Hour), "")
	if _, err := verifier(context.Background(), expired, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expired token should be rejected as invalid token, got %v", err)
	}

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := signTestOIDCToken(t, otherKey, server.URL, "universal-mcp", "user-123", now.Add(time.Hour), now, "")
	if _, err := verifier(context.Background(), badSignature, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("untrusted signing key should be rejected as invalid token, got %v", err)
	}
}

func TestNewOIDCTokenVerifierRejectsUnsafeConfiguration(t *testing.T) {
	for _, issuer := range []string{
		"http://issuer.example.com",
		"http://localhost.attacker.example",
		"https://user:password@issuer.example.com",
		"https://issuer.example.com?tenant=untrusted",
		"https://issuer.example.com#fragment",
	} {
		t.Run(issuer, func(t *testing.T) {
			if _, err := NewOIDCTokenVerifier(context.Background(), issuer, "audience", nil); err == nil {
				t.Fatalf("expected unsafe issuer %q to be rejected", issuer)
			}
		})
	}
	if _, err := NewOIDCTokenVerifier(context.Background(), "https://issuer.example.com", " ", nil); err == nil {
		t.Fatal("expected empty audience to be rejected")
	}
	if _, err := NewOIDCTokenVerifier(nil, "https://issuer.example.com", "audience", nil); err == nil {
		t.Fatal("expected nil context to be rejected")
	}
}

func signTestOIDCToken(t *testing.T, key *rsa.PrivateKey, issuer, audience, subject string, expiry, issued time.Time, scope string) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{
			"iss":   issuer,
			"aud":   audience,
			"sub":   subject,
			"exp":   expiry.Unix(),
			"iat":   issued.Unix(),
			"scope": scope,
		})
	if err != nil {
		t.Fatal(err)
	}
	_ = strconv.FormatInt(expiry.Unix(), 10)
	return oidctest.SignIDToken(key, "universal-mcp-test", oidc.RS256, string(claims))
}
