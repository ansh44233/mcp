package security

import (
	"context"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// PrincipalResolver maps claims from a successfully verified bearer token to
// platform identity and authorization scopes. It must use trusted identity data
// and server-side tenant membership, not arbitrary request headers.
type PrincipalResolver func(context.Context, *auth.TokenInfo) (Principal, error)

// NewBearerMiddleware composes the SDK's bearer-token verifier with the
// platform principal model. The verifier is responsible for cryptographic token
// validation; the resolver is responsible for mapping verified identity to a
// tenant and least-privilege scopes.
func NewBearerMiddleware(
	verifier auth.TokenVerifier,
	options *auth.RequireBearerTokenOptions,
	resolve PrincipalResolver,
) (func(http.Handler) http.Handler, error) {
	if verifier == nil {
		return nil, fmt.Errorf("bearer token verifier is required")
	}
	if resolve == nil {
		return nil, fmt.Errorf("principal resolver is required")
	}

	requireToken := auth.RequireBearerToken(verifier, options)
	return func(next http.Handler) http.Handler {
		if next == nil {
			panic("next HTTP handler is required")
		}
		return requireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenInfo := auth.TokenInfoFromContext(r.Context())
			if tokenInfo == nil {
				http.Error(w, "verified token information is missing", http.StatusUnauthorized)
				return
			}
			if tokenInfo.UserID == "" {
				http.Error(w, "verified token has no user identity", http.StatusForbidden)
				return
			}
			principal, err := resolve(r.Context(), tokenInfo)
			if err != nil {
				http.Error(w, "unable to resolve authenticated principal", http.StatusForbidden)
				return
			}
			if principal.ID != tokenInfo.UserID {
				http.Error(w, "resolved principal does not match token identity", http.StatusForbidden)
				return
			}
			principal.Authenticated = true
			principal.Authentication = "bearer"
			if err := principal.Validate(); err != nil {
				http.Error(w, "resolved principal is invalid", http.StatusForbidden)
				return
			}
			r = r.WithContext(WithPrincipal(r.Context(), principal))
			next.ServeHTTP(w, r)
		}))
	}, nil
}
