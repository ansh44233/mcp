package security

import (
	"net/http"
	"net/url"
	"strings"
)

// NewSessionMiddleware authenticates requests with an opaque server-side
// session cookie. Unsafe methods additionally require an exact configured
// Origin and a matching X-CSRF-Token header. Configure the public origin
// explicitly; do not derive it from untrusted forwarding headers.
func NewSessionMiddleware(store *SessionStore, allowedOrigin string) (func(http.Handler) http.Handler, error) {
	if store == nil {
		return nil, ErrSessionNotFound
	}
	allowedOrigin = strings.TrimSpace(allowedOrigin)
	parsedOrigin, err := url.Parse(allowedOrigin)
	if err != nil || parsedOrigin == nil || !parsedOrigin.IsAbs() ||
		(parsedOrigin.Scheme != "https" && parsedOrigin.Scheme != "http") ||
		parsedOrigin.Host == "" || parsedOrigin.Hostname() == "" ||
		parsedOrigin.User != nil || parsedOrigin.Path != "" ||
		parsedOrigin.RawPath != "" || parsedOrigin.RawQuery != "" ||
		parsedOrigin.Fragment != "" || parsedOrigin.Opaque != "" ||
		strings.ContainsAny(allowedOrigin, "\r\n") ||
		parsedOrigin.String() != allowedOrigin {
		return nil, http.ErrNotSupported
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName())
			if err != nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			session, err := store.Get(cookie.Value)
			if err != nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			if !isSafeMethod(r.Method) {
				if r.Header.Get("Origin") != allowedOrigin {
					http.Error(w, "request origin rejected", http.StatusForbidden)
					return
				}
				if err := ValidateCSRF(session, r.Header.Get("X-CSRF-Token")); err != nil {
					http.Error(w, "CSRF validation failed", http.StatusForbidden)
					return
				}
			}
			ctx := WithPrincipal(r.Context(), session.Principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
