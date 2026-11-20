package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "__Host-universal_mcp_session"
	sessionIDBytes    = 32
	csrfTokenBytes    = 32
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrInvalidCSRF     = errors.New("invalid CSRF token")
)

// Session contains server-side identity state. OAuth credentials must never be
// added to this type or serialized into browser-visible responses.
type Session struct {
	ID        string
	CSRFToken string
	Principal Principal
	ExpiresAt time.Time
}

// SessionStore is a bounded, process-local session store. Restarting the
// process invalidates sessions; multi-instance deployments need shared storage.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
	max      int
	ttl      time.Duration
	now      func() time.Time
}

// NewSessionStore creates a process-local store with a positive capacity and TTL.
func NewSessionStore(max int, ttl time.Duration) (*SessionStore, error) {
	if max < 1 || ttl <= 0 {
		return nil, errors.New("session capacity and TTL must be positive")
	}
	return &SessionStore{sessions: make(map[string]Session), max: max, ttl: ttl, now: time.Now}, nil
}

// Create generates opaque, independent session and CSRF secrets.
func (s *SessionStore) Create(principal Principal) (Session, error) {
	if s == nil {
		return Session{}, errors.New("session store is required")
	}
	if err := principal.Validate(); err != nil {
		return Session{}, err
	}
	id, err := randomURLToken(sessionIDBytes)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomURLToken(csrfTokenBytes)
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	session := Session{
		ID: id, CSRFToken: csrf, Principal: clonePrincipal(principal),
		ExpiresAt: now.Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	if len(s.sessions) >= s.max {
		return Session{}, errors.New("session capacity reached")
	}
	s.sessions[id] = session
	return cloneSession(session), nil
}

// Get returns a defensive copy of a live session.
func (s *SessionStore) Get(id string) (Session, error) {
	if s == nil || !validOpaqueToken(id, sessionIDBytes) {
		return Session{}, ErrSessionNotFound
	}
	now := s.now()
	s.mu.RLock()
	session, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	if !now.Before(session.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
		return Session{}, ErrSessionExpired
	}
	return cloneSession(session), nil
}

// Delete invalidates a session. It is safe to call repeatedly.
func (s *SessionStore) Delete(id string) {
	if s == nil || id == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// ValidateCSRF compares a submitted token without data-dependent string equality.
func ValidateCSRF(session Session, submitted string) error {
	if submitted == "" || len(submitted) != len(session.CSRFToken) ||
		subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(submitted)) != 1 {
		return ErrInvalidCSRF
	}
	return nil
}

// SetSessionCookie writes the opaque session cookie. Secure must be true for
// HTTPS deployments. Insecure cookies are intended only for loopback development.
func SetSessionCookie(w http.ResponseWriter, session Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: session.ID, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteStrictMode,
		Expires: session.ExpiresAt, MaxAge: max(1, int(time.Until(session.ExpiresAt).Seconds())),
	})
}

// ClearSessionCookie expires the browser's session cookie.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteStrictMode,
		MaxAge: -1, Expires: time.Unix(1, 0),
	})
}

// SessionCookieName exposes the fixed cookie name for middleware and tests.
func SessionCookieName() string { return sessionCookieName }

func randomURLToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validOpaqueToken(value string, size int) bool {
	if strings.TrimSpace(value) != value || value == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == size
}

func (s *SessionStore) expireLocked(now time.Time) {
	for id, session := range s.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

func cloneSession(session Session) Session {
	session.Principal = clonePrincipal(session.Principal)
	return session
}

func clonePrincipal(principal Principal) Principal {
	principal.AllowedTools = cloneSet(principal.AllowedTools)
	principal.AllowedProviders = cloneSet(principal.AllowedProviders)
	principal.AllowedResources = cloneResourceSets(principal.AllowedResources)
	return principal
}
