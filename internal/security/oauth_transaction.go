package security

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var ErrOAuthTransactionNotFound = errors.New("OAuth transaction not found")

const (
	oauthStateBytes   = 32
	oauthNonceBytes   = 32
	pkceVerifierBytes = 32
)

// OAuthTransaction holds short-lived, single-use authorization-flow secrets.
// It must remain server-side and must never be serialized into browser output.
type OAuthTransaction struct {
	State         string
	Nonce         string
	CodeVerifier  string
	CodeChallenge string
	ExpiresAt     time.Time
}

// OAuthTransactionStore is a bounded, process-local store for login transactions.
type OAuthTransactionStore struct {
	mu           sync.Mutex
	transactions map[string]OAuthTransaction
	max          int
	ttl          time.Duration
	now          func() time.Time
}

// NewOAuthTransactionStore creates a bounded store with a positive lifetime.
func NewOAuthTransactionStore(max int, ttl time.Duration) (*OAuthTransactionStore, error) {
	if max < 1 || ttl <= 0 {
		return nil, errors.New("OAuth transaction capacity and TTL must be positive")
	}
	return &OAuthTransactionStore{
		transactions: make(map[string]OAuthTransaction),
		max:          max,
		ttl:          ttl,
		now:          time.Now,
	}, nil
}

// Create creates independent state, nonce, and PKCE secrets.
func (s *OAuthTransactionStore) Create() (OAuthTransaction, error) {
	if s == nil {
		return OAuthTransaction{}, errors.New("OAuth transaction store is required")
	}
	state, err := randomURLToken(oauthStateBytes)
	if err != nil {
		return OAuthTransaction{}, err
	}
	nonce, err := randomURLToken(oauthNonceBytes)
	if err != nil {
		return OAuthTransaction{}, err
	}
	verifier, err := randomURLToken(pkceVerifierBytes)
	if err != nil {
		return OAuthTransaction{}, err
	}
	challengeDigest := sha256.Sum256([]byte(verifier))
	transaction := OAuthTransaction{
		State:         state,
		Nonce:         nonce,
		CodeVerifier:  verifier,
		CodeChallenge: base64.RawURLEncoding.EncodeToString(challengeDigest[:]),
		ExpiresAt:     s.now().Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(s.now())
	if len(s.transactions) >= s.max {
		return OAuthTransaction{}, errors.New("OAuth transaction capacity reached")
	}
	s.transactions[state] = transaction
	return transaction, nil
}

// Consume atomically removes and returns a live transaction. State cannot be replayed.
func (s *OAuthTransactionStore) Consume(state string) (OAuthTransaction, error) {
	if s == nil || !validOpaqueToken(state, oauthStateBytes) {
		return OAuthTransaction{}, ErrOAuthTransactionNotFound
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	transaction, ok := s.transactions[state]
	if !ok {
		return OAuthTransaction{}, ErrOAuthTransactionNotFound
	}
	delete(s.transactions, state)
	if !now.Before(transaction.ExpiresAt) {
		return OAuthTransaction{}, ErrOAuthTransactionNotFound
	}
	return transaction, nil
}

func (s *OAuthTransactionStore) expireLocked(now time.Time) {
	for state, transaction := range s.transactions {
		if !now.Before(transaction.ExpiresAt) {
			delete(s.transactions, state)
		}
	}
}
