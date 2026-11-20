package security

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthTransactionCreatesPKCES256AndConsumesOnce(t *testing.T) {
	store, err := NewOAuthTransactionStore(2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	if !validOpaqueToken(transaction.State, oauthStateBytes) ||
		!validOpaqueToken(transaction.Nonce, oauthNonceBytes) ||
		!validOpaqueToken(transaction.CodeVerifier, pkceVerifierBytes) {
		t.Fatal("OAuth transaction secrets must be independent opaque tokens")
	}
	digest := sha256.Sum256([]byte(transaction.CodeVerifier))
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if transaction.CodeChallenge != want {
		t.Fatal("PKCE challenge is not the S256 digest of the verifier")
	}
	got, err := store.Consume(transaction.State)
	if err != nil {
		t.Fatalf("consume transaction: %v", err)
	}
	if got.Nonce != transaction.Nonce || got.CodeVerifier != transaction.CodeVerifier {
		t.Fatal("consumed transaction did not preserve server-side values")
	}
	if _, err := store.Consume(transaction.State); err == nil {
		t.Fatal("transaction state replay was accepted")
	}
}

func TestOAuthTransactionExpiresAndEnforcesCapacity(t *testing.T) {
	store, err := NewOAuthTransactionStore(1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	store.now = func() time.Time { return now }
	transaction, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(); err == nil {
		t.Fatal("transaction capacity was not enforced")
	}
	now = now.Add(time.Minute)
	if _, err := store.Consume(transaction.State); err == nil {
		t.Fatal("expired transaction was accepted")
	}
	if _, err := store.Create(); err != nil {
		t.Fatalf("expired transaction did not free capacity: %v", err)
	}
}

func TestOAuthTransactionRejectsMalformedState(t *testing.T) {
	store, err := NewOAuthTransactionStore(1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"", "not-a-state", " leading", "a/b"} {
		if _, err := store.Consume(state); err == nil {
			t.Errorf("accepted malformed state %q", state)
		}
	}
}

func TestOAuthTransactionConsumeIsAtomicUnderConcurrency(t *testing.T) {
	store, err := NewOAuthTransactionStore(1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}

	const contenders = 32
	var successes atomic.Int32
	var wg sync.WaitGroup
	wg.Add(contenders)
	for range contenders {
		go func() {
			defer wg.Done()
			if _, err := store.Consume(transaction.State); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("expected exactly one successful state consumption, got %d", got)
	}
}
