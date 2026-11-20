package security

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"net/http"
	"net/http/httptest"
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

func TestOAuthStateCookieBindsCallbackToInitiatingBrowser(t *testing.T) {
	store, err := NewOAuthTransactionStore(1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	recorder := httptest.NewRecorder()
	SetOAuthStateCookie(recorder, transaction, true, now)
	response := recorder.Result()
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one state cookie, got %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != oauthStateCookieName || !cookie.HttpOnly || !cookie.Secure ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("state cookie has unsafe attributes: %#v", cookie)
	}

	callback := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+transaction.State, nil)
	callback.AddCookie(cookie)
	if err := ValidateOAuthStateCookie(callback, transaction.State); err != nil {
		t.Fatalf("valid initiating browser rejected: %v", err)
	}
	if err := ValidateOAuthStateCookie(callback, transaction.State+"x"); err == nil {
		t.Fatal("callback accepted a different state")
	}
	otherBrowser := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+transaction.State, nil)
	if err := ValidateOAuthStateCookie(otherBrowser, transaction.State); err == nil {
		t.Fatal("callback accepted missing browser-binding cookie")
	}
}

func TestClearOAuthStateCookieExpiresCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	ClearOAuthStateCookie(recorder, true)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != oauthStateCookieName || cookies[0].MaxAge >= 0 || !cookies[0].Secure {
		t.Fatalf("state cookie was not safely expired: %#v", cookies)
	}
}
