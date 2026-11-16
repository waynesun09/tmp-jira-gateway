package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/testissuer"
)

const aud = "fullsend-jira-gateway-dev"

func newTestVerifier(t *testing.T) (*testissuer.Issuer, *Verifier) {
	t.Helper()
	iss := testissuer.New(t)
	v, err := New(context.Background(), iss.URL, aud, 30*time.Second, iss.Client())
	if err != nil {
		t.Fatal(err)
	}
	return iss, v
}

func TestVerifyValid(t *testing.T) {
	iss, v := newTestVerifier(t)
	c, err := v.Verify(context.Background(), iss.Sign(t, iss.Claims(aud, "org/repo", "11", "22")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Repository != "org/repo" || c.RepositoryID != "11" || c.RepositoryOwnerID != "22" || c.RunID != "1234567890" {
		t.Fatalf("claims = %+v", c)
	}
}

func TestVerifyRejects(t *testing.T) {
	iss, v := newTestVerifier(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base := func() map[string]any { return iss.Claims(aud, "org/repo", "11", "22") }
	with := func(k string, val any) map[string]any {
		c := base()
		if val == nil {
			delete(c, k)
		} else {
			c[k] = val
		}
		return c
	}
	now := time.Now()
	good := iss.Sign(t, base())
	cases := map[string]string{
		"not a JWT":            "not-a-jwt",
		"alg none":             testissuer.AlgNone(t, base()),
		"edited payload":       testissuer.ReplacePayload(t, good, with("repository", "org/other")),
		"other signing key":    testissuer.SignWith(t, otherKey, iss.KeyID, base()),
		"unknown kid":          testissuer.SignWith(t, otherKey, "nope", base()),
		"wrong audience":       iss.Sign(t, with("aud", "some-other-audience")),
		"wrong issuer":         iss.Sign(t, with("iss", "https://token.actions.githubusercontent.com")),
		"expired":              iss.Sign(t, with("exp", now.Add(-31*time.Second).Unix())),
		"missing exp":          iss.Sign(t, with("exp", nil)),
		"nbf in the future":    iss.Sign(t, with("nbf", now.Add(2*time.Minute).Unix())),
		"numeric repo id":      iss.Sign(t, with("repository_id", 11)),
		"missing repository":   iss.Sign(t, with("repository", nil)),
		"missing owner id":     iss.Sign(t, with("repository_owner_id", nil)),
		"HS256 with JWKS data": hs256(t, base()),
	}
	for name, tok := range cases {
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifySkew(t *testing.T) {
	iss, v := newTestVerifier(t)
	c := iss.Claims(aud, "org/repo", "11", "22")
	c["exp"] = time.Now().Add(-10 * time.Second).Unix() // inside the 30 s skew
	if _, err := v.Verify(context.Background(), iss.Sign(t, c)); err != nil {
		t.Fatalf("token 10 s past exp refused with 30 s skew: %v", err)
	}
}

// hs256 forges a token signed with HMAC, as in the classic key-confusion
// attack; the verifier accepts RS256 only.
func hs256(t *testing.T, claims map[string]any) string {
	tok := testissuer.AlgNone(t, claims)
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"test-key-1"}`))
	parts := splitDots(tok)
	signing := head + "." + parts[1]
	m := hmac.New(sha256.New, []byte("public-key-bytes"))
	m.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header map[string][]string
		ok     bool
	}{
		{"bearer", map[string][]string{"Authorization": {"Bearer abc"}}, true},
		{"lowercase scheme", map[string][]string{"Authorization": {"bearer abc"}}, true},
		{"missing", nil, false},
		{"other header", map[string][]string{"X-Authorization": {"Bearer abc"}}, false},
		{"x-api-key", map[string][]string{"X-Api-Key": {"abc"}}, false},
		{"basic", map[string][]string{"Authorization": {"Basic abc"}}, false},
		{"empty token", map[string][]string{"Authorization": {"Bearer "}}, false},
		{"two headers", map[string][]string{"Authorization": {"Bearer a", "Bearer b"}}, false},
		{"space in token", map[string][]string{"Authorization": {"Bearer a b"}}, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		for k, vs := range c.header {
			for _, v := range vs {
				r.Header.Add(k, v)
			}
		}
		if _, ok := BearerToken(r); ok != c.ok {
			t.Errorf("%s: ok = %v, want %v", c.name, ok, c.ok)
		}
	}
}

func TestVerifyStrictDates(t *testing.T) {
	iss, v := newTestVerifier(t)
	exp := time.Now().Add(5 * time.Minute).Unix()
	for name, mod := range map[string]func(map[string]any){
		"quoted exp":     func(c map[string]any) { c["exp"] = fmt.Sprint(exp) },
		"fractional exp": func(c map[string]any) { c["exp"] = float64(exp) + 0.5 },
		"exponent exp":   func(c map[string]any) { c["exp"] = json.Number("1.8e9") },
		"negative exp":   func(c map[string]any) { c["exp"] = -1 },
		"quoted nbf":     func(c map[string]any) { c["nbf"] = fmt.Sprint(time.Now().Unix()) },
		"null nbf":       func(c map[string]any) { c["nbf"] = json.RawMessage("null") },
	} {
		c := iss.Claims(aud, "org/repo", "11", "22")
		mod(c)
		if _, err := v.Verify(context.Background(), iss.Sign(t, c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestJWKSRefetchRateLimited(t *testing.T) {
	iss, v := newTestVerifier(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	v.keys.now = func() time.Time { return now }
	start := iss.JWKSHits.Load() // the startup fetch
	claims := iss.Claims(aud, "org/repo", "11", "22")
	for i := 0; i < 20; i++ {
		tok := testissuer.SignWith(t, other, fmt.Sprintf("unknown-%d", i), claims)
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if got := iss.JWKSHits.Load() - start; got != 0 {
		t.Fatalf("%d refetches inside the first 30 s, want 0", got)
	}
	now = now.Add(MinJWKSRefetch + time.Second)
	for i := 0; i < 20; i++ {
		_, _ = v.Verify(context.Background(), testissuer.SignWith(t, other, fmt.Sprintf("later-%d", i), claims))
	}
	if got := iss.JWKSHits.Load() - start; got != 1 {
		t.Fatalf("%d refetches after the interval, want 1", got)
	}
	// Known keys keep working without a fetch.
	if _, err := v.Verify(context.Background(), iss.Sign(t, claims)); err != nil {
		t.Fatal(err)
	}
	if got := iss.JWKSHits.Load() - start; got != 1 {
		t.Fatalf("known kid caused a fetch")
	}
}

// fakeClock drives the key set's time and makes its sleeps instant.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error { c.Advance(d); return nil }

func withClock(v *Verifier) *fakeClock {
	c := &fakeClock{now: time.Now()}
	v.keys.now, v.keys.sleep, v.now = c.Now, c.Sleep, c.Now
	v.keys.fetched = c.Now()
	return c
}

// TestKeyRotationWaitsForNextFetch: a real rotation shortly before the
// rate-limit window ends is accepted after a short wait, not refused.
func TestKeyRotationWaitsForNextFetch(t *testing.T) {
	iss, v := newTestVerifier(t)
	clock := withClock(v)
	newKey := iss.Rotate(t, "rotated-1")
	clock.Advance(MinJWKSRefetch - 3*time.Second) // 3 s left in the window
	start := iss.JWKSHits.Load()
	claims := iss.Claims(aud, "org/repo", "11", "22")
	claims["exp"] = clock.Now().Add(5 * time.Minute).Unix()
	claims["iat"], claims["nbf"] = clock.Now().Unix(), clock.Now().Unix()
	if _, err := v.Verify(context.Background(), testissuer.SignWith(t, newKey, "rotated-1", claims)); err != nil {
		t.Fatalf("rotated key refused: %v", err)
	}
	if got := iss.JWKSHits.Load() - start; got != 1 {
		t.Fatalf("%d fetches, want 1", got)
	}
}

// TestKidWaitBounded: a wait longer than MaxKidWait, or past the token's
// exp, is refused without a fetch.
func TestKidWaitBounded(t *testing.T) {
	iss, v := newTestVerifier(t)
	clock := withClock(v)
	newKey := iss.Rotate(t, "rotated-2")
	start := iss.JWKSHits.Load()
	claims := iss.Claims(aud, "org/repo", "11", "22")
	claims["exp"] = clock.Now().Add(5 * time.Minute).Unix()
	clock.Advance(10 * time.Second) // 20 s left: more than MaxKidWait
	if _, err := v.Verify(context.Background(), testissuer.SignWith(t, newKey, "rotated-2", claims)); err == nil {
		t.Fatal("accepted without a fetch")
	}
	clock.Advance(MinJWKSRefetch - 10*time.Second - 3*time.Second) // 3 s left
	claims["exp"] = clock.Now().Add(2 * time.Second).Unix()        // but exp in 2 s
	if _, err := v.Verify(context.Background(), testissuer.SignWith(t, newKey, "rotated-2", claims)); err == nil {
		t.Fatal("waited past exp")
	}
	if got := iss.JWKSHits.Load() - start; got != 0 {
		t.Fatalf("%d fetches, want 0", got)
	}
}

// TestUnknownKidsCoalesce: many concurrent unknown kids cause one fetch,
// and a known kid verifies while that fetch is in flight.
func TestUnknownKidsCoalesce(t *testing.T) {
	iss, v := newTestVerifier(t)
	v.keys.fetched = time.Time{}.Add(time.Hour) // window long over
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	iss.JWKSDelay.Store(int64(300 * time.Millisecond))
	start := iss.JWKSHits.Load()
	claims := iss.Claims(aud, "org/repo", "11", "22")
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = v.Verify(context.Background(), testissuer.SignWith(t, other, fmt.Sprintf("fake-%d", i), claims))
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // the fetch is now in flight
	t0 := time.Now()
	if _, err := v.Verify(context.Background(), iss.Sign(t, claims)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 150*time.Millisecond {
		t.Fatalf("known kid waited %v behind the fetch", d)
	}
	wg.Wait()
	if got := iss.JWKSHits.Load() - start; got != 1 {
		t.Fatalf("%d fetches for 30 concurrent unknown kids, want 1", got)
	}
}

// TestCancelledCallerDoesNotBurnWindow: the first caller with a new kid
// disconnects mid-fetch; the fetch still completes, and a second caller
// with that kid succeeds without waiting for another window.
func TestCancelledCallerDoesNotBurnWindow(t *testing.T) {
	iss, v := newTestVerifier(t)
	v.keys.fetched = time.Time{}.Add(time.Hour) // window long over
	newKey := iss.Rotate(t, "rotated-3")
	iss.JWKSDelay.Store(int64(200 * time.Millisecond))
	start := iss.JWKSHits.Load()
	claims := iss.Claims(aud, "org/repo", "11", "22")
	tok := testissuer.SignWith(t, newKey, "rotated-3", claims)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := v.Verify(ctx, tok); done <- err }()
	time.Sleep(50 * time.Millisecond)
	cancel() // the first caller disconnects during the fetch
	<-done
	iss.JWKSDelay.Store(0)

	time.Sleep(250 * time.Millisecond) // the detached fetch finishes
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("second caller refused after a cancelled first caller: %v", err)
	}
	if got := iss.JWKSHits.Load() - start; got != 1 {
		t.Fatalf("%d fetches, want 1", got)
	}
}
