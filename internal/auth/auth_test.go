package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
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
