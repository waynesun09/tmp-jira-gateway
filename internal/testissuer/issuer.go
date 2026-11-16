// Package testissuer is a local OIDC issuer for tests: it serves discovery
// and a JWKS from an httptest server and signs test JWTs. It never talks
// to GitHub.
package testissuer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Issuer is a running test issuer.
type Issuer struct {
	URL   string
	Key   *rsa.PrivateKey
	KeyID string
	// JWKSHits counts JWKS fetches.
	JWKSHits atomic.Int32
	// JWKSDelay slows every JWKS answer (nanoseconds).
	JWKSDelay atomic.Int64
	server    *httptest.Server

	mu    sync.Mutex
	extra map[string]*rsa.PrivateKey // rotated-in keys by kid
}

// New starts an issuer; it stops when the test ends.
func New(t testing.TB) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &Issuer{Key: key, KeyID: "test-key-1"}
	mux := http.NewServeMux()
	iss.server = httptest.NewServer(mux)
	iss.URL = iss.server.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss.URL,
			"jwks_uri":                              iss.URL + "/.well-known/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, _ *http.Request) {
		iss.JWKSHits.Add(1)
		time.Sleep(time.Duration(iss.JWKSDelay.Load()))
		jwk := func(kid string, pub rsa.PublicKey) map[string]string {
			return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
				"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes())}
		}
		keys := []map[string]string{jwk(iss.KeyID, key.PublicKey)}
		iss.mu.Lock()
		for kid, k := range iss.extra {
			keys = append(keys, jwk(kid, k.PublicKey))
		}
		iss.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	t.Cleanup(iss.server.Close)
	return iss
}

// Rotate publishes a new signing key under kid and returns it, as an
// issuer rotating keys would.
func (i *Issuer) Rotate(t testing.TB, kid string) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.extra == nil {
		i.extra = map[string]*rsa.PrivateKey{}
	}
	i.extra[kid] = k
	return k
}

// Client returns an HTTP client for the issuer's server.
func (i *Issuer) Client() *http.Client { return i.server.Client() }

// Claims returns a valid GitHub-shaped claim set for repository.
func (i *Issuer) Claims(audience, repository, repoID, ownerID string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":                 i.URL,
		"aud":                 audience,
		"sub":                 "repo:" + repository + ":ref:refs/heads/main",
		"iat":                 now.Unix(),
		"nbf":                 now.Add(-5 * time.Second).Unix(),
		"exp":                 now.Add(5 * time.Minute).Unix(),
		"repository":          repository,
		"repository_id":       repoID,
		"repository_owner_id": ownerID,
		"run_id":              "1234567890",
	}
}

// Sign returns an RS256 JWT for claims, signed with the issuer's key.
func (i *Issuer) Sign(t testing.TB, claims map[string]any) string {
	t.Helper()
	return SignWith(t, i.Key, i.KeyID, claims)
}

// SignWith signs claims with an arbitrary key and kid.
func SignWith(t testing.TB, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	head := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	signing := encodeJSON(t, head) + "." + encodeJSON(t, claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

// AlgNone returns an unsigned token (alg "none") carrying claims.
func AlgNone(t testing.TB, claims map[string]any) string {
	t.Helper()
	return encodeJSON(t, map[string]string{"alg": "none", "typ": "JWT"}) + "." + encodeJSON(t, claims) + "."
}

// ReplacePayload keeps a token's header and signature and swaps in
// claims, as an attacker editing a real token would.
func ReplacePayload(t testing.TB, token string, claims map[string]any) string {
	t.Helper()
	parts := strings.Split(token, ".")
	return parts[0] + "." + encodeJSON(t, claims) + "." + parts[2]
}

func encodeJSON(t testing.TB, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b64(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
