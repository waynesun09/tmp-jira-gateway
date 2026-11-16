package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// MinJWKSRefetch is the shortest interval between JWKS fetches. A token
// with an unknown key id triggers a refetch at most this often, so a flood
// of forged kids cannot turn the gateway into a JWKS amplifier.
const MinJWKSRefetch = 30 * time.Second

const maxJWKSBytes = 256 << 10

// keySet is an oidc.KeySet that caches the issuer's JWKS and refetches it
// only for an unknown kid and at most once per minInterval.
type keySet struct {
	url         string
	hc          *http.Client
	minInterval time.Duration
	now         func() time.Time

	mu      sync.Mutex
	keys    jose.JSONWebKeySet
	fetched time.Time // last fetch attempt, successful or not
}

func newKeySet(url string, hc *http.Client) *keySet {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &keySet{url: url, hc: hc, minInterval: MinJWKSRefetch, now: time.Now}
}

// VerifySignature implements oidc.KeySet: RS256 only, a kid is required.
func (k *keySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("jwks: want exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, errors.New("jwks: token has no kid")
	}
	for _, key := range k.lookup(ctx, kid) {
		if payload, err := jws.Verify(key); err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("jwks: no key verifies the token")
}

func (k *keySet) lookup(ctx context.Context, kid string) []jose.JSONWebKey {
	k.mu.Lock()
	defer k.mu.Unlock()
	if keys := k.keys.Key(kid); len(keys) > 0 {
		return keys
	}
	if !k.fetched.IsZero() && k.now().Sub(k.fetched) < k.minInterval {
		return nil
	}
	_ = k.fetchLocked(ctx)
	return k.keys.Key(kid)
}

// fetchLocked replaces the cached keys with the issuer's current set. A
// failed fetch keeps the old keys. k.mu must be held.
func (k *keySet) fetchLocked(ctx context.Context) error {
	k.fetched = k.now()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	resp, err := k.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || len(data) > maxJWKSBytes {
		return errors.New("jwks: unreadable response")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return err
	}
	k.keys = set
	return nil
}

// prime fetches the keys once at startup.
func (k *keySet) prime(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.fetchLocked(ctx)
}
