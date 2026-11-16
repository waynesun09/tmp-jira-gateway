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

// MaxKidWait bounds how long a token with an unknown kid waits for the
// next allowed JWKS fetch, so a real key rotation is not refused just
// because a fetch (perhaps forced by forged kids) happened moments ago.
const MaxKidWait = 5 * time.Second

const maxJWKSBytes = 256 << 10

// keySet is an oidc.KeySet that caches the issuer's JWKS and refetches it
// only for an unknown kid, at most once per minInterval. Concurrent
// misses share one fetch, and no lock is held during the network call.
type keySet struct {
	url         string
	hc          *http.Client
	minInterval time.Duration
	maxWait     time.Duration
	now         func() time.Time
	// sleep waits d or until ctx ends; replaced in tests.
	sleep func(ctx context.Context, d time.Duration) error

	mu       sync.Mutex
	keys     jose.JSONWebKeySet
	fetched  time.Time     // end of the last completed fetch attempt
	inflight chan struct{} // closed when the running fetch ends
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newKeySet(url string, hc *http.Client) *keySet {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &keySet{url: url, hc: hc, minInterval: MinJWKSRefetch, maxWait: MaxKidWait, now: time.Now, sleep: sleepCtx}
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
	// Never wait past the token's own exp (read unverified, only to bound
	// the wait; the verifier checks it properly).
	deadline := k.now().Add(k.maxWait)
	var claims struct {
		Exp json.RawMessage `json:"exp"`
	}
	if json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims) == nil {
		if exp, ok := numericDate(claims.Exp); ok && exp.Before(deadline) {
			deadline = exp
		}
	}
	for _, key := range k.lookup(ctx, kid, deadline) {
		if payload, err := jws.Verify(key); err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("jwks: no key verifies the token")
}

// lookup returns the keys for kid. On a miss it joins a running fetch,
// starts one if the rate limit allows, or waits (until deadline at most)
// for the next allowed fetch. A few rounds are enough: each round either
// finds the key or runs/joins a fetch.
func (k *keySet) lookup(ctx context.Context, kid string, deadline time.Time) []jose.JSONWebKey {
	for round := 0; round < 3; round++ {
		k.mu.Lock()
		if keys := k.keys.Key(kid); len(keys) > 0 {
			k.mu.Unlock()
			return keys
		}
		if ch := k.inflight; ch != nil {
			k.mu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return nil
			}
			continue
		}
		if wait := k.minInterval - k.now().Sub(k.fetched); !k.fetched.IsZero() && wait > 0 {
			k.mu.Unlock()
			if k.now().Add(wait).After(deadline) || k.sleep(ctx, wait) != nil {
				return nil
			}
			continue
		}
		ch := make(chan struct{})
		k.inflight = ch
		k.mu.Unlock()

		// The fetch outlives the caller: a client that disconnects must
		// not cancel it after the window is spent. The window starts
		// when an attempt completes, success or a real failure.
		set, err := k.fetch(context.WithoutCancel(ctx))

		k.mu.Lock()
		k.fetched = k.now()
		if err == nil {
			k.keys = set
		}
		k.inflight = nil
		close(ch)
		k.mu.Unlock()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.keys.Key(kid)
}

// fetch reads the issuer's current key set. It holds no lock.
func (k *keySet) fetch(ctx context.Context) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return set, err
	}
	resp, err := k.hc.Do(req)
	if err != nil {
		return set, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return set, fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || len(data) > maxJWKSBytes {
		return set, errors.New("jwks: unreadable response")
	}
	err = json.Unmarshal(data, &set)
	return set, err
}

// prime fetches the keys once at startup.
func (k *keySet) prime(ctx context.Context) error {
	k.mu.Lock()
	k.fetched = k.now()
	k.mu.Unlock()
	set, err := k.fetch(ctx)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.keys = set
	k.mu.Unlock()
	return nil
}
