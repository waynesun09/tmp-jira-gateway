// Package auth verifies the caller's CI OIDC token.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrUnauthorized is returned for every token the gateway does not accept.
// The reason stays internal; callers answer 401 with a fixed message.
var ErrUnauthorized = errors.New("unauthorized")

// maxTokenBytes bounds the bearer token.
const maxTokenBytes = 16 << 10

// Claims are the caller identity claims the gateway uses.
type Claims struct {
	Repository        string
	RepositoryID      string
	RepositoryOwnerID string
	RunID             string
}

// Verifier checks signature (issuer JWKS, RS256 only), issuer, audience,
// exp and nbf.
type Verifier struct {
	v    *oidc.IDTokenVerifier
	keys *keySet
	skew time.Duration
	now  func() time.Time
}

// New discovers the issuer's keys and returns a Verifier. hc, when not
// nil, is used for discovery and JWKS fetches.
func New(ctx context.Context, issuer, audience string, skew time.Duration, hc *http.Client) (*Verifier, error) {
	if hc != nil {
		ctx = oidc.ClientContext(ctx, hc)
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", issuer, err)
	}
	var meta struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := p.Claims(&meta); err != nil || meta.JWKSURL == "" {
		return nil, fmt.Errorf("oidc discovery for %s: no jwks_uri", issuer)
	}
	ks := newKeySet(meta.JWKSURL, hc)
	if err := ks.prime(ctx); err != nil {
		return nil, fmt.Errorf("oidc keys for %s: %w", issuer, err)
	}
	v := &Verifier{keys: ks, skew: skew, now: time.Now}
	v.v = oidc.NewVerifier(issuer, ks, &oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: []string{oidc.RS256},
		// exp and nbf are checked below with the configured skew; the
		// library's own nbf leeway is five minutes.
		SkipExpiryCheck: true,
	})
	return v, nil
}

// numericDateRe is a JWT NumericDate as sent by GitHub: an unquoted
// integer. Quoted strings, fractions and exponents are refused.
var numericDateRe = regexp.MustCompile(`^[0-9]{1,12}$`)

func numericDate(raw json.RawMessage) (time.Time, bool) {
	if !numericDateRe.Match(raw) {
		return time.Time{}, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// BearerToken extracts the token from an Authorization header. Only the
// Authorization header is read.
func BearerToken(r *http.Request) (string, bool) {
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		return "", false
	}
	scheme, tok, ok := strings.Cut(vals[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" || len(tok) > maxTokenBytes || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}

// Verify checks raw and returns its identity claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	idt, err := v.v.Verify(ctx, raw)
	if err != nil {
		return nil, ErrUnauthorized
	}
	var c struct {
		Exp               json.RawMessage `json:"exp"`
		Nbf               json.RawMessage `json:"nbf"`
		Repository        any             `json:"repository"`
		RepositoryID      any             `json:"repository_id"`
		RepositoryOwnerID any             `json:"repository_owner_id"`
		RunID             any             `json:"run_id"`
	}
	if err := idt.Claims(&c); err != nil {
		return nil, ErrUnauthorized
	}
	now := v.now()
	exp, ok := numericDate(c.Exp)
	if !ok || !now.Before(exp.Add(v.skew)) {
		return nil, ErrUnauthorized
	}
	if c.Nbf != nil {
		nbf, ok := numericDate(c.Nbf)
		if !ok || now.Add(v.skew).Before(nbf) {
			return nil, ErrUnauthorized
		}
	}
	// GitHub sends these as strings; anything else is refused.
	repo, ok1 := c.Repository.(string)
	id, ok2 := c.RepositoryID.(string)
	owner, ok3 := c.RepositoryOwnerID.(string)
	if !ok1 || !ok2 || !ok3 || repo == "" || id == "" || owner == "" {
		return nil, ErrUnauthorized
	}
	runID, _ := c.RunID.(string)
	return &Claims{Repository: repo, RepositoryID: id, RepositoryOwnerID: owner, RunID: runID}, nil
}
