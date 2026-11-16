// Package auth verifies the caller's CI OIDC token.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	return newVerifier(p.Verifier, audience, skew), nil
}

func newVerifier(mk func(*oidc.Config) *oidc.IDTokenVerifier, audience string, skew time.Duration) *Verifier {
	v := &Verifier{skew: skew, now: time.Now}
	v.v = mk(&oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: []string{oidc.RS256},
		// exp and nbf are checked below with the configured skew; the
		// library's own nbf leeway is five minutes.
		SkipExpiryCheck: true,
	})
	return v
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
		Exp               *json.Number `json:"exp"`
		Nbf               *json.Number `json:"nbf"`
		Repository        any          `json:"repository"`
		RepositoryID      any          `json:"repository_id"`
		RepositoryOwnerID any          `json:"repository_owner_id"`
		RunID             any          `json:"run_id"`
	}
	if err := idt.Claims(&c); err != nil {
		return nil, ErrUnauthorized
	}
	now := v.now()
	if c.Exp == nil {
		return nil, ErrUnauthorized
	}
	exp, err := c.Exp.Int64()
	if err != nil || !now.Before(time.Unix(exp, 0).Add(v.skew)) {
		return nil, ErrUnauthorized
	}
	if c.Nbf != nil {
		nbf, err := c.Nbf.Int64()
		if err != nil || now.Add(v.skew).Before(time.Unix(nbf, 0)) {
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
