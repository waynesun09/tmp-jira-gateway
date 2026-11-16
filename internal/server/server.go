// Package server is the gateway's HTTP handler: authenticate, match the
// grant, apply the allowlist, forward.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/audit"
	"github.com/nonflux/tmp-jira-gateway/internal/auth"
	"github.com/nonflux/tmp-jira-gateway/internal/config"
	"github.com/nonflux/tmp-jira-gateway/internal/policy"
	"github.com/nonflux/tmp-jira-gateway/internal/upstream"
)

// HealthPath answers 200 without authentication and without any call to
// Jira or Atlassian.
const HealthPath = "/healthz"

// Fixed error messages returned by the gateway itself.
const (
	msgUnauthorized     = "unauthorized"
	msgNoGrant          = "no grant for caller"
	msgTooLarge         = "request too large"
	msgUpstreamAuth     = "upstream authentication failed"
	msgUpstreamRefused  = "upstream refused the call"
	msgUpstreamError    = "upstream error"
	msgUpstreamRedirect = "upstream redirect"
)

// Verifier checks a bearer token.
type Verifier interface {
	Verify(ctx context.Context, raw string) (*auth.Claims, error)
}

// Handler serves the gateway.
type Handler struct {
	Config    *config.Config
	Verifier  Verifier
	Forwarder *upstream.Forwarder
	Log       *audit.Logger
	Now       func() time.Time
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.RequestURI == HealthPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	start := h.now()
	rec := audit.Request{Method: r.Method, Decision: "deny"}
	defer func() {
		rec.Latency = h.now().Sub(start)
		h.Log.Request(rec)
	}()
	fail := func(status int, msg string) {
		rec.Status, rec.Reason = status, msg
		writeError(w, status, msg)
	}

	raw, ok := auth.BearerToken(r)
	if !ok {
		fail(http.StatusUnauthorized, msgUnauthorized)
		return
	}
	claims, err := h.Verifier.Verify(r.Context(), raw)
	if err != nil {
		fail(http.StatusUnauthorized, msgUnauthorized)
		return
	}
	rec.Repository, rec.RunID = claims.Repository, safeRunID(claims.RunID)

	g := h.Config.Lookup(claims.Repository)
	if g == nil || g.RepositoryID != claims.RepositoryID || g.RepositoryOwnerID != claims.RepositoryOwnerID {
		fail(http.StatusForbidden, msgNoGrant)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.Config.MaxRequestBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(http.StatusRequestEntityTooLarge, msgTooLarge)
			return
		}
		fail(http.StatusBadRequest, policy.ReasonBody)
		return
	}

	dec, denial := policy.Authorize(g, policy.Request{
		Method: r.Method, RequestURI: r.RequestURI, ContentType: r.Header.Get("Content-Type"), Body: body,
	})
	rec.Template, rec.JQLSHA256 = dec.Template, dec.JQLHash
	if denial != nil {
		fail(http.StatusForbidden, denial.Reason)
		return
	}

	var fwdBody []byte
	if len(body) > 0 {
		fwdBody = body
	}
	res, err := h.Forwarder.Do(r.Context(), g.CanWrite(), r.Method, dec.UpstreamPath, dec.RawQuery, fwdBody)
	if err != nil {
		rec.Decision = "allow"
		msg := upstream.ErrTransport.Error()
		if errors.Is(err, upstream.ErrToken) || errors.Is(err, upstream.ErrResponseTooLarge) {
			msg = err.Error()
		}
		fail(http.StatusBadGateway, msg)
		return
	}
	rec.Decision, rec.UpstreamStatus = "allow", res.Status
	switch {
	case res.Status == http.StatusUnauthorized:
		// Still 401 after a fresh token: the gateway's credential is
		// wrong. Never pass a 401 on: the caller would read it as a
		// refusal of its own token.
		fail(http.StatusBadGateway, msgUpstreamAuth)
	case res.Status == http.StatusForbidden:
		fail(http.StatusForbidden, msgUpstreamRefused)
	case res.Status >= 300 && res.Status < 400:
		fail(http.StatusBadGateway, msgUpstreamRedirect)
	case res.Status >= 500:
		fail(res.Status, msgUpstreamError)
	default:
		// 2xx and the remaining 4xx (400, 404, 409, 429) pass back with
		// their body: these are Jira's answers to an allowed call.
		rec.Status = res.Status
		writeUpstream(w, res)
	}
}

var runIDRe = regexp.MustCompile(`^[0-9]{1,20}$`)

func safeRunID(s string) string {
	if runIDRe.MatchString(s) {
		return s
	}
	return ""
}

var retryAfterRe = regexp.MustCompile(`^[0-9]{1,6}$`)

func writeUpstream(w http.ResponseWriter, res *upstream.Result) {
	hdr := w.Header()
	setCommonHeaders(hdr)
	if res.ContentType != "" && len(res.ContentType) < 128 {
		hdr.Set("Content-Type", res.ContentType)
	}
	if retryAfterRe.MatchString(res.RetryAfter) {
		hdr.Set("Retry-After", res.RetryAfter)
	}
	w.WriteHeader(res.Status)
	_, _ = w.Write(res.Body)
}

func setCommonHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	setCommonHeaders(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
