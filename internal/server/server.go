// Package server is the gateway's HTTP handler: authenticate, match the
// grant, apply the allowlist, pre-flight issue keys, forward, filter.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/apierr"
	"github.com/nonflux/tmp-jira-gateway/internal/audit"
	"github.com/nonflux/tmp-jira-gateway/internal/auth"
	"github.com/nonflux/tmp-jira-gateway/internal/config"
	"github.com/nonflux/tmp-jira-gateway/internal/policy"
	"github.com/nonflux/tmp-jira-gateway/internal/preflight"
	"github.com/nonflux/tmp-jira-gateway/internal/respfilter"
	"github.com/nonflux/tmp-jira-gateway/internal/upstream"
)

// HealthPath answers 200 without authentication and without any call to
// Jira or Atlassian.
const HealthPath = "/healthz"

// Audit reasons for refusals decided outside the policy package.
const (
	reasonUnauthenticated = "unauthenticated"
	reasonNoGrant         = "no grant for caller"
	reasonTooLarge        = "request too large"
	reasonBodyRead        = "request body unreadable"
	reasonPreflightIssue  = "pre-flight: issue not confirmed in grant"
	reasonPreflightComent = "pre-flight: comment not on the issue"
	reasonUpstream        = "upstream"
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
	Preflight *preflight.Resolver
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
	fail := func(e apierr.E, reason string) {
		rec.Status, rec.Code, rec.Reason = e.Status, e.Code, reason
		writeError(w, e)
	}

	raw, ok := auth.BearerToken(r)
	if !ok {
		fail(apierr.Unauthenticated, reasonUnauthenticated)
		return
	}
	claims, err := h.Verifier.Verify(r.Context(), raw)
	if err != nil {
		fail(apierr.Unauthenticated, reasonUnauthenticated)
		return
	}
	rec.Repository, rec.RunID = claims.Repository, safeRunID(claims.RunID)

	g := h.Config.Lookup(claims.Repository)
	if g == nil || g.RepositoryID != claims.RepositoryID || g.RepositoryOwnerID != claims.RepositoryOwnerID {
		fail(apierr.NotGranted, reasonNoGrant)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.Config.MaxRequestBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(apierr.RequestTooLarge, reasonTooLarge)
			return
		}
		fail(apierr.BodyNotAllowed, reasonBodyRead)
		return
	}

	dec, denial := policy.Authorize(g, policy.Request{
		Method: r.Method, RequestURI: r.RequestURI, ContentType: r.Header.Get("Content-Type"), Body: body,
	})
	rec.Template, rec.JQLSHA256 = dec.Template, dec.JQLHash
	if denial != nil {
		fail(denial.Err, denial.Reason)
		return
	}

	// Pre-flight every issue key, then the comment if the call edits or
	// deletes one. Every failure looks like any other grant refusal.
	ids := map[string]string{}
	for _, key := range dec.IssueKeys {
		id, calls, ok := h.Preflight.Issue(r.Context(), g, key)
		rec.PreflightCalls += calls
		if !ok {
			fail(apierr.NotGranted, reasonPreflightIssue)
			return
		}
		ids[key] = id
	}
	if dec.CommentID != "" {
		rec.PreflightCalls++
		if !h.Preflight.Comment(r.Context(), g, dec.CommentIssueKey, ids[dec.CommentIssueKey], dec.CommentID) {
			fail(apierr.NotGranted, reasonPreflightComent)
			return
		}
	}

	var fwdBody []byte
	if len(body) > 0 {
		fwdBody = body
	}
	res, err := h.Forwarder.Do(r.Context(), g.CanWrite(), r.Method, dec.UpstreamPath, dec.RawQuery, fwdBody)
	rec.Decision = "allow"
	if err != nil {
		switch {
		case errors.Is(err, upstream.ErrTokenRejected):
			fail(apierr.UpstreamAuth, reasonUpstream)
		case errors.Is(err, upstream.ErrResponseTooLarge):
			fail(apierr.UpstreamTooLarge, reasonUpstream)
		default:
			fail(apierr.UpstreamUnavailable, reasonUpstream)
		}
		return
	}
	rec.UpstreamStatus = res.Status
	switch {
	case res.Status == http.StatusUnauthorized:
		// Still 401 after a fresh token: the gateway's credential is
		// wrong. Never pass a 401 on: the caller would read it as a
		// refusal of its own token.
		fail(apierr.UpstreamAuth, reasonUpstream)
		return
	case res.Status == http.StatusForbidden:
		fail(apierr.UpstreamRefused, reasonUpstream)
		return
	case res.Status >= 300 && res.Status < 400:
		fail(apierr.UpstreamRedirect, reasonUpstream)
		return
	case res.Status >= 500:
		fail(apierr.UpstreamFailed, reasonUpstream)
		return
	}
	if res.Status >= 200 && res.Status < 300 && dec.Strip != policy.StripNone {
		var filtered []byte
		if dec.Strip == policy.StripIssue {
			filtered, err = respfilter.Issue(res.Body)
		} else {
			filtered, err = respfilter.Search(res.Body)
		}
		if err != nil {
			fail(apierr.UpstreamUndecodable, reasonUpstream)
			return
		}
		res.Body = filtered
	}
	// 2xx and the remaining 4xx (400, 404, 409, 429) pass back with their
	// body: these are Jira's answers to an allowed call.
	rec.Status = res.Status
	writeUpstream(w, res)
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
	hdr.Set("Content-Length", strconv.Itoa(len(res.Body)))
	w.WriteHeader(res.Status)
	_, _ = w.Write(res.Body)
}

func setCommonHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func writeError(w http.ResponseWriter, e apierr.E) {
	writeJSON(w, e.Status, map[string]string{"error": e.Message, "code": e.Code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	setCommonHeaders(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
