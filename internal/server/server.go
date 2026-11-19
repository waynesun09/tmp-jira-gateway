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

	"github.com/waynesun09/tmp-jira-gateway/internal/apierr"
	"github.com/waynesun09/tmp-jira-gateway/internal/audit"
	"github.com/waynesun09/tmp-jira-gateway/internal/auth"
	"github.com/waynesun09/tmp-jira-gateway/internal/config"
	"github.com/waynesun09/tmp-jira-gateway/internal/policy"
	"github.com/waynesun09/tmp-jira-gateway/internal/preflight"
	"github.com/waynesun09/tmp-jira-gateway/internal/respfilter"
	"github.com/waynesun09/tmp-jira-gateway/internal/upstream"
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
	reasonFilterBusy      = "response filter busy"
	reasonIssueKeyChanged = "returned issue key differs from the requested key"
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
	Filters   *respfilter.Limiter
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

	// Pre-flight every issue key (write routes skip the cache), then the
	// comment if the call edits or deletes one. A refusal looks like any
	// other grant refusal; a transient failure is a 502 and the call is
	// not forwarded either way.
	ids := map[string]string{}
	preflightFailed := func(res preflight.Result, reason string) bool {
		switch res.Outcome {
		case preflight.OK:
			return false
		case preflight.Transient:
			if retryAfterRe.MatchString(res.RetryAfter) {
				w.Header().Set("Retry-After", res.RetryAfter)
			}
			fail(apierr.UpstreamUnavailable, reason+" (transient)")
		case preflight.AuthFailed:
			fail(apierr.UpstreamAuth, reason+" (credential refused)")
		default:
			fail(apierr.NotGranted, reason)
		}
		return true
	}
	for _, key := range dec.IssueKeys {
		res := h.Preflight.Issue(r.Context(), g, key, !dec.Write)
		rec.PreflightCalls += res.Calls
		if preflightFailed(res, reasonPreflightIssue) {
			return
		}
		ids[key] = res.IssueID
	}
	if dec.CommentID != "" {
		res := h.Preflight.Comment(r.Context(), g, dec.CommentIssueKey, ids[dec.CommentIssueKey], dec.CommentID)
		rec.PreflightCalls += res.Calls
		if preflightFailed(res, reasonPreflightComent) {
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
	case res.Status >= 500 || !passThrough(res.Status):
		// Only the documented statuses carry Jira's body back.
		fail(apierr.UpstreamFailed, reasonUpstream)
		return
	}
	if res.Status >= 200 && res.Status < 300 && dec.Strip != policy.StripNone {
		var filtered []byte
		var gotKey string
		err := h.Filters.Do(r.Context(), func() error {
			var err error
			switch dec.Strip {
			case policy.StripIssue:
				filtered, gotKey, err = respfilter.Issue(res.Body)
			case policy.StripSearch:
				filtered, err = respfilter.Search(res.Body)
			case policy.StripChangelog:
				filtered, err = respfilter.Changelog(res.Body)
			}
			return err
		})
		switch {
		case errors.Is(err, respfilter.ErrBusy):
			fail(apierr.GatewayBusy, reasonFilterBusy)
			return
		case err != nil:
			fail(apierr.UpstreamUndecodable, reasonUpstream)
			return
		case dec.Strip == policy.StripIssue && gotKey != dec.IssueKeys[0]:
			// The issue Jira returned is not the one asked for (it moved
			// after the pre-flight, or the cache was stale).
			fail(apierr.NotGranted, reasonIssueKeyChanged)
			return
		}
		res.Body = filtered
	}
	// 2xx and the remaining 4xx (400, 404, 409, 429) pass back with their
	// body: these are Jira's answers to an allowed call.
	rec.Status = res.Status
	writeUpstream(w, res)
}

// passThrough reports whether an upstream status is returned to the
// caller with Jira's body: 2xx, 400, 404, 409 and 429. Every other status
// gets a fixed error body.
func passThrough(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests:
		return true
	}
	return status >= 200 && status < 300
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
