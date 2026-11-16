// Package preflight checks, upstream, that an issue key still names an
// issue inside the grant before a call on it is forwarded.
//
// Jira resolves an issue key case-insensitively and follows moves: after
// ABC-5 moves to project OTHER, GET /issue/ABC-5 returns the moved issue
// under its new key, with no redirect. A key prefix check alone would let
// a grant on ABC reach it. The pre-flight asks Jira which issue a key
// names and requires the answer to carry the same key, in a granted
// project.
package preflight

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/config"
	"github.com/nonflux/tmp-jira-gateway/internal/respfilter"
	"github.com/nonflux/tmp-jira-gateway/internal/strictjson"
	"github.com/nonflux/tmp-jira-gateway/internal/upstream"
)

// Timeout bounds one pre-flight call.
const Timeout = 10 * time.Second

// maxEntries bounds the cache; it is cleared when full.
const maxEntries = 10000

// Doer sends a GET upstream; *upstream.Forwarder satisfies it.
type Doer interface {
	Do(ctx context.Context, write bool, method, path, rawQuery string, body []byte) (*upstream.Result, error)
}

// Outcome is a pre-flight's answer.
type Outcome int

const (
	// OK: the key names an issue in a granted project.
	OK Outcome = iota
	// Denied: Jira answered, and the issue is not reachable under the
	// grant (another key came back, 404, 403, a project outside the
	// grant, a malformed answer).
	Denied
	// Transient: Jira did not answer usefully this time (429, 5xx, a
	// redirect, a transport error or a timeout). The call is not
	// forwarded; the caller may retry.
	Transient
	// AuthFailed: Atlassian refused the gateway's own credential.
	AuthFailed
)

// Result is a pre-flight's outcome, with the issue id when OK and Jira's
// Retry-After on a 429.
type Result struct {
	Outcome    Outcome
	IssueID    string
	RetryAfter string
	Calls      int // upstream requests made (0 on a cache hit)
}

// classify maps an upstream error or non-200 status to an outcome.
func classify(res *upstream.Result, err error) Result {
	switch {
	case errors.Is(err, upstream.ErrTokenRejected):
		return Result{Outcome: AuthFailed}
	case err != nil:
		return Result{Outcome: Transient}
	case res.Status == http.StatusUnauthorized:
		return Result{Outcome: AuthFailed}
	case res.Status == http.StatusTooManyRequests:
		return Result{Outcome: Transient, RetryAfter: res.RetryAfter}
	case res.Status >= 500, res.Status >= 300 && res.Status < 400:
		return Result{Outcome: Transient}
	}
	return Result{Outcome: Denied}
}

// Resolver runs pre-flights and caches only successful lookups.
type Resolver struct {
	up  Doer
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	cache map[string]entry // cloudId + "/" + key
}

// entry is the one cached fact: on a cloud, key KEY-n names issue id in
// project. It is not tied to any grant; each use re-checks the grant.
type entry struct {
	id      string
	project string
	expires time.Time
}

// New returns a Resolver; ttl 0 disables the cache.
func New(up Doer, ttl time.Duration) *Resolver {
	return &Resolver{up: up, ttl: ttl, now: time.Now, cache: map[string]entry{}}
}

var (
	numRe     = regexp.MustCompile(`^[0-9]{1,18}$`)
	projectRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	// selfRe finds the issue and comment ids in a comment's self URL.
	selfRe = regexp.MustCompile(`/rest/api/[23]/issue/([0-9]{1,18})/comment/([0-9]{1,18})$`)
)

// Issue checks key against the grant. useCache false (write routes)
// always asks Jira. Nothing but a successful lookup is cached.
func (r *Resolver) Issue(ctx context.Context, g *config.Grant, key string, useCache bool) Result {
	ck := g.CloudID + "/" + key
	if useCache {
		if e, hit := r.get(ck); hit {
			if !g.HasProject(e.project) {
				return Result{Outcome: Denied}
			}
			return Result{Outcome: OK, IssueID: e.id}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	res, err := r.up.Do(ctx, g.CanWrite(), http.MethodGet,
		"/ex/jira/"+g.CloudID+"/rest/api/3/issue/"+key, "fields=project", nil)
	if err != nil || res.Status != http.StatusOK {
		out := classify(res, err)
		out.Calls = 1
		return out
	}
	denied := Result{Outcome: Denied, Calls: 1}
	obj, err := strictjson.ParseObject(res.Body)
	if err != nil {
		return denied
	}
	gotID, _ := obj["id"].(string)
	gotKey, _ := obj["key"].(string)
	fields, _ := obj["fields"].(map[string]any)
	project, _ := fields["project"].(map[string]any)
	projectKey, _ := project["key"].(string)
	if !numRe.MatchString(gotID) || gotKey != key || !projectRe.MatchString(projectKey) || !g.HasProject(projectKey) {
		return denied
	}
	r.put(ck, entry{id: gotID, project: projectKey})
	return Result{Outcome: OK, IssueID: gotID, Calls: 1}
}

// Comment checks that comment commentID belongs to the issue with id
// issueID, by reading it through that issue and comparing the issue id in
// its self URL. It is never cached.
func (r *Resolver) Comment(ctx context.Context, g *config.Grant, key, issueID, commentID string) Result {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	res, err := r.up.Do(ctx, g.CanWrite(), http.MethodGet,
		"/ex/jira/"+g.CloudID+"/rest/api/3/issue/"+key+"/comment/"+commentID, "", nil)
	if err != nil || res.Status != http.StatusOK {
		out := classify(res, err)
		out.Calls = 1
		return out
	}
	denied := Result{Outcome: Denied, Calls: 1}
	// A comment carries its ADF body, which can nest deeply: read it with
	// the response parser, not the strict request one.
	top, err := respfilter.TopStrings(res.Body, "id", "self")
	if err != nil {
		return denied
	}
	gotID, self := top["id"], top["self"]
	m := selfRe.FindStringSubmatch(self)
	if gotID != commentID || m == nil || m[1] != issueID || m[2] != commentID {
		return denied
	}
	return Result{Outcome: OK, IssueID: issueID, Calls: 1}
}

func (r *Resolver) get(k string) (entry, bool) {
	if r.ttl <= 0 {
		return entry{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[k]
	if !ok || !r.now().Before(e.expires) {
		delete(r.cache, k)
		return entry{}, false
	}
	return e, true
}

func (r *Resolver) put(k string, e entry) {
	if r.ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxEntries {
		r.cache = map[string]entry{}
	}
	e.expires = r.now().Add(r.ttl)
	r.cache[k] = e
}
