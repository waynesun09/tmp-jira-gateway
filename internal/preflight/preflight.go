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
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/config"
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

// Issue checks key against the grant and returns the issue id. calls is
// the number of upstream requests made (0 on a cache hit). Any error,
// timeout, unexpected answer or project outside the grant gives ok false;
// nothing about a refusal is cached.
func (r *Resolver) Issue(ctx context.Context, g *config.Grant, key string) (id string, calls int, ok bool) {
	ck := g.CloudID + "/" + key
	if e, hit := r.get(ck); hit {
		return e.id, 0, g.HasProject(e.project)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	res, err := r.up.Do(ctx, g.CanWrite(), http.MethodGet,
		"/ex/jira/"+g.CloudID+"/rest/api/3/issue/"+key, "fields=project", nil)
	if err != nil || res.Status != http.StatusOK {
		return "", 1, false
	}
	obj, err := strictjson.ParseObject(res.Body)
	if err != nil {
		return "", 1, false
	}
	gotID, _ := obj["id"].(string)
	gotKey, _ := obj["key"].(string)
	fields, _ := obj["fields"].(map[string]any)
	project, _ := fields["project"].(map[string]any)
	projectKey, _ := project["key"].(string)
	if !numRe.MatchString(gotID) || gotKey != key || !projectRe.MatchString(projectKey) {
		return "", 1, false
	}
	if !g.HasProject(projectKey) {
		return "", 1, false
	}
	r.put(ck, entry{id: gotID, project: projectKey})
	return gotID, 1, true
}

// Comment checks that comment commentID belongs to the issue with id
// issueID, by reading it through that issue and comparing the issue id in
// its self URL. It is never cached.
func (r *Resolver) Comment(ctx context.Context, g *config.Grant, key, issueID, commentID string) bool {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	res, err := r.up.Do(ctx, g.CanWrite(), http.MethodGet,
		"/ex/jira/"+g.CloudID+"/rest/api/3/issue/"+key+"/comment/"+commentID, "", nil)
	if err != nil || res.Status != http.StatusOK {
		return false
	}
	obj, err := strictjson.ParseObject(res.Body)
	if err != nil {
		return false
	}
	gotID, _ := obj["id"].(string)
	self, _ := obj["self"].(string)
	m := selfRe.FindStringSubmatch(self)
	return gotID == commentID && m != nil && m[1] == issueID && m[2] == commentID
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
