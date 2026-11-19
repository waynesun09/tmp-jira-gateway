package preflight

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/waynesun09/tmp-jira-gateway/internal/config"
	"github.com/waynesun09/tmp-jira-gateway/internal/upstream"
)

type stub struct {
	calls  int
	status int
	body   string
	retry  string
	err    error
}

func (s *stub) Do(context.Context, bool, string, string, string, []byte) (*upstream.Result, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &upstream.Result{Status: s.status, Body: []byte(s.body), RetryAfter: s.retry}, nil
}

func grants(t *testing.T) (abc, def *config.Grant) {
	cfg, err := config.Parse([]byte(`{"audience":"a","read_client_id_file":"/x","read_client_secret_file":"/y","grants":[
	  {"repository":"o/abc","repository_id":"1","repository_owner_id":"9","cloudId":"c1","level":"read","projects":["ABC"]},
	  {"repository":"o/def","repository_id":"2","repository_owner_id":"9","cloudId":"c1","level":"read","projects":["DEF"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Lookup("o/abc"), cfg.Lookup("o/def")
}

func TestIssue(t *testing.T) {
	abc, _ := grants(t)
	for name, c := range map[string]struct {
		s     stub
		want  Outcome
		retry string
	}{
		"same key, granted":   {s: stub{status: 200, body: `{"id":"10001","key":"ABC-1","fields":{"project":{"key":"ABC"}}}`}, want: OK},
		"moved":               {s: stub{status: 200, body: `{"id":"10001","key":"OTHER-7","fields":{"project":{"key":"OTHER"}}}`}, want: Denied},
		"case-folded key":     {s: stub{status: 200, body: `{"id":"10001","key":"abc-1","fields":{"project":{"key":"ABC"}}}`}, want: Denied},
		"project not granted": {s: stub{status: 200, body: `{"id":"10001","key":"ABC-1","fields":{"project":{"key":"OTHER"}}}`}, want: Denied},
		"no project":          {s: stub{status: 200, body: `{"id":"10001","key":"ABC-1","fields":{}}`}, want: Denied},
		"numeric id missing":  {s: stub{status: 200, body: `{"key":"ABC-1","fields":{"project":{"key":"ABC"}}}`}, want: Denied},
		"duplicate key":       {s: stub{status: 200, body: `{"id":"1","key":"ABC-1","key":"X-1","fields":{"project":{"key":"ABC"}}}`}, want: Denied},
		"404":                 {s: stub{status: 404, body: `{}`}, want: Denied},
		"403":                 {s: stub{status: 403, body: `{}`}, want: Denied},
		"400":                 {s: stub{status: 400, body: `{}`}, want: Denied},
		"429":                 {s: stub{status: 429, retry: "7"}, want: Transient, retry: "7"},
		"500":                 {s: stub{status: 500}, want: Transient},
		"503":                 {s: stub{status: 503}, want: Transient},
		"redirect":            {s: stub{status: 302}, want: Transient},
		"401 after refresh":   {s: stub{status: 401}, want: AuthFailed},
		"credential refused":  {s: stub{err: upstream.ErrTokenRejected}, want: AuthFailed},
		"transport error":     {s: stub{err: fmt.Errorf("boom")}, want: Transient},
		"timeout":             {s: stub{err: context.DeadlineExceeded}, want: Transient},
	} {
		s := c.s
		res := New(&s, time.Minute).Issue(context.Background(), abc, "ABC-1", true)
		if res.Outcome != c.want || res.Calls != 1 || res.RetryAfter != c.retry {
			t.Errorf("%s: %+v, want outcome %d retry %q", name, res, c.want, c.retry)
		}
	}
}

func TestCacheHoldsOnlyTheFact(t *testing.T) {
	abc, def := grants(t)
	s := &stub{status: 200, body: `{"id":"10001","key":"ABC-1","fields":{"project":{"key":"ABC"}}}`}
	r := New(s, time.Minute)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	if res := r.Issue(context.Background(), abc, "ABC-1", true); res.Outcome != OK {
		t.Fatal("first lookup refused")
	}
	// A hit is re-checked against the caller's grant.
	if res := r.Issue(context.Background(), def, "ABC-1", true); res.Outcome != Denied || res.Calls != 0 {
		t.Fatalf("other grant on a cached key: %+v", res)
	}
	if res := r.Issue(context.Background(), abc, "ABC-1", true); res.Outcome != OK || res.Calls != 0 {
		t.Fatalf("cache hit: %+v", res)
	}
	// Write routes never use the cache.
	if res := r.Issue(context.Background(), abc, "ABC-1", false); res.Outcome != OK || res.Calls != 1 {
		t.Fatalf("write route used the cache: %+v", res)
	}
	now = now.Add(61 * time.Second)
	if res := r.Issue(context.Background(), abc, "ABC-1", true); res.Calls != 1 {
		t.Fatalf("expired entry reused")
	}
}

func TestRefusalsNotCached(t *testing.T) {
	abc, _ := grants(t)
	s := &stub{err: context.DeadlineExceeded}
	r := New(s, time.Minute)
	r.Issue(context.Background(), abc, "ABC-1", true)
	s.err, s.status, s.body = nil, 200, `{"id":"10001","key":"OTHER-1","fields":{"project":{"key":"OTHER"}}}`
	r.Issue(context.Background(), abc, "ABC-1", true)
	s.status = 429
	r.Issue(context.Background(), abc, "ABC-1", true)
	s.status, s.body = 200, `{"id":"10001","key":"ABC-1","fields":{"project":{"key":"ABC"}}}`
	if res := r.Issue(context.Background(), abc, "ABC-1", true); res.Outcome != OK || res.Calls != 1 {
		t.Fatalf("a refusal was cached: %+v", res)
	}
	if len(r.cache) != 1 {
		t.Fatalf("cache size %d", len(r.cache))
	}
}

func TestComment(t *testing.T) {
	abc, _ := grants(t)
	deepADF := `{"type":"doc","content":` + strings.Repeat(`[{"content":`, 80) + `[]` + strings.Repeat(`}]`, 80) + `}`
	for name, c := range map[string]struct {
		s    stub
		want Outcome
	}{
		"same issue":        {stub{status: 200, body: `{"id":"500","self":"https://api.atlassian.com/ex/jira/c1/rest/api/3/issue/10001/comment/500"}`}, OK},
		"site self URL":     {stub{status: 200, body: `{"id":"500","self":"https://x.example/rest/api/2/issue/10001/comment/500"}`}, OK},
		"deep ADF body":     {stub{status: 200, body: `{"id":"500","body":` + deepADF + `,"self":"https://x/rest/api/3/issue/10001/comment/500"}`}, OK},
		"case-variant keys": {stub{status: 200, body: `{"id":"500","ID":"9","self":"https://x/rest/api/3/issue/10001/comment/500"}`}, OK},
		"other issue":       {stub{status: 200, body: `{"id":"500","self":"https://api.atlassian.com/ex/jira/c1/rest/api/3/issue/20000/comment/500"}`}, Denied},
		"id mismatch":       {stub{status: 200, body: `{"id":"501","self":"https://api.atlassian.com/ex/jira/c1/rest/api/3/issue/10001/comment/500"}`}, Denied},
		"self id differs":   {stub{status: 200, body: `{"id":"500","self":"https://api.atlassian.com/ex/jira/c1/rest/api/3/issue/10001/comment/501"}`}, Denied},
		"no self":           {stub{status: 200, body: `{"id":"500"}`}, Denied},
		"duplicate self":    {stub{status: 200, body: `{"id":"500","self":"https://x/rest/api/3/issue/10001/comment/500","self":"https://x/rest/api/3/issue/20000/comment/500"}`}, Denied},
		"self suffix":       {stub{status: 200, body: `{"id":"500","self":"https://x/rest/api/3/issue/10001/comment/500/x"}`}, Denied},
		"404":               {stub{status: 404}, Denied},
		"503":               {stub{status: 503}, Transient},
		"timeout":           {stub{err: context.DeadlineExceeded}, Transient},
	} {
		s := c.s
		if res := New(&s, 0).Comment(context.Background(), abc, "ABC-1", "10001", "500"); res.Outcome != c.want {
			t.Errorf("%s: %+v, want %d", name, res, c.want)
		}
	}
}
