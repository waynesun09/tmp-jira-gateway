package preflight

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/config"
	"github.com/nonflux/tmp-jira-gateway/internal/upstream"
)

type stub struct {
	calls  int
	status int
	body   string
	err    error
}

func (s *stub) Do(context.Context, bool, string, string, string, []byte) (*upstream.Result, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &upstream.Result{Status: s.status, Body: []byte(s.body)}, nil
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
		s  stub
		ok bool
	}{
		"same key, granted":   {stub{status: 200, body: `{"id":"10001","key":"ABC-1","fields":{"project":{"key":"ABC"}}}`}, true},
		"moved":               {stub{status: 200, body: `{"id":"10001","key":"OTHER-7","fields":{"project":{"key":"OTHER"}}}`}, false},
		"case-folded key":     {stub{status: 200, body: `{"id":"10001","key":"abc-1","fields":{"project":{"key":"ABC"}}}`}, false},
		"project not granted": {stub{status: 200, body: `{"id":"10001","key":"ABC-1","fields":{"project":{"key":"OTHER"}}}`}, false},
		"no project":          {stub{status: 200, body: `{"id":"10001","key":"ABC-1","fields":{}}`}, false},
		"numeric id missing":  {stub{status: 200, body: `{"key":"ABC-1","fields":{"project":{"key":"ABC"}}}`}, false},
		"duplicate key":       {stub{status: 200, body: `{"id":"1","key":"ABC-1","key":"X-1","fields":{"project":{"key":"ABC"}}}`}, false},
		"404":                 {stub{status: 404, body: `{}`}, false},
		"error":               {stub{err: fmt.Errorf("boom")}, false},
		"timeout":             {stub{err: context.DeadlineExceeded}, false},
	} {
		s := c.s
		_, calls, ok := New(&s, time.Minute).Issue(context.Background(), abc, "ABC-1")
		if ok != c.ok || calls != 1 {
			t.Errorf("%s: ok=%v calls=%d", name, ok, calls)
		}
	}
}

func TestCacheHoldsOnlyTheFact(t *testing.T) {
	abc, def := grants(t)
	s := &stub{status: 200, body: `{"id":"10001","key":"ABC-1","fields":{"project":{"key":"ABC"}}}`}
	r := New(s, time.Minute)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	if _, _, ok := r.Issue(context.Background(), abc, "ABC-1"); !ok {
		t.Fatal("first lookup refused")
	}
	// A hit is re-checked against the caller's grant.
	if _, calls, ok := r.Issue(context.Background(), def, "ABC-1"); ok || calls != 0 {
		t.Fatalf("other grant on a cached key: ok=%v calls=%d", ok, calls)
	}
	if _, calls, ok := r.Issue(context.Background(), abc, "ABC-1"); !ok || calls != 0 {
		t.Fatalf("cache hit: ok=%v calls=%d", ok, calls)
	}
	now = now.Add(61 * time.Second)
	if _, calls, _ := r.Issue(context.Background(), abc, "ABC-1"); calls != 1 {
		t.Fatalf("expired entry reused")
	}
}

func TestRefusalsNotCached(t *testing.T) {
	abc, _ := grants(t)
	s := &stub{err: context.DeadlineExceeded}
	r := New(s, time.Minute)
	r.Issue(context.Background(), abc, "ABC-1")
	s.err, s.status, s.body = nil, 200, `{"id":"10001","key":"OTHER-1","fields":{"project":{"key":"OTHER"}}}`
	r.Issue(context.Background(), abc, "ABC-1")
	s.body = `{"id":"10001","key":"ABC-1","fields":{"project":{"key":"ABC"}}}`
	if _, calls, ok := r.Issue(context.Background(), abc, "ABC-1"); !ok || calls != 1 {
		t.Fatalf("a refusal was cached: ok=%v calls=%d", ok, calls)
	}
	if len(r.cache) != 1 {
		t.Fatalf("cache size %d", len(r.cache))
	}
}

func TestComment(t *testing.T) {
	abc, _ := grants(t)
	for name, c := range map[string]struct {
		body string
		ok   bool
	}{
		"same issue":      {`{"id":"500","self":"https://api.atlassian.com/ex/jira/c1/rest/api/3/issue/10001/comment/500"}`, true},
		"site self URL":   {`{"id":"500","self":"https://x.example/rest/api/2/issue/10001/comment/500"}`, true},
		"other issue":     {`{"id":"500","self":"https://api.atlassian.com/ex/jira/c1/rest/api/3/issue/20000/comment/500"}`, false},
		"id mismatch":     {`{"id":"501","self":"https://api.atlassian.com/ex/jira/c1/rest/api/3/issue/10001/comment/500"}`, false},
		"self id differs": {`{"id":"500","self":"https://api.atlassian.com/ex/jira/c1/rest/api/3/issue/10001/comment/501"}`, false},
		"no self":         {`{"id":"500"}`, false},
		"self suffix":     {`{"id":"500","self":"https://x/rest/api/3/issue/10001/comment/500/x"}`, false},
	} {
		s := &stub{status: 200, body: c.body}
		if ok := New(s, 0).Comment(context.Background(), abc, "ABC-1", "10001", "500"); ok != c.ok {
			t.Errorf("%s: ok=%v", name, ok)
		}
	}
}
