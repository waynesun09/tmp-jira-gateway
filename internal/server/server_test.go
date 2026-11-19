package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waynesun09/tmp-jira-gateway/internal/apierr"
	"github.com/waynesun09/tmp-jira-gateway/internal/audit"
	"github.com/waynesun09/tmp-jira-gateway/internal/auth"
	"github.com/waynesun09/tmp-jira-gateway/internal/config"
	"github.com/waynesun09/tmp-jira-gateway/internal/preflight"
	"github.com/waynesun09/tmp-jira-gateway/internal/respfilter"
	"github.com/waynesun09/tmp-jira-gateway/internal/testissuer"
	"github.com/waynesun09/tmp-jira-gateway/internal/upstream"
)

const (
	aud   = "fullsend-jira-gateway-dev"
	cloud = "11111111-2222-3333-4444-555555555555"
	base  = "/ex/jira/" + cloud + "/rest/api/3"
)

// issue is what the fake Jira returns when a key is looked up.
type issue struct{ id, key, project string }

// atlassian is a fake token endpoint plus Jira API. It answers the
// gateway's pre-flight calls from issues and comments, and every other
// call with status/body, recording it in requests.
type atlassian struct {
	srv           *httptest.Server
	mu            sync.Mutex
	tokens        map[string]int // client_id → token requests
	issues        map[string]issue
	comments      map[string]string // comment id → issue id
	preflights    int
	preflightFail int    // status the pre-flight answers with, when non-zero
	retryAfter    string // Retry-After on that answer
	requests      []*http.Request
	bodies        []string
	status        int
	body          string
	ctype         string
}

var (
	issuePathRe   = regexp.MustCompile(`^/ex/jira/[^/]+/rest/api/3/issue/([^/]+)$`)
	commentPathRe = regexp.MustCompile(`^/ex/jira/[^/]+/rest/api/3/issue/([^/]+)/comment/([0-9]+)$`)
)

func newAtlassian(t *testing.T) *atlassian {
	a := &atlassian{
		tokens: map[string]int{},
		issues: map[string]issue{
			"ABC-1": {"10001", "ABC-1", "ABC"},
			"ABC-2": {"10002", "ABC-2", "ABC"},
			"ABC-9": {"10009", "ABC-9", "ABC"},
			// ABC-5 was moved to OTHER: Jira answers with the new key.
			"ABC-5": {"20012", "OTHER-7", "OTHER"},
		},
		comments: map[string]string{"10001": "10001", "20002": "20000"},
		status:   200, body: `{"accountId":"svc","accountType":"app"}`, ctype: "application/json",
	}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *atlassian) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path == "/oauth/token" {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		a.tokens[b["client_id"]]++
		fmt.Fprintf(w, `{"access_token":"atlassian-token-%s-%d","token_type":"Bearer","expires_in":3600}`, b["client_id"], a.tokens[b["client_id"]])
		return
	}
	if r.Method == "GET" && r.URL.RawQuery == "fields=project" {
		if m := issuePathRe.FindStringSubmatch(r.URL.Path); m != nil {
			a.preflights++
			is, ok := a.issues[m[1]]
			if a.preflightFail != 0 {
				if a.retryAfter != "" {
					w.Header().Set("Retry-After", a.retryAfter)
				}
				w.WriteHeader(a.preflightFail)
				return
			}
			if !ok {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"errorMessages":["Issue does not exist"]}`)
				return
			}
			fmt.Fprintf(w, `{"id":%q,"key":%q,"self":"x","fields":{"project":{"id":"1","key":%q}}}`, is.id, is.key, is.project)
			return
		}
	}
	if m := commentPathRe.FindStringSubmatch(r.URL.Path); r.Method == "GET" && m != nil {
		a.preflights++
		issueID, ok := a.comments[m[2]]
		if !ok {
			w.WriteHeader(404)
			return
		}
		fmt.Fprintf(w, `{"id":%q,"self":"https://api.atlassian.com/ex/jira/%s/rest/api/3/issue/%s/comment/%s","body":{}}`, m[2], cloud, issueID, m[2])
		return
	}
	b, _ := io.ReadAll(r.Body)
	a.requests = append(a.requests, r.Clone(context.Background()))
	a.bodies = append(a.bodies, string(b))
	w.Header().Set("Content-Type", a.ctype)
	w.Header().Set("X-Upstream-Secret-Header", "internal")
	w.WriteHeader(a.status)
	fmt.Fprint(w, a.body)
}

// calls counts every upstream request of any kind.
func (a *atlassian) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.preflights + len(a.requests)
	for _, c := range a.tokens {
		n += c
	}
	return n
}

func (a *atlassian) forwarded() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.requests)
}

type env struct {
	h   *Handler
	iss *testissuer.Issuer
	up  *atlassian
	log *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	iss := testissuer.New(t)
	up := newAtlassian(t)
	d := t.TempDir()
	files := map[string]string{"rid": "read-client-id", "rsec": "read-client-secret-value", "wid": "write-client-id", "wsec": "write-client-secret-value"}
	for name, v := range files {
		if err := os.WriteFile(filepath.Join(d, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfgJSON := fmt.Sprintf(`{
	  "issuer": %q, "audience": %q,
	  "upstream_base_url": %q, "token_url": %q,
	  "read_client_id_file": %q, "read_client_secret_file": %q,
	  "write_client_id_file": %q, "write_client_secret_file": %q,
	  "max_request_bytes": 4096,
	  "grants": [
	    {"repository":"org/ro","repository_id":"100","repository_owner_id":"900","cloudId":%q,"level":"read","projects":["ABC"]},
	    {"repository":"org/rw","repository_id":"200","repository_owner_id":"900","cloudId":%q,"level":"write","projects":["ABC"]}
	  ]}`, iss.URL, aud, up.srv.URL, up.srv.URL+"/oauth/token",
		filepath.Join(d, "rid"), filepath.Join(d, "rsec"), filepath.Join(d, "wid"), filepath.Join(d, "wsec"), cloud, cloud)
	cfg, err := config.Parse([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.New(context.Background(), iss.URL, aud, 30*time.Second, iss.Client())
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	log := audit.New(&logBuf)
	hc := upstream.NewHTTPClient(5 * time.Second)
	read := upstream.NewTokenSource("read", cfg.ReadClientIDFile, cfg.ReadClientSecretFile, cfg.TokenURL, hc, log)
	write := upstream.NewTokenSource("write", cfg.WriteClientIDFile, cfg.WriteClientSecretFile, cfg.TokenURL, hc, log)
	fwd := upstream.NewForwarder(cfg.UpstreamBaseURL, hc, read, write, cfg.MaxResponseBytes)
	h := &Handler{Config: cfg, Verifier: v, Forwarder: fwd, Preflight: preflight.New(fwd, 60*time.Second),
		Filters: respfilter.NewLimiter(2, time.Second), Log: log}
	return &env{h: h, iss: iss, up: up, log: &logBuf}
}

func (e *env) token(t *testing.T, repo string) string {
	switch repo {
	case "org/ro":
		return e.iss.Sign(t, e.iss.Claims(aud, repo, "100", "900"))
	case "org/rw":
		return e.iss.Sign(t, e.iss.Claims(aud, repo, "200", "900"))
	}
	return e.iss.Sign(t, e.iss.Claims(aud, repo, "300", "900"))
}

func (e *env) do(t *testing.T, method, uri, token, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rb io.Reader
	if body != "" {
		rb = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/", rb)
	r.RequestURI = uri // exactly as sent, without client-side cleaning
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// wantError checks a gateway answer: the status, a JSON body that is
// exactly {"error": e.Message, "code": e.Code}, and no upstream text.
func wantError(t *testing.T, name string, w *httptest.ResponseRecorder, e apierr.E) {
	t.Helper()
	if w.Code != e.Status {
		t.Errorf("%s: status %d, want %d (body %s)", name, w.Code, e.Status, w.Body)
		return
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s: content type %q", name, ct)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || len(m) != 2 {
		t.Errorf("%s: body %q is not {\"error\",\"code\"}", name, w.Body)
		return
	}
	if m["error"] != e.Message || m["code"] != e.Code {
		t.Errorf("%s: body %s, want error %q code %q", name, w.Body, e.Message, e.Code)
	}
	for _, s := range []string{"accountId", "errorMessages", "atlassian", "upstream detail", "OTHER", "does not exist"} {
		if strings.Contains(w.Body.String(), s) {
			t.Errorf("%s: body leaks %q", name, s)
		}
	}
}

func TestHealthNeverCallsUpstream(t *testing.T) {
	e := newEnv(t)
	for _, m := range []string{"GET", "HEAD"} {
		w := e.do(t, m, HealthPath, "", "", nil)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d", m, HealthPath, w.Code)
		}
	}
	if n := e.up.calls(); n != 0 {
		t.Fatalf("health check made %d upstream calls", n)
	}
	if w := e.do(t, "GET", HealthPath+"?x=1", "", "", nil); w.Code != 401 {
		t.Fatalf("health with a query should not be the health path: %d", w.Code)
	}
}

func TestUnauthorized(t *testing.T) {
	e := newEnv(t)
	good := e.token(t, "org/ro")
	claims := e.iss.Claims(aud, "org/ro", "100", "900")
	expired := e.iss.Claims(aud, "org/ro", "100", "900")
	expired["exp"] = time.Now().Add(-31 * time.Second).Unix()
	quotedExp := e.iss.Claims(aud, "org/ro", "100", "900")
	quotedExp["exp"] = fmt.Sprint(time.Now().Add(time.Minute).Unix())
	otherAud := e.iss.Claims("another-audience", "org/ro", "100", "900")
	edited := e.iss.Claims(aud, "org/rw", "200", "900")
	cases := []struct {
		name  string
		token string
		hdr   map[string]string
	}{
		{"no Authorization", "", nil},
		{"token in X-Authorization", "", map[string]string{"X-Authorization": "Bearer " + good}},
		{"token in x-api-key", "", map[string]string{"X-Api-Key": good}},
		{"not a JWT", "not-a-jwt", nil},
		{"alg none", testissuer.AlgNone(t, claims), nil},
		{"edited payload", testissuer.ReplacePayload(t, good, edited), nil},
		{"expired", e.iss.Sign(t, expired), nil},
		{"quoted exp", e.iss.Sign(t, quotedExp), nil},
		{"other audience", e.iss.Sign(t, otherAud), nil},
	}
	for _, c := range cases {
		w := e.do(t, "GET", base+"/myself", c.token, "", c.hdr)
		wantError(t, c.name, w, apierr.Unauthenticated)
	}
	if n := e.up.calls(); n != 0 {
		t.Fatalf("%d upstream calls on refused tokens", n)
	}
}

func TestForbidden(t *testing.T) {
	e := newEnv(t)
	ro := e.token(t, "org/ro")
	wrongIDs := e.iss.Sign(t, e.iss.Claims(aud, "org/ro", "100", "901"))
	cases := []struct {
		name, method, uri, token, body string
		want                           apierr.E
	}{
		{"no grant", "GET", base + "/myself", e.token(t, "org/none"), "", apierr.NotGranted},
		{"owner id mismatch", "GET", base + "/myself", wrongIDs, "", apierr.NotGranted},
		{"unknown cloudId", "GET", "/ex/jira/99999999-0000-0000-0000-000000000000/rest/api/3/myself", ro, "", apierr.NotGranted},
		{"foreign issue", "GET", base + "/issue/OTHER-1", ro, "", apierr.NotGranted},
		{"read grant write", "POST", base + "/issue/ABC-1/comment", ro, `{"body":{}}`, apierr.NotGranted},
		{"foreign property key", "GET", base + "/issue/ABC-1/properties/fullsend.poll.org.rw.lock", ro, "", apierr.NotGranted},
		{"lowercase issue key", "GET", base + "/issue/abc-1", ro, "", apierr.EndpointNotAllowed},
		{"numeric issue id", "GET", base + "/issue/10001", ro, "", apierr.EndpointNotAllowed},
		{"api v2", "GET", "/ex/jira/" + cloud + "/rest/api/2/myself", ro, "", apierr.EndpointNotAllowed},
		{"agile", "GET", "/ex/jira/" + cloud + "/rest/agile/1.0/board", ro, "", apierr.EndpointNotAllowed},
		{"dot dot", "GET", base + "/issue/ABC-1/../../issue/OTHER-1", ro, "", apierr.EndpointNotAllowed},
		{"%2F", "GET", base + "/issue/ABC-1%2F..%2F..%2Fmyself", ro, "", apierr.EndpointNotAllowed},
		{"%2f", "GET", base + "/issue/ABC-1%2f..%2f..%2fmyself", ro, "", apierr.EndpointNotAllowed},
		{"double slash", "GET", base + "//myself", ro, "", apierr.EndpointNotAllowed},
		{"comment property", "GET", base + "/comment/1/properties/k", ro, "", apierr.EndpointNotAllowed},
		{"jql in query string", "POST", base + "/search/jql?jql=project", ro, `{"jql":"project = ABC"}`, apierr.QueryNotAllowed},
		{"user groups without accountId", "GET", base + "/user/groups", ro, "", apierr.QueryNotAllowed},
		{"jql twice", "POST", base + "/search/jql", ro, `{"jql":"project = ABC","jql":"project = OTHER"}`, apierr.BodyNotAllowed},
		{"jql grammar", "POST", base + "/search/jql", ro, `{"jql":"project = ABC OR project = OTHER"}`, apierr.JQLGrammar},
	}
	for _, c := range cases {
		w := e.do(t, c.method, c.uri, c.token, c.body, nil)
		wantError(t, c.name, w, c.want)
	}
	if n := e.up.calls(); n != 0 {
		t.Fatalf("%d upstream calls on denied requests", n)
	}
}

func TestJQLRefusalBody(t *testing.T) {
	e := newEnv(t)
	marker := "SECRETMARKER"
	q := `project = ABC OR labels = ` + marker
	body, _ := json.Marshal(map[string]any{"jql": q, "maxResults": 50})
	w := e.do(t, "POST", base+"/search/jql", e.token(t, "org/ro"), string(body), nil)
	if w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
	if got := w.Body.String(); got != `{"code":"jql_grammar","error":"jql outside the accepted grammar"}` {
		t.Fatalf("body %q", got)
	}
	if strings.Contains(w.Body.String(), marker) || strings.Contains(e.log.String(), marker) {
		t.Fatal("query text echoed or logged")
	}
}

func TestAllowedForwarding(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/ro")
	w := e.do(t, "GET", base+"/myself", tok, "", map[string]string{
		"Connection": "keep-alive, X-Foo", "X-Foo": "bar", "Proxy-Authorization": "Basic x",
		"Cookie": "a=b", "X-Forwarded-For": "1.2.3.4", "Te": "trailers", "Upgrade": "h2c",
	})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"accountType":"app"`) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if w.Header().Get("X-Upstream-Secret-Header") != "" {
		t.Fatal("upstream header passed back")
	}
	r := e.up.requests[0]
	if got := r.Header.Get("Authorization"); got != "Bearer atlassian-token-read-client-id-1" {
		t.Fatalf("upstream Authorization = %q", got)
	}
	if strings.Contains(fmt.Sprint(r.Header), tok) {
		t.Fatal("caller's token forwarded")
	}
	for _, h := range []string{"Connection", "X-Foo", "Proxy-Authorization", "Cookie", "X-Forwarded-For", "Te", "Upgrade"} {
		if r.Header.Get(h) != "" {
			t.Errorf("header %s forwarded", h)
		}
	}
	if r.URL.Path != base+"/myself" {
		t.Fatalf("upstream path %q", r.URL.Path)
	}
}

// TestGrantLevelPicksClient checks the upstream Authorization: a read
// grant uses the read OAuth client, a write grant the write client, for
// pre-flights and forwarded calls alike.
func TestGrantLevelPicksClient(t *testing.T) {
	e := newEnv(t)
	e.do(t, "GET", base+"/issue/ABC-1/comment", e.token(t, "org/ro"), "", nil)
	e.do(t, "GET", base+"/issue/ABC-2/comment", e.token(t, "org/rw"), "", nil)
	if len(e.up.requests) != 2 {
		t.Fatalf("forwarded %d", len(e.up.requests))
	}
	if got := e.up.requests[0].Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer atlassian-token-read-client-id-") {
		t.Errorf("read grant used %q", got)
	}
	if got := e.up.requests[1].Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer atlassian-token-write-client-id-") {
		t.Errorf("write grant used %q", got)
	}
	if e.up.tokens["read-client-id"] != 1 || e.up.tokens["write-client-id"] != 1 {
		t.Errorf("token requests %v", e.up.tokens)
	}
}

func TestFullsendDefaultQueriesForwardedUnchanged(t *testing.T) {
	e := newEnv(t)
	e.up.body = `{"issues":[],"isLast":true}`
	for _, q := range []string{
		`project = "ABC" AND statusCategory != Done ORDER BY updated DESC`,
		`project = "ABC" AND (statusCategory != Done) ORDER BY updated DESC`,
	} {
		body := `{"jql":` + mustJSON(q) + `,"maxResults":50,"fields":["summary","status","labels","reporter","assignee","created","updated","project","issuetype"]}`
		w := e.do(t, "POST", base+"/search/jql", e.token(t, "org/ro"), body, nil)
		if w.Code != 200 {
			t.Fatalf("%q: status %d %s", q, w.Code, w.Body)
		}
		if got := e.up.bodies[len(e.up.bodies)-1]; got != body {
			t.Fatalf("body rewritten: %q", got)
		}
	}
}

func TestUserGroups(t *testing.T) {
	e := newEnv(t)
	e.up.body = `[{"name":"g","groupId":"1"}]`
	w := e.do(t, "GET", base+"/user/groups?accountId=557058%3A0b6d5c34-1f2e-4a5b-8c9d-0e1f2a3b4c5d", e.token(t, "org/ro"), "", nil)
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if got := e.up.requests[0].URL.RawQuery; got != "accountId=557058%3A0b6d5c34-1f2e-4a5b-8c9d-0e1f2a3b4c5d" {
		t.Fatalf("forwarded query %q", got)
	}
	wantError(t, "double-encoded", e.do(t, "GET", base+"/user/groups?accountId=557058%253A0b6d5c34-1f2e-4a5b-8c9d-0e1f2a3b4c5d", e.token(t, "org/ro"), "", nil), apierr.QueryNotAllowed)
	wantError(t, "repeated", e.do(t, "GET", base+"/user/groups?accountId=5b10ac8d82e05b22cc7d4ef5&accountId=5b10ac8d82e05b22cc7d4ef5", e.token(t, "org/ro"), "", nil), apierr.QueryNotAllowed)
}

// TestMovedIssueOldKeyIsConfined: ABC-5 was moved to OTHER, and Jira
// resolves the old key to the moved issue. No call on it is forwarded,
// and the refusal is the same as any grant refusal.
func TestMovedIssueOldKeyIsConfined(t *testing.T) {
	e := newEnv(t)
	cases := []struct{ method, uri, token, body string }{
		{"GET", base + "/issue/ABC-5", e.token(t, "org/ro"), ""},
		{"GET", base + "/issue/ABC-5/comment", e.token(t, "org/ro"), ""},
		{"GET", base + "/issue/ABC-5/changelog", e.token(t, "org/ro"), ""},
		{"POST", base + "/issue/ABC-5/comment", e.token(t, "org/rw"), `{"body":{"type":"doc","version":1,"content":[]}}`},
		{"PUT", base + "/issue/ABC-5", e.token(t, "org/rw"), `{"update":{"labels":[{"add":"x"}]}}`},
		{"POST", base + "/issue/ABC-5/transitions", e.token(t, "org/rw"), `{"transition":{"id":"31"}}`},
		{"DELETE", base + "/issue/ABC-5/properties/fullsend.poll.org.rw.lock", e.token(t, "org/rw"), ""},
		{"POST", base + "/issueLink", e.token(t, "org/rw"), `{"type":{"name":"Blocks"},"inwardIssue":{"key":"ABC-1"},"outwardIssue":{"key":"ABC-5"}}`},
		{"POST", base + "/issue", e.token(t, "org/rw"), `{"fields":{"project":{"key":"ABC"},"issuetype":{"name":"Sub-task"},"summary":"s","parent":{"key":"ABC-5"}}}`},
		{"GET", base + "/issue/ABC-404", e.token(t, "org/ro"), ""}, // unknown key: same answer
	}
	for _, c := range cases {
		wantError(t, c.method+" "+c.uri, e.do(t, c.method, c.uri, c.token, c.body, nil), apierr.NotGranted)
	}
	if n := e.up.forwarded(); n != 0 {
		t.Fatalf("%d calls forwarded for a moved issue", n)
	}
}

func TestPreflightTransientFailures(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/ro")
	for _, st := range []int{500, 502, 503, 504} {
		e.up.preflightFail = st
		wantError(t, fmt.Sprint("pre-flight ", st), e.do(t, "GET", base+"/issue/ABC-1", tok, "", nil), apierr.UpstreamUnavailable)
	}
	e.up.preflightFail, e.up.retryAfter = 429, "17"
	w := e.do(t, "GET", base+"/issue/ABC-1", tok, "", nil)
	wantError(t, "pre-flight 429", w, apierr.UpstreamUnavailable)
	if got := w.Header().Get("Retry-After"); got != "17" {
		t.Fatalf("Retry-After %q", got)
	}
	e.up.retryAfter = "soon<script>"
	if w := e.do(t, "GET", base+"/issue/ABC-1", tok, "", nil); w.Header().Get("Retry-After") != "" {
		t.Fatal("malformed Retry-After passed")
	}
	// A pre-flight 401 (after the token refresh) is the gateway's credential.
	e.up.preflightFail, e.up.retryAfter = 401, ""
	wantError(t, "pre-flight 401", e.do(t, "GET", base+"/issue/ABC-1", tok, "", nil), apierr.UpstreamAuth)
	// 404 and 403 are answers: not granted.
	for _, st := range []int{404, 403, 400} {
		e.up.preflightFail = st
		wantError(t, fmt.Sprint("pre-flight ", st), e.do(t, "GET", base+"/issue/ABC-1", tok, "", nil), apierr.NotGranted)
	}
	if e.up.forwarded() != 0 {
		t.Fatal("forwarded after a failed pre-flight")
	}
	// A failure is not cached: once Jira answers, the call goes through.
	e.up.preflightFail = 0
	e.up.body = `{"id":"10001","key":"ABC-1","fields":{}}`
	if w := e.do(t, "GET", base+"/issue/ABC-1", e.token(t, "org/ro"), "", nil); w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
}

func TestPreflightCacheAndCount(t *testing.T) {
	e := newEnv(t)
	e.up.body = `{"id":"10001","key":"ABC-1","fields":{}}`
	tok := e.token(t, "org/ro")
	for i := 0; i < 3; i++ {
		if w := e.do(t, "GET", base+"/issue/ABC-1", tok, "", nil); w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
	}
	if e.up.preflights != 1 {
		t.Fatalf("pre-flights = %d, want 1 (cached)", e.up.preflights)
	}
	var counts []float64
	for _, l := range strings.Split(strings.TrimSpace(e.log.String()), "\n") {
		var m map[string]any
		_ = json.Unmarshal([]byte(l), &m)
		if m["message"] == "request" {
			counts = append(counts, m["preflight_calls"].(float64))
		}
	}
	if fmt.Sprint(counts) != "[1 0 0]" {
		t.Fatalf("preflight_calls = %v", counts)
	}
}

func TestPreflightCacheDisabled(t *testing.T) {
	e := newEnv(t)
	e.h.Preflight = preflight.New(e.h.Forwarder, 0)
	e.up.body = `{"id":"10001","key":"ABC-1","fields":{}}`
	for i := 0; i < 3; i++ {
		e.do(t, "GET", base+"/issue/ABC-1", e.token(t, "org/ro"), "", nil)
	}
	if e.up.preflights != 3 {
		t.Fatalf("pre-flights = %d, want 3", e.up.preflights)
	}
}

// TestCommentIDMustBelongToPathIssue: comment 20002 lives on issue 20000
// (in OTHER); editing or deleting it through ABC-1 is refused.
func TestCommentIDMustBelongToPathIssue(t *testing.T) {
	e := newEnv(t)
	rw := e.token(t, "org/rw")
	body := `{"body":{"type":"doc","version":1,"content":[]}}`
	wantError(t, "delete foreign comment", e.do(t, "DELETE", base+"/issue/ABC-1/comment/20002", rw, "", nil), apierr.NotGranted)
	wantError(t, "edit foreign comment", e.do(t, "PUT", base+"/issue/ABC-1/comment/20002", rw, body, nil), apierr.NotGranted)
	wantError(t, "unknown comment", e.do(t, "PUT", base+"/issue/ABC-1/comment/30003", rw, body, nil), apierr.NotGranted)
	if n := e.up.forwarded(); n != 0 {
		t.Fatalf("%d writes forwarded", n)
	}
	e.up.status, e.up.body = 204, ""
	if w := e.do(t, "DELETE", base+"/issue/ABC-1/comment/10001", rw, "", nil); w.Code != 204 {
		t.Fatalf("own comment: %d %s", w.Code, w.Body)
	}
	if r := e.up.requests[0]; r.Method != "DELETE" || r.URL.Path != base+"/issue/ABC-1/comment/10001" {
		t.Fatalf("forwarded %s %s", r.Method, r.URL.Path)
	}
}

func TestEditCommentWriteGrant(t *testing.T) {
	e := newEnv(t)
	rw := e.token(t, "org/rw")
	ok := `{"body":{"type":"doc","version":1,"content":[]},"properties":[{"key":"fullsend.agent-status","value":{"s":1}}]}`
	if w := e.do(t, "PUT", base+"/issue/ABC-1/comment/10001", rw, ok, nil); w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	for name, c := range map[string]struct {
		uri, token, body string
		want             apierr.E
	}{
		"extra top-level key":  {base + "/issue/ABC-1/comment/10001", rw, `{"body":{},"visibility":{}}`, apierr.BodyNotAllowed},
		"duplicate properties": {base + "/issue/ABC-1/comment/10001", rw, `{"properties":[],"properties":[]}`, apierr.BodyNotAllowed},
		"read grant":           {base + "/issue/ABC-1/comment/10001", e.token(t, "org/ro"), ok, apierr.NotGranted},
		"foreign project":      {base + "/issue/OTHER-1/comment/10001", rw, ok, apierr.NotGranted},
		"non-numeric id":       {base + "/issue/ABC-1/comment/x1", rw, ok, apierr.EndpointNotAllowed},
	} {
		wantError(t, name, e.do(t, "PUT", c.uri, c.token, c.body, nil), c.want)
	}
}

func TestResponseStrip(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/ro")
	e.up.body = `{"id":"10001","key":"ABC-1","fields":{"summary":"s <b>&","parent":{"key":"OTHER-1"},"subtasks":[{"key":"OTHER-2"}],"issuelinks":[{"outwardIssue":{"key":"OTHER-3"}}],"customfield_1":12345678901234567890},"renderedFields":{"parent":"OTHER-1","summary":"s"}}`
	w := e.do(t, "GET", base+"/issue/ABC-1", tok, "", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "OTHER") {
		t.Fatalf("issue: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"summary":"s <b>&"`) || !strings.Contains(w.Body.String(), "12345678901234567890") {
		t.Fatalf("issue fields altered: %s", w.Body)
	}
	if w.Header().Get("Content-Length") != fmt.Sprint(w.Body.Len()) {
		t.Fatalf("Content-Length %q for %d bytes", w.Header().Get("Content-Length"), w.Body.Len())
	}

	e.up.body = `{"issues":[{"key":"ABC-1","fields":{"parent":{"key":"OTHER-1"},"status":{"name":"Open"}}},{"key":"ABC-2","fields":{"issuelinks":[{"inwardIssue":{"key":"OTHER-9"}}]}}],"nextPageToken":"t","isLast":false}`
	w = e.do(t, "POST", base+"/search/jql", tok, `{"jql":"project = ABC","fields":["*all"],"nextPageToken":"t"}`, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "OTHER") || !strings.Contains(w.Body.String(), `"nextPageToken":"t"`) {
		t.Fatalf("search: %d %s", w.Code, w.Body)
	}

	// Not decodable: fail closed with a fixed error.
	for _, bad := range []string{`not json`, `{"issues":{}}`, `{"issues":[1]}`, `{"fields":{"a":1,"a":2}}`, `[]`} {
		e.up.body = bad
		uri, body := base+"/search/jql", `{"jql":"project = ABC"}`
		if !strings.Contains(bad, "issues") && bad != "not json" {
			uri, body = base+"/issue/ABC-1", ""
		}
		method := "POST"
		if body == "" {
			method = "GET"
		}
		wantError(t, "undecodable "+bad, e.do(t, method, uri, tok, body, nil), apierr.UpstreamUndecodable)
	}

	// Error bodies and other routes pass unchanged.
	e.up.status, e.up.body = 404, `{"errorMessages":["Issue does not exist"]}`
	if w := e.do(t, "GET", base+"/issue/ABC-1", tok, "", nil); w.Code != 404 || !strings.Contains(w.Body.String(), "does not exist") {
		t.Fatalf("404: %d %s", w.Code, w.Body)
	}
}

func TestUpstreamAnswers(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/ro")
	// A Jira 404 to an allowed call passes back with its body.
	e.up.status, e.up.body = 404, `{"errorMessages":["Comment page missing"]}`
	w := e.do(t, "GET", base+"/issue/ABC-9/comment", tok, "", nil)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "Comment page missing") {
		t.Fatalf("404: %d %s", w.Code, w.Body)
	}
	for _, c := range []struct {
		up   int
		want apierr.E
	}{
		{403, apierr.UpstreamRefused}, {500, apierr.UpstreamFailed}, {503, apierr.UpstreamFailed},
		{401, apierr.UpstreamAuth}, {302, apierr.UpstreamRedirect},
	} {
		e.up.status, e.up.body = c.up, `{"errorMessages":["atlassian upstream detail"]}`
		wantError(t, fmt.Sprint("upstream ", c.up), e.do(t, "GET", base+"/myself", tok, "", nil), c.want)
	}
}

func TestTokenEndpointRejection(t *testing.T) {
	e := newEnv(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"access_denied","error_description":"atlassian upstream detail"}`)
	}))
	defer bad.Close()
	hc := upstream.NewHTTPClient(5 * time.Second)
	c := e.h.Config
	read := upstream.NewTokenSource("read", c.ReadClientIDFile, c.ReadClientSecretFile, bad.URL, hc, e.h.Log)
	e.h.Forwarder = upstream.NewForwarder(c.UpstreamBaseURL, hc, read, nil, c.MaxResponseBytes)
	wantError(t, "token rejected", e.do(t, "GET", base+"/myself", e.token(t, "org/ro"), "", nil), apierr.UpstreamAuth)
}

func TestRequestTooLarge(t *testing.T) {
	e := newEnv(t)
	body := `{"jql":"` + strings.Repeat("a", 5000) + `"}`
	wantError(t, "large body", e.do(t, "POST", base+"/search/jql", e.token(t, "org/ro"), body, nil), apierr.RequestTooLarge)
}

func TestAuditLog(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/rw")
	e.do(t, "PUT", base+"/issue/ABC-1/properties/fullsend.poll.org.rw.lastCheck", tok, `"BODYMARKER"`, nil)
	e.up.body = `{"issues":[]}`
	e.do(t, "POST", base+"/search/jql", tok, `{"jql":"project = ABC AND labels = JQLMARKER"}`, nil)
	e.do(t, "GET", base+"/issue/OTHER-1", tok, "", nil)
	logs := e.log.String()
	for _, s := range []string{tok, "atlassian-token", "write-client-secret-value", "write-client-id", "BODYMARKER", "JQLMARKER", "OTHER-1", "fullsend.poll"} {
		if strings.Contains(logs, s) {
			t.Errorf("log contains %q", s)
		}
	}
	var reqs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %s", l)
		}
		if m["message"] == "request" {
			reqs = append(reqs, m)
		}
	}
	if len(reqs) != 3 {
		t.Fatalf("request lines = %d", len(reqs))
	}
	want := []struct {
		path, decision string
		preflight      float64
	}{
		{"/ex/jira/{cloudId}/rest/api/3/issue/{key}/properties/{k}", "allow", 1},
		{"/ex/jira/{cloudId}/rest/api/3/search/jql", "allow", 0},
		{"/ex/jira/{cloudId}/rest/api/3/issue/{key}", "deny", 0},
	}
	for i, w := range want {
		r := reqs[i]
		if r["path"] != w.path || r["decision"] != w.decision || r["repository"] != "org/rw" || r["run_id"] != "1234567890" || r["preflight_calls"] != w.preflight {
			t.Errorf("line %d = %v", i, r)
		}
	}
	if reqs[1]["jql_sha256"] == nil || reqs[0]["upstream_status"] != float64(200) || reqs[2]["code"] != "not_granted" || reqs[2]["reason"] != "project not in grant" {
		t.Errorf("fields: %v / %v / %v", reqs[0], reqs[1], reqs[2])
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// timeoutDoer stands in for an upstream that never answers in time.
type timeoutDoer struct{}

func (timeoutDoer) Do(ctx context.Context, _ bool, _, _, _ string, _ []byte) (*upstream.Result, error) {
	return nil, context.DeadlineExceeded
}

// TestDenialTable has one row per documented denial: status and code.
func TestDenialTable(t *testing.T) {
	e := newEnv(t)
	ro, rw := e.token(t, "org/ro"), e.token(t, "org/rw")
	adf := `{"body":{"type":"doc","version":1,"content":[]}}`
	rows := []struct {
		name, method, uri, token, body string
		want                           apierr.E
	}{
		{"comment property GET", "GET", base + "/comment/1/properties/k", ro, "", apierr.EndpointNotAllowed},
		{"comment property PUT", "PUT", base + "/comment/1/properties/k", rw, `{}`, apierr.EndpointNotAllowed},
		{"comment property DELETE", "DELETE", base + "/comment/1/properties/k", rw, "", apierr.EndpointNotAllowed},
		{"unknown query parameter", "GET", base + "/issue/ABC-1?expand=names", ro, "", apierr.QueryNotAllowed},
		{"repeated query parameter", "GET", base + "/issue/ABC-1/changelog?startAt=0&startAt=1", ro, "", apierr.QueryNotAllowed},
		{"JQL outside the grammar", "POST", base + "/search/jql", ro, `{"jql":"project = ABC OR project = OTHER"}`, apierr.JQLGrammar},
		{"duplicate body key", "POST", base + "/search/jql", ro, `{"jql":"project = ABC","jql":"project = ABC"}`, apierr.BodyNotAllowed},
		{"unknown body key", "POST", base + "/search/jql", ro, `{"jql":"project = ABC","expand":"x"}`, apierr.BodyNotAllowed},
		{"non-JSON body", "POST", base + "/search/jql", ro, `jql=project`, apierr.BodyNotAllowed},
		{"project not in grant", "GET", base + "/issue/OTHER-1", ro, "", apierr.NotGranted},
		{"moved issue", "GET", base + "/issue/ABC-5", ro, "", apierr.NotGranted},
		{"another repo's property key", "GET", base + "/issue/ABC-1/properties/fullsend.poll.org.rw.lock", ro, "", apierr.NotGranted},
		{"non-poll property key", "GET", base + "/issue/ABC-1/properties/foo", ro, "", apierr.NotGranted},
		{"unknown cloudId", "GET", "/ex/jira/99999999-0000-0000-0000-000000000000/rest/api/3/myself", ro, "", apierr.NotGranted},
		{"numeric issue id", "GET", base + "/issue/10001", ro, "", apierr.EndpointNotAllowed},
		{"lowercase issue key", "GET", base + "/issue/abc-1", ro, "", apierr.EndpointNotAllowed},
		{"../", "GET", base + "/issue/ABC-1/../../myself", ro, "", apierr.EndpointNotAllowed},
		{"%2F", "GET", base + "/issue/ABC-1%2F..", ro, "", apierr.EndpointNotAllowed},
		{"%2f", "GET", base + "/issue/ABC-1%2f..", ro, "", apierr.EndpointNotAllowed},
		{"//", "GET", base + "//myself", ro, "", apierr.EndpointNotAllowed},
		{"/rest/api/2", "GET", "/ex/jira/" + cloud + "/rest/api/2/myself", ro, "", apierr.EndpointNotAllowed},
		{"agile path", "GET", "/ex/jira/" + cloud + "/rest/agile/1.0/board", ro, "", apierr.EndpointNotAllowed},
		{"write method on a read grant", "POST", base + "/issue/ABC-1/comment", ro, adf, apierr.NotGranted},
		{"in-grammar JQL, foreign project", "POST", base + "/search/jql", ro, `{"jql":"project = OTHER"}`, apierr.NotGranted},
		{"comment binding mismatch", "PUT", base + "/issue/ABC-1/comment/20002", rw, adf, apierr.NotGranted},
		{"bad token", "GET", base + "/myself", "not-a-jwt", "", apierr.Unauthenticated},
		{"missing token", "GET", base + "/myself", "", "", apierr.Unauthenticated},
	}
	for _, r := range rows {
		wantError(t, r.name, e.do(t, r.method, r.uri, r.token, r.body, nil), r.want)
	}

	// A pre-flight that errors or times out is a 502, and nothing is forwarded.
	e.h.Preflight = preflight.New(timeoutDoer{}, 0)
	wantError(t, "pre-flight timeout", e.do(t, "GET", base+"/issue/ABC-1", ro, "", nil), apierr.UpstreamUnavailable)
	e.h.Preflight = preflight.New(e.h.Forwarder, 0)
	e.up.preflightFail = 503
	wantError(t, "pre-flight 5xx", e.do(t, "GET", base+"/issue/ABC-1", ro, "", nil), apierr.UpstreamUnavailable)
	if n := e.up.forwarded(); n != 0 {
		t.Fatalf("%d calls forwarded", n)
	}
}

func TestWriteRoutesSkipPreflightCache(t *testing.T) {
	e := newEnv(t)
	e.up.status, e.up.body = 201, `{"id":"1"}`
	rw := e.token(t, "org/rw")
	for i := 0; i < 3; i++ {
		if w := e.do(t, "POST", base+"/issue/ABC-1/comment", rw, `{"body":{"type":"doc","version":1,"content":[]}}`, nil); w.Code != 201 {
			t.Fatalf("status %d %s", w.Code, w.Body)
		}
	}
	if e.up.preflights != 3 {
		t.Fatalf("pre-flights = %d, want 3 (writes never use the cache)", e.up.preflights)
	}
}

// TestIssueKeyRecheckedAfterStrip: if the issue Jira returns is not the
// one requested (it moved after a cached pre-flight), the answer is
// refused.
func TestIssueKeyRecheckedAfterStrip(t *testing.T) {
	e := newEnv(t)
	e.up.body = `{"id":"10001","key":"OTHER-9","fields":{"summary":"secret OTHER work"}}`
	w := e.do(t, "GET", base+"/issue/ABC-1", e.token(t, "org/ro"), "", nil)
	wantError(t, "returned key differs", w, apierr.NotGranted)
}

func TestChangelogAllowlist(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/ro")
	e.up.body = `{"startAt":0,"maxResults":100,"total":3,"isLast":false,"values":[
	  {"id":"1","created":"x","items":[{"field":"status","from":"1","to":"3"},{"field":"Link","toString":"OTHER-1"}]},
	  {"id":"2","created":"y","items":[{"field":"issuelinks","toString":"OTHER-2"},{"field":"customfield_1","toString":"OTHER-3"}]},
	  {"id":"3","created":"z","items":[{"field":"labels","fromString":"","toString":"fullsend"}]}]}`
	w := e.do(t, "GET", base+"/issue/ABC-1/changelog?maxResults=100&startAt=0", tok, "", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "OTHER") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var got struct {
		StartAt, Total int
		IsLast         bool
		Values         []struct {
			ID    string
			Items []map[string]any
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 3 || got.IsLast || len(got.Values) != 3 || len(got.Values[0].Items) != 1 || len(got.Values[1].Items) != 0 || len(got.Values[2].Items) != 1 {
		t.Fatalf("changelog %+v", got)
	}
	e.up.body = `{"values":{}}`
	wantError(t, "undecodable changelog", e.do(t, "GET", base+"/issue/ABC-1/changelog", tok, "", nil), apierr.UpstreamUndecodable)
}

func TestFilterBusy(t *testing.T) {
	e := newEnv(t)
	e.h.Filters = respfilter.NewLimiter(1, 20*time.Millisecond)
	hold := make(chan struct{})
	started := make(chan struct{})
	go e.h.Filters.Do(context.Background(), func() error { close(started); <-hold; return nil })
	<-started
	e.up.body = `{"issues":[]}`
	w := e.do(t, "POST", base+"/search/jql", e.token(t, "org/ro"), `{"jql":"project = ABC"}`, nil)
	close(hold)
	wantError(t, "filter busy", w, apierr.GatewayBusy)
}

// TestUpstreamStatusPassThrough: only 2xx, 400, 404, 409 and 429 carry
// Jira's body back; every other status gets a fixed upstream_error body.
func TestUpstreamStatusPassThrough(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/ro")
	for _, st := range []int{200, 201, 204, 400, 404, 409, 429} {
		e.up.status, e.up.body = st, `{"errorMessages":["jira says"]}`
		if st == 204 {
			e.up.body = ""
		}
		w := e.do(t, "GET", base+"/myself", tok, "", nil)
		if w.Code != st || w.Body.String() != e.up.body {
			t.Errorf("status %d: got %d %q", st, w.Code, w.Body)
		}
	}
	for _, st := range []int{402, 405, 406, 408, 410, 411, 412, 413, 415, 418, 422, 423, 451, 500, 501, 503, 599} {
		e.up.status, e.up.body = st, `{"errorMessages":["atlassian upstream detail"]}`
		wantError(t, fmt.Sprint("upstream ", st), e.do(t, "GET", base+"/myself", tok, "", nil), apierr.UpstreamFailed)
	}
}
