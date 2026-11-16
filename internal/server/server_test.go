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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/audit"
	"github.com/nonflux/tmp-jira-gateway/internal/auth"
	"github.com/nonflux/tmp-jira-gateway/internal/config"
	"github.com/nonflux/tmp-jira-gateway/internal/testissuer"
	"github.com/nonflux/tmp-jira-gateway/internal/upstream"
)

const (
	aud   = "fullsend-jira-gateway-dev"
	cloud = "11111111-2222-3333-4444-555555555555"
	base  = "/ex/jira/" + cloud + "/rest/api/3"
)

// atlassian is a fake token endpoint plus Jira API that records what it
// receives.
type atlassian struct {
	srv      *httptest.Server
	mu       sync.Mutex
	tokens   int
	requests []*http.Request
	bodies   []string
	status   int
	body     string
	ctype    string
}

func newAtlassian(t *testing.T) *atlassian {
	a := &atlassian{status: 200, body: `{"accountId":"svc","accountType":"app"}`, ctype: "application/json"}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if r.URL.Path == "/oauth/token" {
			a.tokens++
			fmt.Fprintf(w, `{"access_token":"atlassian-access-token-%d","token_type":"Bearer","expires_in":3600}`, a.tokens)
			return
		}
		b, _ := io.ReadAll(r.Body)
		a.requests = append(a.requests, r.Clone(context.Background()))
		a.bodies = append(a.bodies, string(b))
		w.Header().Set("Content-Type", a.ctype)
		w.Header().Set("X-Upstream-Secret-Header", "internal")
		w.WriteHeader(a.status)
		fmt.Fprint(w, a.body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *atlassian) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokens + len(a.requests)
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
	h := &Handler{Config: cfg, Verifier: v, Forwarder: upstream.NewForwarder(cfg.UpstreamBaseURL, hc, read, write, cfg.MaxResponseBytes), Log: log}
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

// wantError checks a gateway answer: status, a JSON body that is exactly
// {"error": msg}, and no upstream text.
func wantError(t *testing.T, name string, w *httptest.ResponseRecorder, status int, msg string) {
	t.Helper()
	if w.Code != status {
		t.Errorf("%s: status %d, want %d (body %s)", name, w.Code, status, w.Body)
		return
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s: content type %q", name, ct)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || len(m) != 1 {
		t.Errorf("%s: body %q is not {\"error\": ...}", name, w.Body)
		return
	}
	if msg != "" && m["error"] != msg {
		t.Errorf("%s: error %q, want %q", name, m["error"], msg)
	}
	for _, s := range []string{"accountId", "errorMessages", "atlassian", "upstream detail"} {
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
		{"other audience", e.iss.Sign(t, otherAud), nil},
	}
	for _, c := range cases {
		w := e.do(t, "GET", base+"/myself", c.token, "", c.hdr)
		wantError(t, c.name, w, 401, msgUnauthorized)
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
		name, method, uri, token, body, msg string
	}{
		{"no grant", "GET", base + "/myself", e.token(t, "org/none"), "", msgNoGrant},
		{"owner id mismatch", "GET", base + "/myself", wrongIDs, "", msgNoGrant},
		{"unknown cloudId", "GET", "/ex/jira/99999999-0000-0000-0000-000000000000/rest/api/3/myself", ro, "", "cloud id not in grant"},
		{"lowercase issue key", "GET", base + "/issue/abc-1", ro, "", "endpoint not allowed"},
		{"numeric issue id", "GET", base + "/issue/10001", ro, "", "endpoint not allowed"},
		{"foreign issue", "GET", base + "/issue/OTHER-1", ro, "", "project not in grant"},
		{"api v2", "GET", "/ex/jira/" + cloud + "/rest/api/2/myself", ro, "", "path not allowed"},
		{"agile", "GET", "/ex/jira/" + cloud + "/rest/agile/1.0/board", ro, "", "path not allowed"},
		{"dot dot", "GET", base + "/issue/ABC-1/../../issue/OTHER-1", ro, "", "path not allowed"},
		{"%2F", "GET", base + "/issue/ABC-1%2F..%2F..%2Fmyself", ro, "", "path not allowed"},
		{"%2f", "GET", base + "/issue/ABC-1%2f..%2f..%2fmyself", ro, "", "path not allowed"},
		{"double slash", "GET", base + "//myself", ro, "", "path not allowed"},
		{"read grant write", "POST", base + "/issue/ABC-1/comment", ro, `{"body":{}}`, "write grant required"},
		{"comment property", "GET", base + "/comment/1/properties/k", ro, "", "comment property calls are not allowed"},
		{"jql twice", "POST", base + "/search/jql", ro, `{"jql":"project = ABC","jql":"project = OTHER"}`, "request body not allowed"},
		{"jql in query string", "POST", base + "/search/jql?jql=project", ro, `{"jql":"project = ABC"}`, "query not allowed"},
	}
	for _, c := range cases {
		w := e.do(t, c.method, c.uri, c.token, c.body, nil)
		wantError(t, c.name, w, 403, c.msg)
	}
	if n := e.up.calls(); n != 0 {
		t.Fatalf("%d upstream calls on denied requests", n)
	}
}

func TestJQLRefusalBody(t *testing.T) {
	e := newEnv(t)
	marker := "SECRETMARKER"
	q := `project = OTHER AND labels = ` + marker
	body, _ := json.Marshal(map[string]any{"jql": q, "maxResults": 50})
	w := e.do(t, "POST", base+"/search/jql", e.token(t, "org/ro"), string(body), nil)
	if w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"error":"jql outside the accepted grammar"}` {
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
	if got := r.Header.Get("Authorization"); got != "Bearer atlassian-access-token-1" {
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

func TestFullsendDefaultQueriesForwardedUnchanged(t *testing.T) {
	e := newEnv(t)
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

func TestEditCommentWriteGrant(t *testing.T) {
	e := newEnv(t)
	rw := e.token(t, "org/rw")
	ok := `{"body":{"type":"doc","version":1,"content":[]},"properties":[{"key":"fullsend.agent-status","value":{"s":1}}]}`
	if w := e.do(t, "PUT", base+"/issue/ABC-1/comment/10001", rw, ok, nil); w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	for name, c := range map[string]struct{ uri, token, body, msg string }{
		"extra top-level key":  {base + "/issue/ABC-1/comment/10001", rw, `{"body":{},"visibility":{}}`, "request body not allowed"},
		"duplicate properties": {base + "/issue/ABC-1/comment/10001", rw, `{"properties":[],"properties":[]}`, "request body not allowed"},
		"read grant":           {base + "/issue/ABC-1/comment/10001", e.token(t, "org/ro"), ok, "write grant required"},
		"foreign project":      {base + "/issue/OTHER-1/comment/10001", rw, ok, "project not in grant"},
		"non-numeric id":       {base + "/issue/ABC-1/comment/x1", rw, ok, "endpoint not allowed"},
	} {
		wantError(t, name, e.do(t, "PUT", c.uri, c.token, c.body, nil), 403, c.msg)
	}
}

func TestUpstreamAnswers(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/ro")
	// A Jira 404 to an allowed call passes back with its body.
	e.up.status, e.up.body = 404, `{"errorMessages":["Issue does not exist"]}`
	w := e.do(t, "GET", base+"/issue/ABC-9", tok, "", nil)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "Issue does not exist") {
		t.Fatalf("404: %d %s", w.Code, w.Body)
	}
	// 403 and 5xx bodies are replaced; 401 becomes 502 so the caller does
	// not read it as a refusal of its own token.
	for _, c := range []struct {
		up, want int
		msg      string
	}{{403, 403, msgUpstreamRefused}, {500, 500, msgUpstreamError}, {503, 503, msgUpstreamError}, {401, 502, msgUpstreamAuth}, {302, 502, msgUpstreamRedirect}} {
		e.up.status, e.up.body = c.up, `{"errorMessages":["atlassian upstream detail"]}`
		wantError(t, fmt.Sprint("upstream ", c.up), e.do(t, "GET", base+"/myself", tok, "", nil), c.want, c.msg)
	}
}

func TestRequestTooLarge(t *testing.T) {
	e := newEnv(t)
	body := `{"jql":"` + strings.Repeat("a", 5000) + `"}`
	wantError(t, "large body", e.do(t, "POST", base+"/search/jql", e.token(t, "org/ro"), body, nil), 413, msgTooLarge)
}

func TestAuditLog(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "org/rw")
	e.do(t, "PUT", base+"/issue/ABC-1/properties/fullsend.poll.org.repo.lastCheck", tok, `"BODYMARKER"`, nil)
	e.do(t, "POST", base+"/search/jql", tok, `{"jql":"project = ABC AND labels = JQLMARKER"}`, nil)
	e.do(t, "GET", base+"/issue/OTHER-1", tok, "", nil)
	logs := e.log.String()
	for _, s := range []string{tok, "atlassian-access-token", "write-client-secret-value", "write-client-id", "BODYMARKER", "JQLMARKER", "OTHER-1", "fullsend.poll"} {
		if strings.Contains(logs, s) {
			t.Errorf("log contains %q", s)
		}
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %s", l)
		}
		lines = append(lines, m)
	}
	var reqs []map[string]any
	for _, l := range lines {
		if l["message"] == "request" {
			reqs = append(reqs, l)
		}
	}
	if len(reqs) != 3 {
		t.Fatalf("request lines = %d", len(reqs))
	}
	want := []struct{ path, decision string }{
		{"/ex/jira/{cloudId}/rest/api/3/issue/{key}/properties/{k}", "allow"},
		{"/ex/jira/{cloudId}/rest/api/3/search/jql", "allow"},
		{"/ex/jira/{cloudId}/rest/api/3/issue/{key}", "deny"},
	}
	for i, w := range want {
		r := reqs[i]
		if r["path"] != w.path || r["decision"] != w.decision || r["repository"] != "org/rw" || r["run_id"] != "1234567890" {
			t.Errorf("line %d = %v", i, r)
		}
	}
	if reqs[1]["jql_sha256"] == nil || reqs[0]["upstream_status"] != float64(200) || reqs[2]["reason"] != "project not in grant" {
		t.Errorf("fields: %v / %v / %v", reqs[0], reqs[1], reqs[2])
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
