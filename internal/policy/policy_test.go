package policy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nonflux/tmp-jira-gateway/internal/config"
)

const cloud = "11111111-2222-3333-4444-555555555555"

func grants(t *testing.T) (read, write *config.Grant) {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`{
	  "audience": "fullsend-jira-gateway-dev",
	  "read_client_id_file": "/x", "read_client_secret_file": "/y",
	  "write_client_id_file": "/x", "write_client_secret_file": "/y",
	  "grants": [
	    {"repository":"org/ro","repository_id":"1","repository_owner_id":"9","cloudId":%q,"level":"read","projects":["ABC"]},
	    {"repository":"org/rw","repository_id":"2","repository_owner_id":"9","cloudId":%q,"level":"write","projects":["ABC","DEF"]}
	  ]}`, cloud, cloud)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Lookup("org/ro"), cfg.Lookup("org/rw")
}

const base = "/ex/jira/" + cloud + "/rest/api/3"

type tc struct {
	name   string
	method string
	uri    string
	body   string
	reason string // "" means allowed
}

func run(t *testing.T, g *config.Grant, cases []tc) {
	t.Helper()
	for _, c := range cases {
		ct := ""
		if c.body != "" {
			ct = "application/json"
		}
		d, denial := Authorize(g, Request{Method: c.method, RequestURI: c.uri, ContentType: ct, Body: []byte(c.body)})
		got := ""
		if denial != nil {
			got = denial.Reason
		}
		if got != c.reason {
			t.Errorf("%s: %s %s: got %q, want %q", c.name, c.method, c.uri, got, c.reason)
		}
		if denial == nil && d.UpstreamPath == "" {
			t.Errorf("%s: allowed without an upstream path", c.name)
		}
	}
}

const pollerJQL = `{"jql":"project = \"ABC\" AND statusCategory != Done ORDER BY updated DESC","maxResults":50,"fields":["summary","status","labels","reporter","assignee","created","updated","project","issuetype"]}`

func TestReadGrant(t *testing.T) {
	ro, _ := grants(t)
	run(t, ro, []tc{
		{"myself", "GET", base + "/myself", "", ""},
		{"status id", "GET", base + "/status/10001", "", ""},
		{"status name", "GET", base + "/status/In%20Progress", "", ""},
		{"project roles", "GET", base + "/project/ABC/role", "", ""},
		{"project role", "GET", base + "/project/ABC/role/10002", "", ""},
		{"issue", "GET", base + "/issue/ABC-1", "", ""},
		{"comments", "GET", base + "/issue/ABC-1/comment?orderBy=created&maxResults=100&startAt=0&expand=properties", "", ""},
		{"changelog", "GET", base + "/issue/ABC-1/changelog?maxResults=100&startAt=200", "", ""},
		{"transitions", "GET", base + "/issue/ABC-1/transitions?expand=transitions.fields", "", ""},
		{"issue property lastCheck", "GET", base + "/issue/ABC-1/properties/fullsend.poll.org.ro.lastCheck", "", ""},
		{"issue property lock", "GET", base + "/issue/ABC-1/properties/fullsend.poll.org.ro.lock", "", ""},
		{"user groups, uuid form", "GET", base + "/user/groups?accountId=557058%3A0b6d5c34-1f2e-4a5b-8c9d-0e1f2a3b4c5d", "", ""},
		{"user groups, literal colon", "GET", base + "/user/groups?accountId=557058:0b6d5c34-1f2e-4a5b-8c9d-0e1f2a3b4c5d", "", ""},
		{"user groups, lowercase escape", "GET", base + "/user/groups?accountId=557058%3a0b6d5c34-1f2e-4a5b-8c9d-0e1f2a3b4c5d", "", ""},
		{"user groups, hex form", "GET", base + "/user/groups?accountId=5b10ac8d82e05b22cc7d4ef5", "", ""},
		{"search", "POST", base + "/search/jql", pollerJQL, ""},
		{"search, CLI form", "POST", base + "/search/jql", `{"jql":"project = \"ABC\" AND (statusCategory != Done) ORDER BY updated DESC","maxResults":50,"fields":["summary"],"nextPageToken":"abc"}`, ""},

		{"foreign issue", "GET", base + "/issue/OTHER-1", "", ReasonProject},
		{"foreign comments", "GET", base + "/issue/OTHER-1/comment", "", ReasonProject},
		{"foreign project roles", "GET", base + "/project/OTHER/role", "", ReasonProject},
		{"numeric issue id", "GET", base + "/issue/10001", "", ReasonEndpoint},
		{"lowercase key", "GET", base + "/issue/abc-1", "", ReasonEndpoint},
		{"encoded key", "GET", base + "/issue/ABC%2D1", "", ReasonEndpoint},
		{"user groups, bad id", "GET", base + "/user/groups?accountId=x", "", ReasonQuery},
		{"user groups, missing id", "GET", base + "/user/groups", "", ReasonQuery},
		{"user groups, repeated id", "GET", base + "/user/groups?accountId=5b10ac8d82e05b22cc7d4ef5&accountId=5b10ac8d82e05b22cc7d4ef6", "", ReasonQuery},
		{"user groups, extra param", "GET", base + "/user/groups?accountId=5b10ac8d82e05b22cc7d4ef5&expand=x", "", ReasonQuery},
		{"user groups, double-encoded colon", "GET", base + "/user/groups?accountId=557058%253A0b6d5c34-1f2e-4a5b-8c9d-0e1f2a3b4c5d", "", ReasonQuery},
		{"user groups, other escape", "GET", base + "/user/groups?accountId=5b10ac8d82e05b22cc7d4ef%35", "", ReasonQuery},
		{"user groups, uppercase hex", "GET", base + "/user/groups?accountId=5B10AC8D82E05B22CC7D4EF5", "", ReasonQuery},
		{"user groups, POST", "POST", base + "/user/groups?accountId=5b10ac8d82e05b22cc7d4ef5", `{}`, ReasonEndpoint},
		{"colon in another param", "GET", base + "/issue/ABC-1/changelog?startAt=1:2", "", ReasonQuery},
		{"leading zero key", "GET", base + "/issue/ABC-01", "", ReasonEndpoint},
		{"zero key", "GET", base + "/issue/ABC-0", "", ReasonEndpoint},
		{"project list", "GET", base + "/project", "", ReasonEndpoint},
		{"users search", "GET", base + "/users/search", "", ReasonEndpoint},
		{"delete issue", "DELETE", base + "/issue/ABC-1", "", ReasonEndpoint},
		{"search GET", "GET", base + "/search/jql?jql=project%3DABC", "", ReasonEndpoint},
		{"api v2", "GET", "/ex/jira/" + cloud + "/rest/api/2/myself", "", ReasonPath},
		{"agile", "GET", "/ex/jira/" + cloud + "/rest/agile/1.0/board", "", ReasonPath},
		{"site path", "GET", "/rest/api/3/myself", "", ReasonPath},
		{"wrong cloud id", "GET", "/ex/jira/99999999-0000-0000-0000-000000000000/rest/api/3/myself", "", ReasonCloudID},

		{"dot dot", "GET", base + "/issue/ABC-1/../../issue/OTHER-1", "", ReasonPath},
		{"encoded dot dot", "GET", base + "/issue/ABC-1/%2e%2e/OTHER-1", "", ReasonPath},
		{"dot", "GET", base + "/./myself", "", ReasonPath},
		{"encoded slash", "GET", base + "/issue/ABC-1%2F..%2FOTHER-1", "", ReasonPath},
		{"encoded slash lower", "GET", base + "/issue/ABC-1%2f..%2fOTHER-1", "", ReasonPath},
		{"double slash", "GET", base + "//myself", "", ReasonPath},
		{"trailing slash", "GET", base + "/myself/", "", ReasonPath},
		{"backslash", "GET", base + "/issue\\ABC-1", "", ReasonPath},
		{"encoded backslash", "GET", base + "/issue/ABC-1%5C..", "", ReasonPath},
		{"bad escape", "GET", base + "/issue/ABC-1%zz", "", ReasonPath},
		{"nul", "GET", base + "/issue/ABC-1%00", "", ReasonPath},
		{"absolute form", "GET", "http://evil" + base + "/myself", "", ReasonPath},
		{"encoded prefix", "GET", "/ex/jira/" + cloud + "/rest/api/%33/myself", "", ReasonPath},

		{"unknown query param", "GET", base + "/issue/ABC-1?fields=*all", "", ReasonQuery},
		{"repeated param", "GET", base + "/issue/ABC-1/changelog?startAt=0&startAt=1", "", ReasonQuery},
		{"bad query value", "GET", base + "/issue/ABC-1/comment?orderBy=-created", "", ReasonQuery},
		{"jql in query", "POST", base + "/search/jql?jql=project", pollerJQL, ReasonQuery},
		{"repeated jql in query", "POST", base + "/search/jql?jql=a&jql=b", pollerJQL, ReasonQuery},
		{"encoded query", "GET", base + "/issue/ABC-1/changelog?startAt=%30", "", ReasonQuery},

		{"body on GET", "GET", base + "/myself", `{}`, ReasonBody},
		{"jql twice", "POST", base + "/search/jql", `{"jql":"project = ABC","jql":"project = OTHER"}`, ReasonBody},
		{"trailing data", "POST", base + "/search/jql", `{"jql":"project = ABC"} {"jql":"project = OTHER"}`, ReasonBody},
		{"reconcileIssues", "POST", base + "/search/jql", `{"jql":"project = ABC","reconcileIssues":[10001]}`, ReasonBody},
		{"array body", "POST", base + "/search/jql", `[{"jql":"project = ABC"}]`, ReasonBody},
		{"foreign jql", "POST", base + "/search/jql", `{"jql":"project = OTHER"}`, ReasonJQLProject},
		{"jql escape", "POST", base + "/search/jql", `{"jql":"project = ABC AND status = Open) OR (project = OTHER"}`, ReasonJQL},
		{"jql without project", "POST", base + "/search/jql", `{"jql":"statusCategory != Done"}`, ReasonJQL},

		{"comment property GET", "GET", base + "/comment/10001/properties/fullsend.sticky-marker", "", ReasonCommentProperty},
		{"comment property PUT", "PUT", base + "/comment/10001/properties/k", `{}`, ReasonCommentProperty},
		{"comment property DELETE", "DELETE", base + "/comment/10001/properties/k", "", ReasonCommentProperty},

		{"write on read grant: comment", "POST", base + "/issue/ABC-1/comment", `{"body":{}}`, ReasonLevel},
		{"write on read grant: edit comment", "PUT", base + "/issue/ABC-1/comment/10001", `{"body":{}}`, ReasonLevel},
		{"write on read grant: property", "PUT", base + "/issue/ABC-1/properties/k", `"x"`, ReasonLevel},
		{"write on read grant: create", "POST", base + "/issue", `{"fields":{"project":{"key":"ABC"}}}`, ReasonLevel},
	})
}

func TestWriteGrant(t *testing.T) {
	_, rw := grants(t)
	adf := `{"type":"doc","version":1,"content":[]}`
	run(t, rw, []tc{
		{"add comment", "POST", base + "/issue/ABC-1/comment", `{"body":` + adf + `}`, ""},
		{"add comment with properties", "POST", base + "/issue/DEF-2/comment", `{"body":` + adf + `,"properties":[{"key":"fullsend.sticky-marker","value":{"m":"x"}}]}`, ""},
		{"edit comment: body", "PUT", base + "/issue/ABC-1/comment/10001", `{"body":` + adf + `}`, ""},
		{"edit comment: properties", "PUT", base + "/issue/ABC-1/comment/10001", `{"properties":[{"key":"fullsend.agent-status","value":{"s":1}}]}`, ""},
		{"edit comment: both", "PUT", base + "/issue/ABC-1/comment/10001", `{"body":` + adf + `,"properties":[]}`, ""},
		{"edit comment: extra key", "PUT", base + "/issue/ABC-1/comment/10001", `{"body":` + adf + `,"visibility":{"type":"role","value":"x"}}`, ReasonBody},
		{"edit comment: duplicate properties", "PUT", base + "/issue/ABC-1/comment/10001", `{"properties":[],"properties":[{"key":"k","value":1}]}`, ReasonBody},
		{"edit comment: empty", "PUT", base + "/issue/ABC-1/comment/10001", `{}`, ReasonBody},
		{"edit comment: foreign project", "PUT", base + "/issue/OTHER-1/comment/10001", `{"body":` + adf + `}`, ReasonProject},
		{"edit comment: non-numeric id", "PUT", base + "/issue/ABC-1/comment/abc", `{"body":` + adf + `}`, ReasonEndpoint},
		{"edit comment: no body", "PUT", base + "/issue/ABC-1/comment/10001", "", ReasonBody},
		{"delete comment", "DELETE", base + "/issue/ABC-1/comment/10001", "", ""},
		{"transition", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"resolution":{"name":"Done"}},"update":{"comment":[{"add":{"body":` + adf + `}}]}}`, ""},
		{"transition, resolution by id", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"resolution":{"id":"10000"}}}`, ""},
		{"transition, bare", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"}}`, ""},
		{"transition, custom field", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"customfield_10014":"OTHER-1"}}`, ReasonBody},
		{"transition, security", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"security":{"id":"1"}}}`, ReasonBody},
		{"transition, resolution with extra key", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"resolution":{"name":"Done","id":"1"}}}`, ReasonBody},
		{"transition, case-variant field", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"Resolution":{"name":"Done"}}}`, ReasonBody},
		{"transition with parent", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"parent":{"key":"OTHER-1"}}}`, ReasonBody},
		{"transition update labels", "POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"update":{"issuelinks":[]}}`, ReasonBody},
		{"set lock", "PUT", base + "/issue/ABC-1/properties/fullsend.poll.org.rw.lock", `{"owner":"x","expires":"y"}`, ""},
		{"set lastCheck", "PUT", base + "/issue/ABC-1/properties/fullsend.poll.org.rw.lastCheck", `"2026-11-16T10:00:00Z"`, ""},
		{"set lock dup keys", "PUT", base + "/issue/ABC-1/properties/fullsend.poll.org.rw.lock", `{"a":1,"a":2}`, ReasonBody},
		{"set lock too big", "PUT", base + "/issue/ABC-1/properties/fullsend.poll.org.rw.lock", `"` + strings.Repeat("x", 33<<10) + `"`, ReasonBody},
		{"delete lock", "DELETE", base + "/issue/ABC-1/properties/fullsend.poll.org.rw.lock", "", ""},
		{"delete lastCheck", "DELETE", base + "/issue/ABC-1/properties/fullsend.poll.org.rw.lastCheck", "", ReasonPropertyKey},
		{"arbitrary key", "PUT", base + "/issue/ABC-1/properties/foo", `1`, ReasonPropertyKey},
		{"other repo's key", "PUT", base + "/issue/ABC-1/properties/fullsend.poll.org.ro.lock", `1`, ReasonPropertyKey},
		{"add label", "PUT", base + "/issue/ABC-1", `{"update":{"labels":[{"add":"fullsend"}]}}`, ""},
		{"edit other field", "PUT", base + "/issue/ABC-1", `{"fields":{"parent":{"key":"OTHER-1"}}}`, ReasonBody},
		{"edit labels and links", "PUT", base + "/issue/ABC-1", `{"update":{"labels":[{"add":"x"}],"issuelinks":[]}}`, ReasonBody},
		{"create", "POST", base + "/issue", `{"fields":{"project":{"key":"ABC"},"issuetype":{"name":"Task"},"summary":"s","description":` + adf + `}}`, ""},
		{"create sub-task", "POST", base + "/issue", `{"fields":{"project":{"key":"DEF"},"issuetype":{"id":"10003"},"summary":"s","parent":{"key":"ABC-1"}}}`, ""},
		{"create in foreign project", "POST", base + "/issue", `{"fields":{"project":{"key":"OTHER"},"issuetype":{"name":"Task"},"summary":"s"}}`, ReasonProject},
		{"create with foreign parent", "POST", base + "/issue", `{"fields":{"project":{"key":"ABC"},"issuetype":{"name":"Task"},"summary":"s","parent":{"key":"OTHER-1"}}}`, ReasonProject},
		{"create with project twice", "POST", base + "/issue", `{"fields":{"project":{"key":"ABC"},"project":{"key":"OTHER"}}}`, ReasonBody},
		{"create with project case variant", "POST", base + "/issue", `{"fields":{"project":{"key":"ABC"},"Project":{"key":"OTHER"}}}`, ReasonBody},
		{"create by project id", "POST", base + "/issue", `{"fields":{"project":{"id":"10000"}}}`, ReasonBody},
		{"create with parent id", "POST", base + "/issue", `{"fields":{"project":{"key":"ABC"},"parent":{"id":"10001"}}}`, ReasonBody},
		{"create with extra field", "POST", base + "/issue", `{"fields":{"project":{"key":"ABC"},"labels":["x"]}}`, ReasonBody},
		{"create with update", "POST", base + "/issue", `{"fields":{"project":{"key":"ABC"}},"update":{}}`, ReasonBody},
		{"link", "POST", base + "/issueLink", `{"type":{"name":"Blocks"},"inwardIssue":{"key":"ABC-1"},"outwardIssue":{"key":"DEF-2"}}`, ""},
		{"link to foreign issue", "POST", base + "/issueLink", `{"type":{"name":"Blocks"},"inwardIssue":{"key":"ABC-1"},"outwardIssue":{"key":"OTHER-2"}}`, ReasonProject},
		{"link by id", "POST", base + "/issueLink", `{"type":{"name":"Blocks"},"inwardIssue":{"key":"ABC-1"},"outwardIssue":{"id":"10001"}}`, ReasonBody},
		{"link with comment", "POST", base + "/issueLink", `{"type":{"name":"Blocks"},"inwardIssue":{"key":"ABC-1"},"outwardIssue":{"key":"ABC-2"},"comment":{}}`, ReasonBody},
		{"comment property still denied", "PUT", base + "/comment/10001/properties/k", `{}`, ReasonCommentProperty},
	})
}

func TestUpstreamPathIsReencoded(t *testing.T) {
	ro, _ := grants(t)
	d, denial := Authorize(ro, Request{Method: "GET", RequestURI: base + "/issue/ABC-1/properties/fullsend.poll.org.ro.lastCheck"})
	if denial != nil {
		t.Fatal(denial)
	}
	if want := base + "/issue/ABC-1/properties/fullsend.poll.org.ro.lastCheck"; d.UpstreamPath != want {
		t.Fatalf("upstream path %q, want %q", d.UpstreamPath, want)
	}
	if d.Template != "/ex/jira/{cloudId}/rest/api/3/issue/{key}/properties/{k}" {
		t.Fatalf("template %q", d.Template)
	}
	d, _ = Authorize(ro, Request{Method: "GET", RequestURI: base + "/status/In%20Progress"})
	if !strings.HasSuffix(d.UpstreamPath, "/status/In%20Progress") {
		t.Fatalf("status path %q", d.UpstreamPath)
	}
}

func TestSearchRecordsHash(t *testing.T) {
	ro, _ := grants(t)
	d, _ := Authorize(ro, Request{Method: "POST", RequestURI: base + "/search/jql", ContentType: "application/json", Body: []byte(`{"jql":"project = OTHER"}`)})
	if len(d.JQLHash) != 64 {
		t.Fatalf("JQL hash %q", d.JQLHash)
	}
}

func FuzzParseRequestURI(f *testing.F) {
	for _, s := range []string{base + "/myself", base + "/issue/ABC-1/../x", base + "//x", base + "/a%2Fb", base + "/a%252E?x=1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		_, rest, _, ok := parseRequestURI(uri)
		if !ok {
			return
		}
		for _, s := range rest {
			if s.dec == "" || s.dec == "." || s.dec == ".." || strings.ContainsAny(s.dec, "/\\") {
				t.Fatalf("accepted %q with segment %q", uri, s.dec)
			}
		}
	})
}

// TestPropertyKeyNamespace uses the worked examples agreed for core's key
// format (fullsend internal/jirapoll/lock.go).
func TestPropertyKeyNamespace(t *testing.T) {
	cfg, err := config.Parse([]byte(fmt.Sprintf(`{
	  "audience": "a", "read_client_id_file": "/x", "read_client_secret_file": "/y",
	  "write_client_id_file": "/x", "write_client_secret_file": "/y",
	  "grants": [
	    {"repository":"Acme-Org/my.repo-x","repository_id":"5","repository_owner_id":"9","cloudId":%q,"level":"write","projects":["PROJ"]},
	    {"repository":"acme/web.app-v2","repository_id":"6","repository_owner_id":"9","cloudId":%q,"level":"write","projects":["PROJ"]}
	  ]}`, cloud, cloud)))
	if err != nil {
		t.Fatal(err)
	}
	acme, web := cfg.Lookup("Acme-Org/my.repo-x"), cfg.Lookup("acme/web.app-v2")
	p := base + "/issue/PROJ-1/properties/"
	run(t, acme, []tc{
		{"lock", "PUT", p + "fullsend.poll.Acme-Org.my%252Erepo-x.lock", `{}`, ""},
		{"lock GET", "GET", p + "fullsend.poll.Acme-Org.my%252Erepo-x.lock", "", ""},
		{"lock DELETE", "DELETE", p + "fullsend.poll.Acme-Org.my%252Erepo-x.lock", "", ""},
		{"owner and repo case drift", "GET", p + "fullsend.poll.acme-org.MY%252Erepo-X.lock", "", ""},
		{"lowercase escape", "GET", p + "fullsend.poll.Acme-Org.my%252erepo-x.lock", "", ReasonPropertyKey},
		{"suffix case", "GET", p + "fullsend.poll.Acme-Org.my%252Erepo-x.Lock", "", ReasonPropertyKey},
		{"prefix case", "GET", p + "Fullsend.poll.Acme-Org.my%252Erepo-x.lock", "", ReasonPropertyKey},
		{"unescaped dot", "GET", p + "fullsend.poll.Acme-Org.my.repo-x.lock", "", ReasonPropertyKey},
		{"single-encoded escape", "GET", p + "fullsend.poll.Acme-Org.my%2Erepo-x.lock", "", ReasonEndpoint},
		{"triple-encoded escape", "GET", p + "fullsend.poll.Acme-Org.my%25252Erepo-x.lock", "", ReasonPropertyKey},
		{"other encoded byte", "GET", p + "fullsend.poll.Acme-Org.my%252Erepo%2Dx.lock", "", ReasonEndpoint},
		{"another repo", "GET", p + "fullsend.poll.acme.web%252Eapp-v2.lastCheck", "", ReasonPropertyKey},
		{"gitlab form", "GET", p + "fullsend.poll.gitlab.gitlab%252Ecom.Acme-Org.my%252Erepo-x.lock", "", ReasonPropertyKey},
		{"dots only", "GET", p + "...", "", ReasonEndpoint},
		{"encoded dots", "GET", p + "%252E%252E", "", ReasonPropertyKey},
		{"arbitrary", "GET", p + "foo", "", ReasonPropertyKey},
		{"trailing junk", "GET", p + "fullsend.poll.Acme-Org.my%252Erepo-x.lock.x", "", ReasonPropertyKey},
	})
	run(t, web, []tc{
		{"lastCheck", "PUT", p + "fullsend.poll.acme.web%252Eapp-v2.lastCheck", `"2026-11-16T10:00:00Z"`, ""},
		{"lastCheck GET", "GET", p + "fullsend.poll.acme.web%252Eapp-v2.lastCheck", "", ""},
		{"lastCheck DELETE", "DELETE", p + "fullsend.poll.acme.web%252Eapp-v2.lastCheck", "", ReasonPropertyKey},
		{"prefix-confusable repo", "GET", p + "fullsend.poll.acme.web%252Eapp-v2x.lastCheck", "", ReasonPropertyKey},
	})
}

func TestDecisionCarriesPreflightKeys(t *testing.T) {
	_, rw := grants(t)
	d, den := Authorize(rw, Request{Method: "DELETE", RequestURI: base + "/issue/ABC-1/comment/20002"})
	if den != nil || len(d.IssueKeys) != 1 || d.IssueKeys[0] != "ABC-1" || d.CommentID != "20002" || d.CommentIssueKey != "ABC-1" {
		t.Fatalf("delete comment: %+v %v", d, den)
	}
	d, _ = Authorize(rw, Request{Method: "POST", RequestURI: base + "/issueLink", ContentType: "application/json",
		Body: []byte(`{"type":{"name":"Blocks"},"inwardIssue":{"key":"ABC-1"},"outwardIssue":{"key":"DEF-2"}}`)})
	if strings.Join(d.IssueKeys, ",") != "ABC-1,DEF-2" {
		t.Fatalf("issueLink keys %v", d.IssueKeys)
	}
	d, _ = Authorize(rw, Request{Method: "POST", RequestURI: base + "/issue", ContentType: "application/json",
		Body: []byte(`{"fields":{"project":{"key":"ABC"},"parent":{"key":"DEF-3"}}}`)})
	if strings.Join(d.IssueKeys, ",") != "DEF-3" {
		t.Fatalf("create keys %v", d.IssueKeys)
	}
	d, _ = Authorize(rw, Request{Method: "GET", RequestURI: base + "/issue/ABC-1"})
	if d.Strip != StripIssue || d.CommentID != "" {
		t.Fatalf("get issue: %+v", d)
	}
	d, _ = Authorize(rw, Request{Method: "GET", RequestURI: base + "/myself"})
	if len(d.IssueKeys) != 0 || d.Strip != StripNone {
		t.Fatalf("myself: %+v", d)
	}
}

func TestDenialCodes(t *testing.T) {
	ro, _ := grants(t)
	for uri, code := range map[string]string{
		base + "/issue/OTHER-1": "not_granted",
		"/ex/jira/99999999-0000-0000-0000-000000000000/rest/api/3/myself": "not_granted",
		base + "/issue/abc-1":                "endpoint_not_allowed",
		base + "//myself":                    "endpoint_not_allowed",
		base + "/comment/1/properties/k":     "endpoint_not_allowed",
		base + "/issue/ABC-1?fields=x":       "query_not_allowed",
		base + "/issue/ABC-1/properties/foo": "not_granted",
	} {
		_, den := Authorize(ro, Request{Method: "GET", RequestURI: uri})
		if den == nil || den.Err.Code != code {
			t.Errorf("%s: %+v, want code %s", uri, den, code)
		}
	}
}

func TestContentType(t *testing.T) {
	_, rw := grants(t)
	body := []byte(`{"body":{"type":"doc","version":1,"content":[]}}`)
	for ct, want := range map[string]bool{
		"application/json":                  true,
		"application/json; charset=utf-8":   true,
		"application/json; charset=UTF-8":   true,
		"text/plain":                        false,
		"application/json; charset=latin1":  false,
		"":                                  false,
		"application/x-www-form-urlencoded": false,
	} {
		_, den := Authorize(rw, Request{Method: "PUT", RequestURI: base + "/issue/ABC-1/comment/10001", ContentType: ct, Body: body})
		if (den == nil) != want {
			t.Errorf("Content-Type %q: denial %v, want allowed=%v", ct, den, want)
		}
	}
}
