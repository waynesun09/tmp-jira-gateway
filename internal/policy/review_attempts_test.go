package policy

import (
	"strings"
	"testing"
)

// reviewAllowed are the only reviewer attempts the policy lets through;
// all are harmless (the comment edit is then pre-flighted, and "*all"
// search results are stripped).
var reviewAllowed = map[string]bool{
	"GET " + base + "/issue/ABC-1?":                        true,
	"GET " + base + "/myself":                              true,
	"GET " + base + "/status/a%20(b)":                      true,
	`POST {"jql":"project = ABC","maxResults":-0}`:         true,
	`POST {"jql":"project = ABC","fields":["*all"]}`:       true,
	"POST {\"jql\":\"project = ABC\"}\n":                   true,
	`PUT {"body":{"type":"doc","version":1,"content":[]}}`: true,
}

// TestReviewPathAttempts runs a reviewer's path, query and body bypass
// attempts; everything outside reviewAllowed must be denied.
func TestReviewPathAttempts(t *testing.T) {
	ro, rw := grants(t)
	type c struct {
		method, uri, body string
		write             bool
	}
	cases := []c{
		{"GET", base + "/issue/ABC-1%2F..%2F..%2Fmyself", "", false},
		{"GET", base + "/issue/ABC-1%252F..%252FOTHER-1", "", false},
		{"GET", base + "/issue/ABC-1%5Cx", "", false},
		{"GET", base + "/issue/ABC-1%255C", "", false},
		{"GET", base + "/issue/ABC-1;x=y", "", false},
		{"GET", base + "/issue/ABC-1;", "", false},
		{"GET", base + "/myself;jsessionid=x", "", false},
		{"GET", base + "/issue/ABC-1%3Bx", "", false},
		{"GET", base + "/issue/ABC-1/properties/%252E%252E", "", false},
		{"DELETE", base + "/issue/ABC-1/properties/%252E%252E", "", true},
		{"PUT", base + "/issue/ABC-1/properties/%252E%252E", `{"fields":{"summary":"x"}}`, true},
		{"GET", base + "/issue/ABC-1/properties/...", "", false},
		{"GET", base + "/issue/ABC-1/properties/%2E%2E", "", false},
		{"GET", base + "/issue/ABC-1/properties/%2e", "", false},
		{"GET", base + "/issue/ABC-1/properties/a%2Fb", "", false},
		{"GET", base + "/issue/ABC-1/properties/" + strings.Repeat("a", 256), "", false},
		{"GET", base + "/issue/ABC-1/properties/" + strings.Repeat("a", 255), "", false},
		{"GET", base + "/issue/" + strings.Repeat("A", 4000) + "-1", "", false},
		{"GET", base + "/issue/ABC-" + strings.Repeat("1", 19), "", false},
		{"GET", base + "/issue/ABC-0001", "", false},
		{"GET", base + "/issue/ABC-1?", "", false},
		{"GET", base + "/issue/ABC-1/comment?&", "", false},
		{"GET", base + "/issue/ABC-1/comment?maxResults=1%26fields%3D*all", "", false},
		{"GET", base + "/issue/ABC-1/comment?maxResults=1&maxresults=2", "", false},
		{"GET", base + "/issue/ABC-1/comment?expand=properties;renderedBody", "", false},
		{"GET", base + "/issue/ABC-1/comment?startAt", "", false},
		{"GET", base + "/issue/ABC-1/comment#x", "", false},
		{"GET", base + "/ISSUE/ABC-1", "", false},
		{"GET", base + "/Myself", "", false},
		{"GET", "/ex/jira/" + cloud + "/rest/api/latest/myself", "", false},
		{"GET", "/ex/jira/" + cloud + "/rest/api/3", "", false},
		{"GET", "/ex/jira/" + strings.ToUpper(cloud) + "/rest/api/3/myself", "", false},
		{"GET", "/ex/jira/" + cloud + "%2Frest/api/3/myself", "", false},
		{"GET", "/ex/confluence/" + cloud + "/rest/api/3/myself", "", false},
		{"GET", "/EX/jira/" + cloud + "/rest/api/3/myself", "", false},
		{"GET", base + "/status/..", "", false},
		{"GET", base + "/status/%2E%2E", "", false},
		{"GET", base + "/status/a%20(b)", "", false},
		{"GET", base + "/status/Open%3F", "", false},
		{"GET", base + "/status/%C2%A0Open", "", false},
		{"GET", base + "/status/Op%E2%80%8Ben", "", false},
		{"GET", base + "/project/ABC/role/1%2E0", "", false},
		{"GET", base + "/project/abc/role", "", false},
		{"GET", base + "/project/10000/role", "", false},
		{"get", base + "/myself", "", false},
		{"HEAD", base + "/myself", "", false},
		{"OPTIONS", base + "/myself", "", false},
		{"POST", base + "/issue/ABC-1/comment", `{"body":{},"properties":[]}`, false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC","jql\u0000":"x"}`, false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC","jql":"project = OTHER"}`, false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC","maxResults":1e2}`, false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC","maxResults":100.0}`, false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC","maxResults":-0}`, false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC","maxResults":99999999999999999999}`, false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC","fields":["*all"]}`, false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC","expand":"x"}`, false},
		{"POST", base + "/search/jql", "{\"jql\":\"project = ABC\"}\n", false},
		{"POST", base + "/search/jql", "\uFEFF{\"jql\":\"project = ABC\"}", false},
		{"POST", base + "/search/jql", `{"jql":"project = ABC"}/*x*/`, false},
		{"POST", base + "/issue", `{"fields":{"project":{"key":"ABC","KEY":"OTHER"}}}`, true},
		{"POST", base + "/issue", `{"fields":{"project":{"key":"ABC"},"parent":{"key":"ABC-1"},"parent":{"key":"OTHER-1"}}}`, true},
		{"POST", base + "/issue", `{"fields":{"project":{"key":"ABC"},"issuetype":{"name":"Sub-task"},"parent":{"key":"ABC-1","id":"1"}}}`, true},
		{"POST", base + "/issue", `{"fields":{"project":{"Key":"OTHER"}}}`, true},
		{"POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"Project":{"key":"OTHER"}}}`, true},
		{"POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"customfield_10014":"OTHER-1"}}`, true},
		{"POST", base + "/issue/ABC-1/transitions", `{"transition":{"id":"31"},"fields":{"issuetype":{"id":"1"},"security":{"id":"1"}}}`, true},
		{"PUT", base + "/issue/ABC-1/comment/10001", `{"body":{"type":"doc","version":1,"content":[]}}`, true},
	}
	for _, x := range cases {
		g := ro
		if x.write {
			g = rw
		}
		ct := ""
		if x.body != "" {
			ct = "application/json"
		}
		_, den := Authorize(g, Request{Method: x.method, RequestURI: x.uri, ContentType: ct, Body: []byte(x.body)})
		id := x.method + " " + x.uri
		if x.body != "" {
			id = x.method + " " + x.body
		}
		if allowed := den == nil; allowed != reviewAllowed[id] {
			u := strings.TrimPrefix(x.uri, base)
			if len(u) > 100 {
				u = u[:100] + "..."
			}
			t.Errorf("%s %s %s: allowed=%v", x.method, u, x.body, allowed)
		}
	}
}
