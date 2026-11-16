package config

import (
	"strings"
	"testing"
)

const good = `{
  "audience": "fullsend-jira-gateway-dev",
  "read_client_id_file": "/r/id", "read_client_secret_file": "/r/secret",
  "grants": [{"repository":"org/repo","repository_id":"1","repository_owner_id":"2","cloudId":"abc-123","level":"read","projects":["ABC"]}]
}`

func TestParseGood(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != DefaultIssuer || c.UpstreamBaseURL != DefaultUpstreamBaseURL || c.TokenURL != DefaultTokenURL {
		t.Fatalf("defaults not applied: %+v", c)
	}
	g := c.Lookup("org/repo")
	if g == nil || !g.HasProject("ABC") || g.HasProject("abc") || g.CanWrite() {
		t.Fatalf("grant = %+v", g)
	}
	if c.Lookup("org/other") != nil {
		t.Fatal("unknown repository found")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"no audience":         strings.Replace(good, `"audience": "fullsend-jira-gateway-dev",`, "", 1),
		"unknown field":       strings.Replace(good, `"audience"`, `"audiance": "x", "audience"`, 1),
		"duplicate key":       strings.Replace(good, `"audience"`, `"audience": "x", "audience"`, 1),
		"http issuer":         strings.Replace(good, `"audience"`, `"issuer": "http://example.com", "audience"`, 1),
		"bad level":           strings.Replace(good, `"level":"read"`, `"level":"admin"`, 1),
		"numeric id":          strings.Replace(good, `"repository_id":"1"`, `"repository_id":1`, 1),
		"lowercase project":   strings.Replace(good, `["ABC"]`, `["abc"]`, 1),
		"no projects":         strings.Replace(good, `["ABC"]`, `[]`, 1),
		"bad cloud id":        strings.Replace(good, `"abc-123"`, `"abc/123"`, 1),
		"bad repository":      strings.Replace(good, `"org/repo"`, `"repo"`, 1),
		"write without files": strings.Replace(good, `"level":"read"`, `"level":"write"`, 1),
		"read without files":  strings.Replace(good, `"read_client_id_file": "/r/id", `, "", 1),
		"no grants":           `{"audience":"a","grants":[]}`,
		"trailing data":       good + ` {}`,
		"big skew":            strings.Replace(good, `"audience"`, `"clock_skew_seconds": 600, "audience"`, 1),
		"duplicate grant": strings.Replace(good, `]
}`, `,{"repository":"org/repo","repository_id":"3","repository_owner_id":"2","cloudId":"abc-123","level":"read","projects":["ABC"]}]
}`, 1),
	}
	for name, s := range cases {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPreflightCacheSeconds(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil || *c.PreflightCacheSeconds != DefaultPreflightCache || c.MaxResponseBytes != DefaultMaxResponseBytes {
		t.Fatalf("defaults: %v %v", c, err)
	}
	c, err = Parse([]byte(strings.Replace(good, `"audience"`, `"preflight_cache_seconds": 0, "audience"`, 1)))
	if err != nil || *c.PreflightCacheSeconds != 0 {
		t.Fatalf("0 should disable the cache: %v", err)
	}
	for _, v := range []string{"-1", "3601", `"60"`} {
		if _, err := Parse([]byte(strings.Replace(good, `"audience"`, `"preflight_cache_seconds": `+v+`, "audience"`, 1))); err == nil {
			t.Errorf("preflight_cache_seconds %s accepted", v)
		}
	}
}
