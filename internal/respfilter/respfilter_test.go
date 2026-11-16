package respfilter

import (
	"strings"
	"testing"
)

func TestIssue(t *testing.T) {
	out, err := Issue([]byte(`{"key":"ABC-1","fields":{"parent":{"key":"X-1"},"subtasks":[1],"issuelinks":[2],"summary":"a<b"},"renderedFields":{"issuelinks":"x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != `{"fields":{"summary":"a<b"},"key":"ABC-1","renderedFields":{}}` {
		t.Fatalf("got %s", got)
	}
	// No fields at all is fine.
	if _, err := Issue([]byte(`{"key":"ABC-1"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestSearch(t *testing.T) {
	out, err := Search([]byte(`{"issues":[{"fields":{"parent":{"key":"X-1"}}},{"fields":{"subtasks":[{"key":"X-2"}]}}],"nextPageToken":"n","isLast":false}`))
	if err != nil || strings.Contains(string(out), "X-") || !strings.Contains(string(out), `"nextPageToken":"n"`) {
		t.Fatalf("%s %v", out, err)
	}
	if _, err := Search([]byte(`{"isLast":true}`)); err != nil {
		t.Fatal(err)
	}
}

func TestUndecodable(t *testing.T) {
	for _, b := range []string{``, `x`, `[]`, `{"a":1,"a":2}`, `{"a":1} {}`} {
		if _, err := Issue([]byte(b)); err != ErrUndecodable {
			t.Errorf("Issue(%q) = %v", b, err)
		}
	}
	for _, b := range []string{`{"issues":{}}`, `{"issues":["x"]}`} {
		if _, err := Search([]byte(b)); err != ErrUndecodable {
			t.Errorf("Search(%q) = %v", b, err)
		}
	}
}
