package respfilter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestIssue(t *testing.T) {
	out, key, err := Issue([]byte(`{"key":"ABC-1","fields":{"parent":{"key":"X-1"},"subtasks":[1],"issuelinks":[2],"summary":"a<b"},"renderedFields":{"issuelinks":"x"}}`))
	if err != nil || key != "ABC-1" {
		t.Fatal(key, err)
	}
	if got := string(out); got != `{"key":"ABC-1","fields":{"summary":"a<b"},"renderedFields":{}}` {
		t.Fatalf("got %s", got)
	}
	if _, key, err := Issue([]byte(`{"id":"1"}`)); err != nil || key != "" {
		t.Fatal(key, err)
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

func TestChangelog(t *testing.T) {
	page := func(startAt int, last bool) string {
		return fmt.Sprintf(`{"startAt":%d,"maxResults":2,"total":4,"isLast":%v,"values":[
		  {"id":"%d","author":{"accountId":"a"},"created":"2026-01-01","items":[
		    {"field":"status","fieldtype":"jira","from":"1","to":"3"},
		    {"field":"Link","fieldtype":"jira","to":"OTHER-1"},
		    {"field":"labels","fromString":"a","toString":"a b"},
		    {"field":"Status","to":"x"},
		    {"field":"customfield_1","toString":"OTHER-2"}]},
		  {"id":"%d","created":"2026-01-02","items":[{"field":"parent","toString":"OTHER-3"},{"field":"IssueParentAssociation"}]}]}`,
			startAt, last, startAt+100, startAt+101)
	}
	for i, p := range []string{page(0, false), page(2, true)} {
		out, err := Changelog([]byte(p))
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			StartAt, MaxResults, Total int
			IsLast                     bool
			Values                     []struct {
				ID      string
				Author  map[string]any
				Created string
				Items   []struct{ Field string }
			}
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		if got.StartAt != i*2 || got.MaxResults != 2 || got.Total != 4 || got.IsLast != (i == 1) {
			t.Fatalf("page %d paging changed: %+v", i, got)
		}
		if len(got.Values) != 2 {
			t.Fatalf("page %d: %d entries, want 2 (emptied entries stay)", i, len(got.Values))
		}
		e0, e1 := got.Values[0], got.Values[1]
		if e0.ID != fmt.Sprint(i*2+100) || e0.Author["accountId"] != "a" || e0.Created != "2026-01-01" {
			t.Fatalf("entry members changed: %+v", e0)
		}
		if len(e0.Items) != 2 || e0.Items[0].Field != "status" || e0.Items[1].Field != "labels" {
			t.Fatalf("items %+v", e0.Items)
		}
		if e1.Items == nil || len(e1.Items) != 0 {
			t.Fatalf("emptied entry items %+v", e1.Items)
		}
		if strings.Contains(string(out), "OTHER") {
			t.Fatalf("page %d leaks: %s", i, out)
		}
	}
	if _, err := Changelog([]byte(`{"values":[{"id":"1"}],"isLast":true}`)); err != nil {
		t.Fatal("entry without items:", err)
	}
	for _, b := range []string{`{"values":{}}`, `{"values":["x"]}`, `{"values":[{"items":{}}]}`, `{"values":[{"items":["x"]}]}`, `x`} {
		if _, err := Changelog([]byte(b)); err != ErrUndecodable {
			t.Errorf("Changelog(%q) = %v", b, err)
		}
	}
}

func TestDecoder(t *testing.T) {
	// Response keys that differ only in case are legitimate.
	if _, _, err := Issue([]byte(`{"key":"ABC-1","fields":{"Sprint":1,"sprint":2}}`)); err != nil {
		t.Fatal("case-variant keys refused:", err)
	}
	deep := func(n int) string {
		return `{"key":"ABC-1","fields":{"customfield_1":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}}`
	}
	if _, _, err := Issue([]byte(deep(200))); err != nil {
		t.Fatal("depth 200 refused:", err)
	}
	if _, _, err := Issue([]byte(deep(MaxDepth))); err != ErrUndecodable {
		t.Fatal("depth over the limit accepted")
	}
	for _, b := range []string{``, `x`, `[]`, `{"a":1,"a":2}`, `{"fields":{"a":1,"a":2}}`, `{"a":1} {}`, "{\"a\":\"\xff\"}"} {
		if _, _, err := Issue([]byte(b)); err != ErrUndecodable {
			t.Errorf("Issue(%q) = %v", b, err)
		}
	}
	for _, b := range []string{`{"issues":{}}`, `{"issues":["x"]}`} {
		if _, err := Search([]byte(b)); err != ErrUndecodable {
			t.Errorf("Search(%q) = %v", b, err)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2, 50*time.Millisecond)
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	var busy atomic.Int32
	release := make(chan struct{})
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := l.Do(context.Background(), func() error {
				n := running.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				<-release
				running.Add(-1)
				return nil
			})
			if err == ErrBusy {
				busy.Add(1)
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()
	if peak.Load() != 2 || busy.Load() != 3 {
		t.Fatalf("peak %d, busy %d; want 2 and 3", peak.Load(), busy.Load())
	}
}

// MaxCopies is the documented memory cost of filtering one body: bytes
// allocated while filtering, as a multiple of the body size. render.py
// budgets with the same factor.
const MaxCopies = 12

// realisticPage builds a search page close to size bytes: issues with long
// ADF descriptions, labels, links and custom fields, as "*all" returns.
func realisticPage(size int) []byte {
	para := func(i int) string {
		return fmt.Sprintf(`{"type":"paragraph","content":[{"type":"text","text":"Line %d of a long description with some words in it, repeated to look like a real ticket body."},{"type":"text","text":" bold","marks":[{"type":"strong"}]}]}`, i)
	}
	var paras []string
	for i := 0; i < 40; i++ {
		paras = append(paras, para(i))
	}
	desc := `{"type":"doc","version":1,"content":[` + strings.Join(paras, ",") + `]}`
	var b strings.Builder
	b.WriteString(`{"isLast":false,"nextPageToken":"tok","issues":[`)
	for i := 0; b.Len() < size-12000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id":"%d","key":"ABC-%d","self":"https://api.atlassian.com/ex/jira/c/rest/api/3/issue/%d","fields":{"summary":"Issue %d","status":{"name":"Open","statusCategory":{"key":"new"}},"labels":["a","b","fullsend"],"assignee":{"accountId":"557058:0b6d5c34-1f2e-4a5b-8c9d-0e1f2a3b4c5d","displayName":"Someone"},"created":"2026-01-01T00:00:00.000+0000","updated":"2026-01-02T00:00:00.000+0000","project":{"id":"10000","key":"ABC"},"issuetype":{"name":"Task"},"parent":{"key":"OTHER-%d"},"subtasks":[{"key":"OTHER-%d"}],"issuelinks":[{"outwardIssue":{"key":"OTHER-%d"}}],"customfield_10001":12345.5,"description":%s}}`,
			10000+i, i+1, 10000+i, i, i, i, i, desc)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

// TestStripMemoryBudget pushes a maximum-size realistic page (3 MiB, the
// deploy default) through the search strip with the garbage collector
// off, so the bytes allocated bound the peak heap, and asserts they stay
// within MaxCopies times the body.
func TestStripMemoryBudget(t *testing.T) {
	const size = 3 << 20
	body := realisticPage(size)
	if len(body) < size*9/10 || len(body) > size {
		t.Fatalf("page is %d bytes", len(body))
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out, err := Search(body)
	runtime.ReadMemStats(&after)
	if err != nil || strings.Contains(string(out), "OTHER-") {
		t.Fatal(err)
	}
	alloc := after.TotalAlloc - before.TotalAlloc
	ratio := float64(alloc) / float64(len(body))
	t.Logf("body %d bytes, allocated %d bytes while filtering (%.1fx)", len(body), alloc, ratio)
	if ratio > MaxCopies {
		t.Fatalf("filtering allocated %.1fx the body, over the %dx budget", ratio, MaxCopies)
	}
}

// oracleOK reports, with the standard library only, whether data is
// valid UTF-8 and one valid JSON value with no exact duplicate keys and depth <= MaxDepth.
func oracleOK(data []byte) bool {
	if !utf8.Valid(data) || !json.Valid(data) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func(depth int) bool
	walk = func(depth int) bool {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return true
		}
		if depth >= MaxDepth {
			return false
		}
		seen := map[string]bool{}
		for dec.More() {
			if d == '{' {
				kt, _ := dec.Token()
				k := kt.(string)
				if seen[k] {
					return false
				}
				seen[k] = true
			}
			if !walk(depth + 1) {
				return false
			}
		}
		_, err = dec.Token()
		return err == nil
	}
	if !walk(0) {
		return false
	}
	_, err := dec.Token()
	return err == io.EOF
}

// expectSearch applies the search strip with encoding/json, for
// comparison.
func expectSearch(data []byte) (any, bool) {
	var v any
	if json.Unmarshal(data, &v) != nil {
		return nil, false
	}
	top, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	if raw, present := top["issues"]; present {
		issues, ok := raw.([]any)
		if !ok {
			return nil, false
		}
		for _, it := range issues {
			m, ok := it.(map[string]any)
			if !ok {
				return nil, false
			}
			for _, sec := range []string{"fields", "renderedFields"} {
				if f, ok := m[sec].(map[string]any); ok {
					delete(f, "parent")
					delete(f, "subtasks")
					delete(f, "issuelinks")
				}
			}
		}
	}
	return top, true
}

func FuzzSearchFilter(f *testing.F) {
	for _, s := range []string{
		`{"issues":[{"fields":{"parent":{"key":"X-1"},"a":1}}]}`,
		`{"issues":[],"isLast":true}`,
		`{"a":1,"a":2}`,
		`{"a":{"b":1,"B":2}}`,
		`{"issues":[{"fields":null,"renderedFields":{"subtasks":[]}}]}`,
		` {"issues" : [ { "fields" : { "issuelinks" : [ ] , "x" : "\u0041\"" } } ] } `,
		`{"issues":[{"fields":{"pare\u006et":1}}]}`,
		`[1]`,
		`{"issues":{}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := Search(data)
		want, shapeOK := expectSearch(data)
		if err != nil {
			if oracleOK(data) && shapeOK {
				t.Fatalf("refused a valid, duplicate-free body %q", data)
			}
			return
		}
		if !oracleOK(data) || !shapeOK {
			t.Fatalf("accepted %q", data)
		}
		var got any
		if json.Unmarshal(out, &got) != nil {
			t.Fatalf("output %q is not JSON", out)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("filtered %q to %q, want %v", data, out, want)
		}
	})
}
