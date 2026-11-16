package strictjson

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAccepted(t *testing.T) {
	for _, s := range []string{
		`{}`,
		`{"a":1}`,
		`{"a":{"b":[1,2,{"c":"d"}]},"e":null}`,
		` {"jql":"x","maxResults":50} `,
		`"2026-11-16T10:00:00Z"`,
		`[1,2]`,
		`{"a":{"x":1},"b":{"x":2}}`, // the same key in sibling objects
		`{"a":"ü"}`,
	} {
		if _, err := Parse([]byte(s)); err != nil {
			t.Errorf("Parse(%s) = %v, want accepted", s, err)
		}
	}
}

func TestRejected(t *testing.T) {
	for _, s := range []string{
		``,
		` `,
		`{"a":1,"a":2}`,
		`{"jql":"x","jql":"y"}`,
		`{"fields":{"project":{"key":"A"},"project":{"key":"B"}}}`,
		`{"fields":{"project":{"key":"A","key":"B"}}}`,
		`{"a":[{"b":1,"b":2}]}`,
		`{"project":1,"Project":2}`,      // ASCII case variant
		`{"project":1,"pro\u006aect":2}`, // escaped duplicate
		`{"a":1} {"a":2}`,
		`{"a":1}x`,
		`{"a":1},`,
		`{"a":1`,
		`{"a":}`,
		`{a:1}`,
		`{"a":1,}`,
		"{\"a\":\"\xff\"}",
		strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
	} {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("Parse(%q) accepted, want refused", s)
		}
	}
}

func TestParseObject(t *testing.T) {
	for _, s := range []string{`[]`, `"x"`, `1`, `null`, `true`} {
		if _, err := ParseObject([]byte(s)); err == nil {
			t.Errorf("ParseObject(%s) accepted a non-object", s)
		}
	}
	m, err := ParseObject([]byte(`{"a":{"b":"c"}}`))
	if err != nil || m["a"].(map[string]any)["b"] != "c" {
		t.Fatalf("ParseObject: %v %v", m, err)
	}
}

// hasDupKeys reports duplicate keys (ASCII-case-insensitive) in a decoded
// tree built by an independent, slower route: decoding every object into
// a list of raw key/value pairs.
func hasDupKeys(t *testing.T, data []byte) bool {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var walk func() bool
	walk = func() bool {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return false
		}
		dup := false
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, _ := dec.Token()
				k := strings.Map(func(r rune) rune {
					if r >= 'A' && r <= 'Z' {
						return r + 32
					}
					return r
				}, kt.(string))
				if seen[k] {
					dup = true
				}
				seen[k] = true
				if walk() {
					dup = true
				}
			}
			dec.Token()
		case '[':
			for dec.More() {
				if walk() {
					dup = true
				}
			}
			dec.Token()
		}
		return dup
	}
	return walk()
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":1,"a":2}`, `{"a":[{"b":1}]}`, `{"a":1} {}`, `{"A":1,"a":2}`, `"x"`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := Parse(data); err != nil {
			return
		}
		if !json.Valid(data) {
			t.Fatalf("accepted invalid JSON %q", data)
		}
		if hasDupKeys(t, data) {
			t.Fatalf("accepted duplicate keys %q", data)
		}
	})
}
