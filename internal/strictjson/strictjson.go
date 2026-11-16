// Package strictjson parses request bodies so that the gateway and Jira
// cannot read the same bytes differently.
//
// It refuses invalid UTF-8, duplicate object keys at any depth (also keys
// that differ only in ASCII case, because Go's encoding/json matches
// struct fields case-insensitively), trailing data after the top-level
// value, and nesting deeper than MaxDepth.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// MaxDepth bounds object and array nesting.
const MaxDepth = 64

// ErrInvalid is returned for every refused body.
var ErrInvalid = errors.New("invalid request body")

// Parse checks data and decodes it into generic values (map[string]any,
// []any, string, json.Number, bool, nil). Callers read fields from the
// maps, which match keys exactly.
func Parse(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, ErrInvalid
	}
	if err := check(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, ErrInvalid
	}
	return v, nil
}

// ParseObject is Parse for bodies whose top level must be an object.
func ParseObject(data []byte) (map[string]any, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	return m, nil
}

// check walks the token stream and enforces the rules above.
func check(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	// Each frame is an open container: an object's key set, or nil for
	// an array. expectKey tracks whether the next string in an object is
	// a key.
	type frame struct {
		keys      map[string]struct{}
		expectKey bool
	}
	var stack []*frame
	seenTop := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if !seenTop || len(stack) != 0 {
				return ErrInvalid
			}
			return nil
		}
		if err != nil {
			return ErrInvalid
		}
		if len(stack) == 0 {
			if seenTop {
				return ErrInvalid // trailing data
			}
			seenTop = true
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.keys != nil && top.expectKey {
			// Inside an object, a key or the closing brace.
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				continue
			}
			k, ok := tok.(string)
			if !ok {
				return ErrInvalid
			}
			folded := asciiOnlyLower(k)
			if _, dup := top.keys[folded]; dup {
				return ErrInvalid
			}
			top.keys[folded] = struct{}{}
			top.expectKey = false
			continue
		}
		if top != nil && top.keys != nil {
			top.expectKey = true // this token is the value; next is a key
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				stack = append(stack, &frame{keys: map[string]struct{}{}, expectKey: true})
			case '[':
				stack = append(stack, &frame{})
			case ']':
				if top == nil || top.keys != nil {
					return ErrInvalid
				}
				stack = stack[:len(stack)-1]
			default:
				return ErrInvalid
			}
			if len(stack) > MaxDepth {
				return ErrInvalid
			}
		}
	}
}

// asciiOnlyLower folds ASCII letters only. Non-ASCII runes are kept, so
// two keys collide only when they differ in ASCII case.
func asciiOnlyLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c - 'A' + 'a'
		}
	}
	return string(b)
}
