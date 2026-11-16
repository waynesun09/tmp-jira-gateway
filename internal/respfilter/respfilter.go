// Package respfilter removes issue fields that point at other issues from
// Jira responses: parent, subtasks and issuelinks. They can name issues in
// projects outside the grant, and fullsend does not read them.
package respfilter

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/nonflux/tmp-jira-gateway/internal/strictjson"
)

// ErrUndecodable is returned for a body the filter cannot parse; callers
// fail closed.
var ErrUndecodable = errors.New("response not decodable")

// Removed lists the stripped field names.
var Removed = []string{"parent", "subtasks", "issuelinks"}

// Issue strips one issue object (GET /issue/{key}).
func Issue(body []byte) ([]byte, error) {
	obj, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrUndecodable
	}
	stripIssue(obj)
	return encode(obj)
}

// Search strips every element of issues[] (POST /search/jql).
func Search(body []byte) ([]byte, error) {
	obj, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrUndecodable
	}
	if raw, present := obj["issues"]; present {
		issues, ok := raw.([]any)
		if !ok {
			return nil, ErrUndecodable
		}
		for _, it := range issues {
			m, ok := it.(map[string]any)
			if !ok {
				return nil, ErrUndecodable
			}
			stripIssue(m)
		}
	}
	return encode(obj)
}

// stripIssue removes the fields from "fields" and, if present, from
// "renderedFields".
func stripIssue(issue map[string]any) {
	for _, section := range []string{"fields", "renderedFields"} {
		if f, ok := issue[section].(map[string]any); ok {
			for _, k := range Removed {
				delete(f, k)
			}
		}
	}
}

func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, ErrUndecodable
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
