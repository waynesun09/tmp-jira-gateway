// Package respfilter removes data that points at other issues from Jira
// responses fullsend reads:
//
//   - issue and search responses lose fields.parent, subtasks and
//     issuelinks;
//   - changelog responses keep only history items for labels and status
//     (the only ones fullsend reads), and keep every entry so that
//     startAt-based paging does not shift.
//
// A body the filter cannot decode is refused; callers fail closed.
package respfilter

import (
	"context"
	"errors"
	"time"
)

// ErrUndecodable is returned for a body the filter cannot parse.
var ErrUndecodable = errors.New("response not decodable")

// ErrBusy is returned when no filter slot frees up in time.
var ErrBusy = errors.New("response filter busy")

// changelogFields are the only history item fields that pass.
var changelogFields = map[string]bool{"labels": true, "status": true}

// Limiter bounds how many bodies are decoded at once: a decoded tree is
// several times the size of the body, so unbounded filtering could run
// the instance out of memory.
type Limiter struct {
	slots chan struct{}
	wait  time.Duration
}

// NewLimiter allows n concurrent filters; a caller waits up to wait for a
// slot, then gets ErrBusy.
func NewLimiter(n int, wait time.Duration) *Limiter {
	return &Limiter{slots: make(chan struct{}, n), wait: wait}
}

// Do runs f in a slot.
func (l *Limiter) Do(ctx context.Context, f func() error) error {
	t := time.NewTimer(l.wait)
	defer t.Stop()
	select {
	case l.slots <- struct{}{}:
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return ErrBusy
	}
	defer func() { <-l.slots }()
	return f()
}

var (
	// fieldsRule drops the cross-issue fields from a "fields" object.
	fieldsRule = &rule{drop: map[string]bool{"parent": true, "subtasks": true, "issuelinks": true}}
	issueRule  = &rule{must: true, captureKey: true, members: map[string]*rule{"fields": fieldsRule, "renderedFields": fieldsRule}}
	searchRule = &rule{must: true, members: map[string]*rule{
		"issues": {must: true, elems: &rule{must: true, members: map[string]*rule{"fields": fieldsRule, "renderedFields": fieldsRule}}},
	}}
	changelogRule = &rule{must: true, members: map[string]*rule{
		"values": {must: true, elems: &rule{must: true, members: map[string]*rule{
			"items": {must: true, keep: keepChangelogItem},
		}}},
	}}
)

// keepChangelogItem keeps an item whose "field" is exactly labels or
// status.
func keepChangelogItem(item []byte) (bool, error) {
	f, _, err := topField(item, "field")
	if err != nil {
		return false, err
	}
	return changelogFields[f], nil
}

// Issue strips one issue object (GET /issue/{key}) and returns its key,
// so the caller can check it against the requested key.
func Issue(body []byte) ([]byte, string, error) {
	return filter(body, issueRule)
}

// Search strips every element of issues[] (POST /search/jql).
func Search(body []byte) ([]byte, error) {
	out, _, err := filter(body, searchRule)
	return out, err
}

// Changelog keeps, in every values[] entry, only the items whose field is
// exactly "labels" or "status". Entries are kept even when emptied, and
// startAt, maxResults, total and isLast are untouched.
func Changelog(body []byte) ([]byte, error) {
	out, _, err := filter(body, changelogRule)
	return out, err
}

// TopStrings validates body like the filters do (exact duplicate keys,
// depth MaxDepth) and returns the top-level string members named. A
// missing or non-string member is absent from the map.
func TopStrings(body []byte, names ...string) (map[string]string, error) {
	if _, _, err := filter(body, &rule{must: true, members: map[string]*rule{}}); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, n := range names {
		if v, ok, err := topField(body, n); err != nil {
			return nil, err
		} else if ok {
			out[n] = v
		}
	}
	return out, nil
}
