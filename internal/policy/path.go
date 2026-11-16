package policy

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// segment is one path segment: as sent, and percent-decoded once.
type segment struct {
	raw, dec string
}

var cloudIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// parseRequestURI splits an origin-form request URI into the cloud id,
// the segments after /rest/api/3 and the raw query. It refuses anything
// that is not already in clean form, rather than cleaning it: empty
// segments (// and a trailing slash), dot segments in any encoding,
// encoded slashes and backslashes, control characters and invalid
// percent-encoding or UTF-8.
func parseRequestURI(uri string) (cloudID string, rest []segment, rawQuery string, ok bool) {
	if !strings.HasPrefix(uri, "/") || strings.ContainsAny(uri, "#\\") {
		return "", nil, "", false
	}
	path, rawQuery, _ := strings.Cut(uri, "?")
	parts := strings.Split(path[1:], "/")
	segs := make([]segment, 0, len(parts))
	for _, raw := range parts {
		if raw == "" {
			return "", nil, "", false
		}
		dec, err := url.PathUnescape(raw)
		if err != nil || dec == "." || dec == ".." || !utf8.ValidString(dec) {
			return "", nil, "", false
		}
		for i := 0; i < len(dec); i++ {
			if c := dec[i]; c < 0x20 || c == 0x7f || c == '/' || c == '\\' {
				return "", nil, "", false
			}
		}
		segs = append(segs, segment{raw: raw, dec: dec})
	}
	// /ex/jira/{cloudId}/rest/api/3/<at least one segment>; the fixed
	// segments must be sent literally, not percent-encoded.
	want := []string{"ex", "jira", "", "rest", "api", "3"}
	if len(segs) < len(want)+1 {
		return "", nil, "", false
	}
	for i, w := range want {
		if i == 2 {
			continue
		}
		if segs[i].raw != w {
			return "", nil, "", false
		}
	}
	if segs[2].raw != segs[2].dec || !cloudIDRe.MatchString(segs[2].dec) {
		return "", nil, "", false
	}
	return segs[2].dec, segs[len(want):], rawQuery, true
}

var queryTokenRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// parseQuery splits a raw query into key/value pairs. Keys and values are
// limited to [A-Za-z0-9_.-], so nothing in them needs decoding, and every
// key may appear once.
func parseQuery(raw string) (map[string]string, bool) {
	out := map[string]string{}
	if raw == "" {
		return out, true
	}
	for _, kv := range strings.Split(raw, "&") {
		k, v, found := strings.Cut(kv, "=")
		if !found || !queryTokenRe.MatchString(k) || !queryTokenRe.MatchString(v) {
			return nil, false
		}
		if _, dup := out[k]; dup {
			return nil, false
		}
		out[k] = v
	}
	return out, true
}
