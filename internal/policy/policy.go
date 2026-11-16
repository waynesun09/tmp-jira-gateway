// Package policy is the gateway's endpoint allowlist. Everything not
// listed in routes is denied.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nonflux/tmp-jira-gateway/internal/config"
	"github.com/nonflux/tmp-jira-gateway/internal/jql"
	"github.com/nonflux/tmp-jira-gateway/internal/strictjson"
)

// Denial reasons. Each is a fixed string, safe to return to the caller
// and to log; none carries request or upstream content.
const (
	ReasonPath            = "path not allowed"
	ReasonCloudID         = "cloud id not in grant"
	ReasonEndpoint        = "endpoint not allowed"
	ReasonCommentProperty = "comment property calls are not allowed"
	ReasonProject         = "project not in grant"
	ReasonLevel           = "write grant required"
	ReasonQuery           = "query not allowed"
	ReasonBody            = "request body not allowed"
	ReasonJQL             = "jql outside the accepted grammar"
)

// Denial is a refused request.
type Denial struct{ Reason string }

func (d *Denial) Error() string { return d.Reason }

func deny(reason string) *Denial { return &Denial{Reason: reason} }

// Request is what the policy sees of an incoming call.
type Request struct {
	Method      string
	RequestURI  string // origin form, as received
	ContentType string
	Body        []byte
}

// Decision describes an allowed call. Template is also set on a denial
// once the route is known, for the audit log.
type Decision struct {
	Template     string // for example /ex/jira/{cloudId}/rest/api/3/issue/{key}
	UpstreamPath string // /ex/jira/<cloudId>/rest/api/3/..., re-encoded
	RawQuery     string // validated; forwarded as is
	JQLHash      string // sha256 of the JQL, for search calls
}

// Segment kinds in route patterns.
const (
	pKey     = "{key}"     // issue key, project prefix in grant
	pProject = "{project}" // project key in grant
	pNum     = "{id}"      // numeric id
	pProp    = "{k}"       // entity property key
	pStatus  = "{status}"  // status id or name
)

type bodyKind int

const (
	bodyNone bodyKind = iota
	bodySearch
	bodyCreateIssue
	bodyIssueLink
	bodyComment
	bodyTransition
	bodyEditIssue
	bodyProperty
)

type route struct {
	method  string
	pattern []string
	write   bool
	query   map[string]*regexp.Regexp
	body    bodyKind
}

var (
	reCount   = regexp.MustCompile(`^[0-9]{1,4}$`)
	reOffset  = regexp.MustCompile(`^[0-9]{1,9}$`)
	reCreated = regexp.MustCompile(`^created$`)
	reProps   = regexp.MustCompile(`^properties$`)
	reTrFlds  = regexp.MustCompile(`^transitions\.fields$`)
)

// routes is the contract's allowlist, with the query parameters fullsend
// sends on each call (internal/forge/jira).
var routes = []route{
	{method: http.MethodGet, pattern: []string{"myself"}},
	{method: http.MethodGet, pattern: []string{"status", pStatus}},
	{method: http.MethodGet, pattern: []string{"project", pProject, "role"}},
	{method: http.MethodGet, pattern: []string{"project", pProject, "role", pNum}},
	{method: http.MethodGet, pattern: []string{"issue", pKey}},
	{method: http.MethodGet, pattern: []string{"issue", pKey, "comment"},
		query: map[string]*regexp.Regexp{"orderBy": reCreated, "maxResults": reCount, "startAt": reOffset, "expand": reProps}},
	{method: http.MethodGet, pattern: []string{"issue", pKey, "changelog"},
		query: map[string]*regexp.Regexp{"maxResults": reCount, "startAt": reOffset}},
	{method: http.MethodGet, pattern: []string{"issue", pKey, "transitions"},
		query: map[string]*regexp.Regexp{"expand": reTrFlds}},
	{method: http.MethodGet, pattern: []string{"issue", pKey, "properties", pProp}},
	{method: http.MethodPost, pattern: []string{"search", "jql"}, body: bodySearch},

	{method: http.MethodPost, pattern: []string{"issue", pKey, "comment"}, write: true, body: bodyComment},
	{method: http.MethodPut, pattern: []string{"issue", pKey, "comment", pNum}, write: true, body: bodyComment},
	{method: http.MethodDelete, pattern: []string{"issue", pKey, "comment", pNum}, write: true},
	{method: http.MethodPost, pattern: []string{"issue", pKey, "transitions"}, write: true, body: bodyTransition},
	{method: http.MethodPut, pattern: []string{"issue", pKey, "properties", pProp}, write: true, body: bodyProperty},
	{method: http.MethodDelete, pattern: []string{"issue", pKey, "properties", pProp}, write: true},
	{method: http.MethodPut, pattern: []string{"issue", pKey}, write: true, body: bodyEditIssue},
	{method: http.MethodPost, pattern: []string{"issue"}, write: true, body: bodyCreateIssue},
	{method: http.MethodPost, pattern: []string{"issueLink"}, write: true, body: bodyIssueLink},
}

var (
	issueKeyRe   = regexp.MustCompile(`^([A-Z][A-Z0-9_]+)-[0-9]{1,18}$`)
	projectKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	numRe        = regexp.MustCompile(`^[0-9]{1,18}$`)
	// Property keys: fullsend's keys are dotted names whose repository
	// segments escape "." as a literal "%2E" (sent as %252E).
	propKeyRe = regexp.MustCompile(`^(?:[A-Za-z0-9_.-]|%2E){1,255}$`)
	statusRe  = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}\p{M} ._()-]{0,99}$`)
)

// issueKeyInGrant reports whether s is an issue key whose project is
// granted. Numeric issue ids never match.
func issueKeyInGrant(g *config.Grant, s string) bool {
	m := issueKeyRe.FindStringSubmatch(s)
	return m != nil && g.HasProject(m[1])
}

const templatePrefix = "/ex/jira/{cloudId}/rest/api/3"

// Authorize checks one request against the grant and the allowlist. The
// returned Decision is never nil; on denial it carries the route template
// when one matched.
func Authorize(g *config.Grant, req Request) (*Decision, *Denial) {
	d := &Decision{}
	cloudID, rest, rawQuery, ok := parseRequestURI(req.RequestURI)
	if !ok {
		return d, deny(ReasonPath)
	}
	if cloudID != g.CloudID {
		return d, deny(ReasonCloudID)
	}
	if rest[0].dec == "comment" {
		d.Template = templatePrefix + "/comment/..."
		return d, deny(ReasonCommentProperty)
	}
	r, denial := match(g, req.Method, rest, d)
	if r == nil {
		return d, denial
	}
	if r.write && !g.CanWrite() {
		return d, deny(ReasonLevel)
	}
	q, ok := parseQuery(rawQuery)
	if !ok {
		return d, deny(ReasonQuery)
	}
	for k, v := range q {
		re := r.query[k]
		if re == nil || !re.MatchString(v) {
			return d, deny(ReasonQuery)
		}
	}
	if denial := checkBody(g, r.body, req, d); denial != nil {
		return d, denial
	}
	var b strings.Builder
	b.WriteString("/ex/jira/" + cloudID + "/rest/api/3")
	for _, s := range rest {
		b.WriteString("/" + url.PathEscape(s.dec))
	}
	d.UpstreamPath = b.String()
	d.RawQuery = rawQuery
	return d, nil
}

// match finds the route for method and path. A path whose shape matches
// but whose key is outside the grant is denied with ReasonProject.
func match(g *config.Grant, method string, rest []segment, d *Decision) (*route, *Denial) {
	for i := range routes {
		r := &routes[i]
		if len(r.pattern) != len(rest) {
			continue
		}
		projectDenied, ok := false, true
		for j, p := range r.pattern {
			s := rest[j]
			switch p {
			case pKey:
				if !issueKeyRe.MatchString(s.dec) || s.raw != s.dec {
					ok = false
				} else if !issueKeyInGrant(g, s.dec) {
					projectDenied = true
				}
			case pProject:
				if !projectKeyRe.MatchString(s.dec) || s.raw != s.dec {
					ok = false
				} else if !g.HasProject(s.dec) {
					projectDenied = true
				}
			case pNum:
				ok = ok && numRe.MatchString(s.dec) && s.raw == s.dec
			case pProp:
				ok = ok && propKeyRe.MatchString(s.dec)
			case pStatus:
				ok = ok && statusRe.MatchString(s.dec)
			default:
				ok = ok && s.raw == p
			}
		}
		if !ok {
			continue
		}
		d.Template = templatePrefix + "/" + strings.Join(r.pattern, "/")
		if r.method != method {
			continue
		}
		if projectDenied {
			return nil, deny(ReasonProject)
		}
		return r, nil
	}
	return nil, deny(ReasonEndpoint)
}

// checkBody enforces the body rules for a route: none on GET and DELETE,
// strict JSON with a known shape otherwise.
func checkBody(g *config.Grant, kind bodyKind, req Request, d *Decision) *Denial {
	if kind == bodyNone {
		if len(req.Body) != 0 {
			return deny(ReasonBody)
		}
		return nil
	}
	if mt, params, err := mime.ParseMediaType(req.ContentType); err != nil || mt != "application/json" ||
		(params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		return deny(ReasonBody)
	}
	if kind == bodyProperty {
		// An entity property value may be any JSON value (fullsend stores
		// a bare timestamp string); Jira caps it at 32 KiB.
		if len(req.Body) > 32<<10 {
			return deny(ReasonBody)
		}
		if _, err := strictjson.Parse(req.Body); err != nil {
			return deny(ReasonBody)
		}
		return nil
	}
	obj, err := strictjson.ParseObject(req.Body)
	if err != nil {
		return deny(ReasonBody)
	}
	switch kind {
	case bodySearch:
		return checkSearch(g, obj, d)
	case bodyCreateIssue:
		return checkCreateIssue(g, obj)
	case bodyIssueLink:
		return checkIssueLink(g, obj)
	case bodyComment:
		return checkComment(obj)
	case bodyTransition:
		return checkTransition(obj)
	case bodyEditIssue:
		return checkEditIssue(obj)
	}
	return deny(ReasonBody)
}

// onlyKeys reports whether every key of m is in allowed.
func onlyKeys(m map[string]any, allowed ...string) bool {
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// exactlyKey returns m[key] as a string when m is an object holding only
// that key.
func exactlyKey(v any, key string) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return "", false
	}
	s, ok := m[key].(string)
	return s, ok
}

var searchFieldRe = regexp.MustCompile(`^\*?[A-Za-z0-9_.-]{1,64}$`)

func checkSearch(g *config.Grant, obj map[string]any, d *Decision) *Denial {
	// Unknown keys are refused: reconcileIssues, for example, would add
	// issues by id outside the query.
	if !onlyKeys(obj, "jql", "maxResults", "fields", "nextPageToken") {
		return deny(ReasonBody)
	}
	q, ok := obj["jql"].(string)
	if !ok {
		return deny(ReasonBody)
	}
	if v, present := obj["maxResults"]; present {
		n, ok := v.(json.Number)
		if !ok {
			return deny(ReasonBody)
		}
		i, err := n.Int64()
		if err != nil || i < 0 || i > 100 {
			return deny(ReasonBody)
		}
	}
	if v, present := obj["fields"]; present {
		arr, ok := v.([]any)
		if !ok || len(arr) > 50 {
			return deny(ReasonBody)
		}
		for _, f := range arr {
			s, ok := f.(string)
			if !ok || !searchFieldRe.MatchString(s) {
				return deny(ReasonBody)
			}
		}
	}
	if v, present := obj["nextPageToken"]; present {
		s, ok := v.(string)
		if !ok || len(s) > 4096 {
			return deny(ReasonBody)
		}
	}
	sum := sha256.Sum256([]byte(q))
	d.JQLHash = hex.EncodeToString(sum[:])
	if _, err := jql.Validate(q, g.ProjectSet()); err != nil {
		return deny(ReasonJQL)
	}
	return nil
}

func checkCreateIssue(g *config.Grant, obj map[string]any) *Denial {
	if len(obj) != 1 {
		return deny(ReasonBody)
	}
	fields, ok := obj["fields"].(map[string]any)
	if !ok || !onlyKeys(fields, "project", "issuetype", "summary", "parent", "description") {
		return deny(ReasonBody)
	}
	key, ok := exactlyKey(fields["project"], "key")
	if !ok || !projectKeyRe.MatchString(key) {
		return deny(ReasonBody)
	}
	if !g.HasProject(key) {
		return deny(ReasonProject)
	}
	if p, present := fields["parent"]; present {
		pk, ok := exactlyKey(p, "key")
		if !ok || !issueKeyRe.MatchString(pk) {
			return deny(ReasonBody)
		}
		if !issueKeyInGrant(g, pk) {
			return deny(ReasonProject)
		}
	}
	if it, present := fields["issuetype"]; present {
		_, byID := exactlyKey(it, "id")
		_, byName := exactlyKey(it, "name")
		if !byID && !byName {
			return deny(ReasonBody)
		}
	}
	if s, present := fields["summary"]; present {
		if _, ok := s.(string); !ok {
			return deny(ReasonBody)
		}
	}
	if desc, present := fields["description"]; present {
		if _, ok := desc.(map[string]any); !ok {
			return deny(ReasonBody)
		}
	}
	return nil
}

func checkIssueLink(g *config.Grant, obj map[string]any) *Denial {
	if len(obj) != 3 || !onlyKeys(obj, "type", "inwardIssue", "outwardIssue") {
		return deny(ReasonBody)
	}
	if _, ok := exactlyKey(obj["type"], "name"); !ok {
		return deny(ReasonBody)
	}
	for _, side := range []string{"inwardIssue", "outwardIssue"} {
		k, ok := exactlyKey(obj[side], "key")
		if !ok || !issueKeyRe.MatchString(k) {
			return deny(ReasonBody)
		}
		if !issueKeyInGrant(g, k) {
			return deny(ReasonProject)
		}
	}
	return nil
}

// checkComment allows the top-level keys body and properties (either or
// both) and nothing else.
func checkComment(obj map[string]any) *Denial {
	if len(obj) == 0 || !onlyKeys(obj, "body", "properties") {
		return deny(ReasonBody)
	}
	if b, present := obj["body"]; present {
		if _, ok := b.(map[string]any); !ok {
			return deny(ReasonBody)
		}
	}
	if p, present := obj["properties"]; present {
		if _, ok := p.([]any); !ok {
			return deny(ReasonBody)
		}
	}
	return nil
}

// transitionFieldsDenied are fields that could tie the issue to another
// project or issue; a transition screen has no need for them.
var transitionFieldsDenied = map[string]bool{"project": true, "parent": true, "issuelinks": true}

func checkTransition(obj map[string]any) *Denial {
	if !onlyKeys(obj, "transition", "fields", "update") {
		return deny(ReasonBody)
	}
	id, ok := exactlyKey(obj["transition"], "id")
	if !ok || !numRe.MatchString(id) {
		return deny(ReasonBody)
	}
	if f, present := obj["fields"]; present {
		fm, ok := f.(map[string]any)
		if !ok {
			return deny(ReasonBody)
		}
		for k := range fm {
			if transitionFieldsDenied[strings.ToLower(k)] {
				return deny(ReasonBody)
			}
		}
	}
	if u, present := obj["update"]; present {
		um, ok := u.(map[string]any)
		if !ok || !onlyKeys(um, "comment") {
			return deny(ReasonBody)
		}
	}
	return nil
}

// checkEditIssue allows only label adds and removes, the one edit fullsend
// makes: {"update":{"labels":[{"add":"x"},{"remove":"y"}]}}.
func checkEditIssue(obj map[string]any) *Denial {
	if len(obj) != 1 {
		return deny(ReasonBody)
	}
	u, ok := obj["update"].(map[string]any)
	if !ok || len(u) != 1 {
		return deny(ReasonBody)
	}
	labels, ok := u["labels"].([]any)
	if !ok || len(labels) == 0 {
		return deny(ReasonBody)
	}
	for _, op := range labels {
		_, add := exactlyKey(op, "add")
		_, remove := exactlyKey(op, "remove")
		if !add && !remove {
			return deny(ReasonBody)
		}
	}
	return nil
}
