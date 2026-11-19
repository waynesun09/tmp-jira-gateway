// Package policy is the gateway's endpoint allowlist. Everything not
// listed in routes is denied.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/waynesun09/tmp-jira-gateway/internal/apierr"
	"github.com/waynesun09/tmp-jira-gateway/internal/config"
	"github.com/waynesun09/tmp-jira-gateway/internal/jql"
	"github.com/waynesun09/tmp-jira-gateway/internal/strictjson"
)

// Denial reasons, for the audit log. The caller sees only the apierr
// value each one maps to, so grant refusals of every kind look the same.
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
	ReasonJQLProject      = "jql names a project outside the grant"
	ReasonPropertyKey     = "issue property key not in the caller's namespace"
)

var reasonErr = map[string]apierr.E{
	ReasonPath:            apierr.EndpointNotAllowed,
	ReasonCloudID:         apierr.NotGranted,
	ReasonEndpoint:        apierr.EndpointNotAllowed,
	ReasonCommentProperty: apierr.EndpointNotAllowed,
	ReasonProject:         apierr.NotGranted,
	ReasonLevel:           apierr.NotGranted,
	ReasonQuery:           apierr.QueryNotAllowed,
	ReasonBody:            apierr.BodyNotAllowed,
	ReasonJQL:             apierr.JQLGrammar,
	ReasonJQLProject:      apierr.NotGranted,
	ReasonPropertyKey:     apierr.NotGranted,
}

// Denial is a refused request: Reason for the log, Err for the caller.
type Denial struct {
	Reason string
	Err    apierr.E
}

func (d *Denial) Error() string { return d.Reason }

func deny(reason string) *Denial { return &Denial{Reason: reason, Err: reasonErr[reason]} }

// Request is what the policy sees of an incoming call.
type Request struct {
	Method      string
	RequestURI  string // origin form, as received
	ContentType string
	Body        []byte
}

// Strip names the response filter an allowed call needs.
type Strip int

const (
	StripNone      Strip = iota
	StripIssue           // GET /issue/{key}: remove fields.parent, subtasks, issuelinks
	StripSearch          // POST /search/jql: the same on every issues[] element
	StripChangelog       // GET /issue/{key}/changelog: keep only labels and status items
)

// Decision describes an allowed call. Template is also set on a denial
// once the route is known, for the audit log.
type Decision struct {
	Template     string // for example /ex/jira/{cloudId}/rest/api/3/issue/{key}
	CloudID      string
	UpstreamPath string // /ex/jira/<cloudId>/rest/api/3/..., re-encoded
	RawQuery     string // validated; forwarded as is
	JQLHash      string // sha256 of the JQL, for search calls

	// IssueKeys must each be pre-flighted upstream before the call is
	// forwarded: the path key and any issue keys in the body.
	IssueKeys []string
	// CommentIssueKey and CommentID are set for PUT and DELETE on a
	// comment: the comment must be checked to belong to that issue.
	CommentIssueKey string
	CommentID       string
	Strip           Strip
	// Write is set for write routes: their pre-flight skips the cache.
	Write bool

	propKey string // the property key, decoded once, for property routes
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

// param is one allowed query parameter. With colon set, the value may
// carry ":" sent as %3A; it is decoded once and no other escape is
// accepted.
type param struct {
	re    *regexp.Regexp
	colon bool
}

type route struct {
	method   string
	pattern  []string
	write    bool
	query    map[string]param
	required []string
	body     bodyKind
	strip    Strip
}

var (
	pCount   = param{re: regexp.MustCompile(`^[0-9]{1,4}$`)}
	pOffset  = param{re: regexp.MustCompile(`^[0-9]{1,9}$`)}
	pCreated = param{re: regexp.MustCompile(`^created$`)}
	pProps   = param{re: regexp.MustCompile(`^properties$`)}
	pTrFlds  = param{re: regexp.MustCompile(`^transitions\.fields$`)}
	// Atlassian account ids: "<digits>:<uuid>" (sent with ":" as %3A) or
	// the older 24-hex form.
	pAccountID = param{colon: true, re: regexp.MustCompile(
		`^(?:[0-9]{1,10}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})$`)}
)

// routes is the contract's allowlist, with the query parameters fullsend
// sends on each call (internal/forge/jira).
var routes = []route{
	{method: http.MethodGet, pattern: []string{"myself"}},
	{method: http.MethodGet, pattern: []string{"status", pStatus}},
	{method: http.MethodGet, pattern: []string{"project", pProject, "role"}},
	{method: http.MethodGet, pattern: []string{"project", pProject, "role", pNum}},
	{method: http.MethodGet, pattern: []string{"user", "groups"},
		query: map[string]param{"accountId": pAccountID}, required: []string{"accountId"}},
	{method: http.MethodGet, pattern: []string{"issue", pKey}, strip: StripIssue},
	{method: http.MethodGet, pattern: []string{"issue", pKey, "comment"},
		query: map[string]param{"orderBy": pCreated, "maxResults": pCount, "startAt": pOffset, "expand": pProps}},
	{method: http.MethodGet, pattern: []string{"issue", pKey, "changelog"},
		query: map[string]param{"maxResults": pCount, "startAt": pOffset}, strip: StripChangelog},
	{method: http.MethodGet, pattern: []string{"issue", pKey, "transitions"},
		query: map[string]param{"expand": pTrFlds}},
	{method: http.MethodGet, pattern: []string{"issue", pKey, "properties", pProp}},
	{method: http.MethodPost, pattern: []string{"search", "jql"}, body: bodySearch, strip: StripSearch},

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
	// Issue numbers have no leading zero: Jira resolves ABC-01 to ABC-1,
	// so a zero-padded key would name the same issue under another spelling.
	issueKeyRe   = regexp.MustCompile(`^([A-Z][A-Z0-9_]+)-[1-9][0-9]{0,17}$`)
	projectKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	numRe        = regexp.MustCompile(`^[0-9]{1,18}$`)
	// Property key shape before the namespace check: decoded exactly once
	// (so core's %252E arrives as the literal %2E), at most 255 bytes.
	propKeyRe = regexp.MustCompile(`^[A-Za-z0-9._%-]{1,255}$`)
	statusRe  = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}\p{M} ._()-]{0,99}$`)
)

// validPropKey checks a property key segment's shape: the raw segment
// must be exactly url.PathEscape of the once-decoded key, so no byte is
// encoded other than "%" itself (core sends a literal "%2E" as %252E).
func validPropKey(s segment) bool {
	return propKeyRe.MatchString(s.dec) && strings.Trim(s.dec, ".") != "" && url.PathEscape(s.dec) == s.raw
}

// propAllowed reports whether key is one of the caller's two poller keys
// (internal/jirapoll/lock.go in fullsend) and method is allowed on it:
//
//	fullsend.poll.<esc(owner)>.<esc(repo)>.lock       GET PUT DELETE
//	fullsend.poll.<esc(owner)>.<esc(repo)>.lastCheck  GET PUT
//
// owner and repo come from the grant's repository (equal to the verified
// token's repository claim), split on the last "/". esc replaces "." with
// the literal "%2E". Owner and repo compare case-insensitively; the rest,
// including "%2E", compares exactly.
func propAllowed(repository, key, method string) bool {
	i := strings.LastIndex(repository, "/")
	if i < 0 {
		return false
	}
	owner, repo := repository[:i], repository[i+1:]
	rest, ok := strings.CutPrefix(key, "fullsend.poll.")
	if !ok {
		return false
	}
	if rest, ok = matchEscaped(rest, owner); !ok {
		return false
	}
	if rest, ok = strings.CutPrefix(rest, "."); !ok {
		return false
	}
	if rest, ok = matchEscaped(rest, repo); !ok {
		return false
	}
	switch rest {
	case ".lock":
		return method == http.MethodGet || method == http.MethodPut || method == http.MethodDelete
	case ".lastCheck":
		return method == http.MethodGet || method == http.MethodPut
	}
	return false
}

// matchEscaped consumes esc(name) from the start of s: each "." in name
// must appear as "%2E", every other byte must match ignoring ASCII case.
func matchEscaped(s, name string) (string, bool) {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '.' {
			var ok bool
			if s, ok = strings.CutPrefix(s, "%2E"); !ok {
				return "", false
			}
			continue
		}
		if s == "" || lowerASCII(s[0]) != lowerASCII(c) {
			return "", false
		}
		s = s[1:]
	}
	return s, true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// issueKeyInGrant reports whether s is an issue key whose project is
// granted. Numeric issue ids never match.
func issueKeyInGrant(g *config.Grant, s string) bool {
	m := issueKeyRe.FindStringSubmatch(s)
	return m != nil && g.HasProject(m[1])
}

const templatePrefix = "/ex/jira/{cloudId}/rest/api/3"

// Authorize checks one request against the grant and the allowlist. The
// returned Decision is never nil; on denial it carries the route template
// when one matched. An allowed Decision may still need its IssueKeys and
// comment pre-flighted upstream before forwarding.
func Authorize(g *config.Grant, req Request) (*Decision, *Denial) {
	d := &Decision{}
	cloudID, rest, rawQuery, ok := parseRequestURI(req.RequestURI)
	if !ok {
		return d, deny(ReasonPath)
	}
	if cloudID != g.CloudID {
		return d, deny(ReasonCloudID)
	}
	d.CloudID = cloudID
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
	if d.propKey != "" && !propAllowed(g.Repository, d.propKey, req.Method) {
		return d, deny(ReasonPropertyKey)
	}
	if !checkQuery(r, rawQuery) {
		return d, deny(ReasonQuery)
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
	d.Strip = r.strip
	d.Write = r.write
	return d, nil
}

// checkQuery applies the route's parameter rules: only listed parameters,
// each once, required ones present.
func checkQuery(r *route, rawQuery string) bool {
	q, ok := parseQuery(rawQuery)
	if !ok {
		return false
	}
	for k, raw := range q {
		p, known := r.query[k]
		if !known {
			return false
		}
		v := raw
		if p.colon {
			v = strings.NewReplacer("%3A", ":", "%3a", ":").Replace(raw)
		}
		if strings.Contains(v, "%") || (!p.colon && strings.Contains(raw, ":")) || !p.re.MatchString(v) {
			return false
		}
	}
	for _, k := range r.required {
		if _, ok := q[k]; !ok {
			return false
		}
	}
	return true
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
		var key, num, prop string
		for j, p := range r.pattern {
			s := rest[j]
			switch p {
			case pKey:
				if !issueKeyRe.MatchString(s.dec) || s.raw != s.dec {
					ok = false
				} else if !issueKeyInGrant(g, s.dec) {
					projectDenied = true
				}
				key = s.dec
			case pProject:
				if !projectKeyRe.MatchString(s.dec) || s.raw != s.dec {
					ok = false
				} else if !g.HasProject(s.dec) {
					projectDenied = true
				}
			case pNum:
				ok = ok && numRe.MatchString(s.dec) && s.raw == s.dec
				num = s.dec
			case pProp:
				ok = ok && validPropKey(s)
				prop = s.dec
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
		d.propKey = prop
		if key != "" {
			d.IssueKeys = append(d.IssueKeys, key)
			if r.pattern[len(r.pattern)-2] == "comment" && (method == http.MethodPut || method == http.MethodDelete) {
				d.CommentIssueKey, d.CommentID = key, num
			}
		}
		return r, nil
	}
	return nil, deny(ReasonEndpoint)
}

// addKey records an issue key from the body for pre-flight.
func (d *Decision) addKey(k string) {
	for _, have := range d.IssueKeys {
		if have == k {
			return
		}
	}
	d.IssueKeys = append(d.IssueKeys, k)
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
		return checkCreateIssue(g, obj, d)
	case bodyIssueLink:
		return checkIssueLink(g, obj, d)
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
		if errors.Is(err, jql.ErrNotGranted) {
			return deny(ReasonJQLProject)
		}
		return deny(ReasonJQL)
	}
	return nil
}

func checkCreateIssue(g *config.Grant, obj map[string]any, d *Decision) *Denial {
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
		d.addKey(pk)
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

func checkIssueLink(g *config.Grant, obj map[string]any, d *Decision) *Denial {
	if len(obj) != 3 || !onlyKeys(obj, "type", "inwardIssue", "outwardIssue") {
		return deny(ReasonBody)
	}
	if _, ok := exactlyKey(obj["type"], "name"); !ok {
		return deny(ReasonBody)
	}
	var keys []string
	for _, side := range []string{"inwardIssue", "outwardIssue"} {
		k, ok := exactlyKey(obj[side], "key")
		if !ok || !issueKeyRe.MatchString(k) {
			return deny(ReasonBody)
		}
		if !issueKeyInGrant(g, k) {
			return deny(ReasonProject)
		}
		keys = append(keys, k)
	}
	for _, k := range keys {
		d.addKey(k)
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

// checkTransition allows a transition id, an optional resolution (by
// name or id) and an optional comment. Every other field, including
// custom fields, is refused: a field value can name another issue.
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
		if !ok || !onlyKeys(fm, "resolution") {
			return deny(ReasonBody)
		}
		if r, present := fm["resolution"]; present {
			_, byName := exactlyKey(r, "name")
			_, byID := exactlyKey(r, "id")
			if !byName && !byID {
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
