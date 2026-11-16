package jql

import "regexp"

// projectKeyRe is the shape of a Jira Cloud project key. The value of a
// project clause must have this shape and be listed in the grant exactly
// (case-sensitive), so a project name or numeric id is refused.
var projectKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

// fieldRule lists the operators a field accepts.
type fieldRule struct {
	ops     map[string]bool // = != > >= < <=
	inList  bool            // IN (...)
	notIn   bool            // NOT IN (...)
	isEmpty bool            // IS [NOT] EMPTY|NULL, = EMPTY, != EMPTY
}

var (
	eqOps  = map[string]bool{"=": true, "!=": true}
	cmpOps = map[string]bool{"=": true, "!=": true, ">": true, ">=": true, "<": true, "<=": true}
)

// fields are the filter fields of the grammar, keyed by lower-case name.
// project is handled separately.
var fields = map[string]fieldRule{
	"status":         {ops: eqOps, inList: true, notIn: true, isEmpty: true},
	"statuscategory": {ops: eqOps, inList: true, notIn: true, isEmpty: true},
	"issuetype":      {ops: eqOps, inList: true, notIn: true, isEmpty: true},
	"labels":         {ops: eqOps, inList: true, notIn: true, isEmpty: true},
	"assignee":       {ops: eqOps, inList: true, notIn: true, isEmpty: true},
	"updated":        {ops: cmpOps, isEmpty: true},
}

// orderFields are the fields ORDER BY accepts, keyed by lower-case name.
var orderFields = map[string]bool{
	"updated": true, "created": true, "key": true, "priority": true, "status": true,
}

// Result describes an accepted query.
type Result struct {
	// Projects lists every project key named in a project clause.
	Projects []string
}

// Validate accepts q only if it is inside the grammar below and every
// project it names is in granted. The query is never rewritten: an
// accepted query is forwarded byte for byte.
//
//	query   := conj [ORDER BY sort {"," sort}] EOF
//	conj    := term {AND term}
//	term    := clause | "(" conj ")"            (at most 3 levels deep)
//	clause  := "project" ("=" key | IN "(" key {"," key} ")")
//	         | field op value | field [NOT] IN "(" value {"," value} ")"
//	         | field IS [NOT] (EMPTY|NULL)
//	sort    := orderField [ASC|DESC]
//
// Only AND joins clauses, so every clause narrows the result: one project
// clause inside the grant confines the whole query. At least one project
// clause is required, and a project clause naming any key outside the
// grant is refused even though AND would make it harmless.
func Validate(q string, granted map[string]bool) (*Result, error) {
	toks, err := lex(q)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, granted: granted}
	if err := p.conj(0); err != nil {
		return nil, err
	}
	if p.peek().keyword() == "ORDER" {
		if err := p.orderBy(); err != nil {
			return nil, err
		}
	}
	if p.peek().kind != kEOF {
		return nil, ErrRejected
	}
	if len(p.projects) == 0 {
		return nil, ErrRejected
	}
	return &Result{Projects: p.projects}, nil
}

type parser struct {
	toks     []token
	pos      int
	granted  map[string]bool
	projects []string
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != kEOF {
		p.pos++
	}
	return t
}

func (p *parser) conj(depth int) error {
	if err := p.term(depth); err != nil {
		return err
	}
	for p.peek().keyword() == "AND" {
		p.next()
		if err := p.term(depth); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) term(depth int) error {
	if p.peek().kind == kLParen {
		if depth >= maxDepth {
			return ErrRejected
		}
		p.next()
		if err := p.conj(depth + 1); err != nil {
			return err
		}
		if p.next().kind != kRParen {
			return ErrRejected
		}
		return nil
	}
	return p.clause()
}

func (p *parser) clause() error {
	f := p.next()
	if f.kind != kWord || f.keyword() != "" {
		return ErrRejected
	}
	name := lower(f.text)
	if name == "project" {
		return p.projectClause()
	}
	rule, ok := fields[name]
	if !ok {
		return ErrRejected
	}
	t := p.next()
	switch {
	case t.kind == kOp && rule.ops[t.text]:
		v := p.next()
		if kw := v.keyword(); kw == "EMPTY" || kw == "NULL" {
			if !rule.isEmpty || !eqOps[t.text] {
				return ErrRejected
			}
			return nil
		}
		if !isLiteral(v) {
			return ErrRejected
		}
		return nil
	case t.keyword() == "IN" && rule.inList:
		_, err := p.list()
		return err
	case t.keyword() == "NOT" && rule.notIn:
		if p.next().keyword() != "IN" {
			return ErrRejected
		}
		_, err := p.list()
		return err
	case t.keyword() == "IS" && rule.isEmpty:
		v := p.next()
		if v.keyword() == "NOT" {
			v = p.next()
		}
		if kw := v.keyword(); kw != "EMPTY" && kw != "NULL" {
			return ErrRejected
		}
		return nil
	}
	return ErrRejected
}

func (p *parser) projectClause() error {
	t := p.next()
	var keys []token
	switch {
	case t.kind == kOp && t.text == "=":
		keys = []token{p.next()}
	case t.keyword() == "IN":
		var err error
		if keys, err = p.list(); err != nil {
			return err
		}
	default:
		return ErrRejected
	}
	for _, k := range keys {
		if !isLiteral(k) || !projectKeyRe.MatchString(k.text) || !p.granted[k.text] {
			return ErrRejected
		}
		p.projects = append(p.projects, k.text)
	}
	return nil
}

// list parses "(" literal {"," literal} ")".
func (p *parser) list() ([]token, error) {
	if p.next().kind != kLParen {
		return nil, ErrRejected
	}
	var vals []token
	for {
		v := p.next()
		if !isLiteral(v) {
			return nil, ErrRejected
		}
		vals = append(vals, v)
		if len(vals) > maxListValues {
			return nil, ErrRejected
		}
		switch p.next().kind {
		case kComma:
			continue
		case kRParen:
			return vals, nil
		default:
			return nil, ErrRejected
		}
	}
}

func (p *parser) orderBy() error {
	p.next() // ORDER
	if p.next().keyword() != "BY" {
		return ErrRejected
	}
	for {
		f := p.next()
		if f.kind != kWord || f.keyword() != "" || !orderFields[lower(f.text)] {
			return ErrRejected
		}
		if kw := p.peek().keyword(); kw == "ASC" || kw == "DESC" {
			p.next()
		}
		if p.peek().kind != kComma {
			return nil
		}
		p.next()
	}
}

// isLiteral reports whether t is a value: a quoted string, or an unquoted
// word that is not a keyword.
func isLiteral(t token) bool {
	return t.kind == kString || (t.kind == kWord && t.keyword() == "")
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c - 'A' + 'a'
		}
	}
	return string(b)
}
