// Package jql confines Jira JQL searches to a set of granted projects.
//
// It does not try to understand JQL. It accepts a deliberately narrow
// subset (see Validate) and rejects everything else, so a query that the
// gateway forwards has the same meaning to Jira as it has here.
package jql

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrRejected is returned for every query outside the accepted grammar.
// Callers map it to one fixed message and never echo the query.
var ErrRejected = errors.New("jql outside the accepted grammar")

// Limits on the input, so a hostile query cannot cost much to check.
const (
	MaxQueryBytes = 4096
	maxTokens     = 512
	maxListValues = 50
	maxDepth      = 3
)

type kind int

const (
	kEOF    kind = iota
	kWord        // unquoted literal or identifier: [A-Za-z0-9_-]+
	kString      // quoted literal; text holds the decoded value
	kOp          // = != ~ !~ > >= < <=
	kLParen      // (
	kRParen      // )
	kComma       // ,
)

type token struct {
	kind kind
	text string // decoded value for kString; raw text otherwise
}

// keyword reports the upper-case keyword a word spells, or "".
// Matching is ASCII-only: words are ASCII by construction, so no Unicode
// case folding (for example the Kelvin sign) can turn a word into a keyword.
func (t token) keyword() string {
	if t.kind != kWord {
		return ""
	}
	u := asciiUpper(t.text)
	if _, ok := keywords[u]; ok {
		return u
	}
	return ""
}

// keywords are JQL words that are never accepted as unquoted values. The
// list includes operators and history keywords the grammar does not use,
// so that, for example, `status = was` is refused instead of being read
// as a literal.
var keywords = map[string]struct{}{
	"AND": {}, "OR": {}, "NOT": {}, "IN": {}, "IS": {}, "EMPTY": {}, "NULL": {},
	"ORDER": {}, "BY": {}, "ASC": {}, "DESC": {},
	"WAS": {}, "CHANGED": {}, "ON": {}, "BEFORE": {}, "AFTER": {}, "DURING": {},
	"FROM": {}, "TO": {},
}

func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

func isWordByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// lex splits q into tokens. It refuses, rather than skips, anything it
// does not recognise: non-ASCII outside quotes, control characters, any
// punctuation JQL could read as an operator (& | ! [ ] etc.), unknown
// string escapes and unbalanced quotes.
func lex(q string) ([]token, error) {
	if len(q) > MaxQueryBytes || !utf8.ValidString(q) {
		return nil, ErrRejected
	}
	var toks []token
	i := 0
	for i < len(q) {
		if len(toks) >= maxTokens {
			return nil, ErrRejected
		}
		c := q[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{kind: kLParen, text: "("})
			i++
		case c == ')':
			toks = append(toks, token{kind: kRParen, text: ")"})
			i++
		case c == ',':
			toks = append(toks, token{kind: kComma, text: ","})
			i++
		case c == '=' || c == '~':
			toks = append(toks, token{kind: kOp, text: string(c)})
			i++
		case c == '!':
			if i+1 < len(q) && (q[i+1] == '=' || q[i+1] == '~') {
				toks = append(toks, token{kind: kOp, text: q[i : i+2]})
				i += 2
				continue
			}
			return nil, ErrRejected // bare ! is JQL's NOT
		case c == '<' || c == '>':
			if i+1 < len(q) && q[i+1] == '=' {
				toks = append(toks, token{kind: kOp, text: q[i : i+2]})
				i += 2
				continue
			}
			toks = append(toks, token{kind: kOp, text: string(c)})
			i++
		case c == '"' || c == '\'':
			val, n, err := lexString(q[i:])
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: kString, text: val})
			i += n
		case isWordByte(c):
			j := i
			for j < len(q) && isWordByte(q[j]) {
				j++
			}
			toks = append(toks, token{kind: kWord, text: q[i:j]})
			i = j
		default:
			return nil, ErrRejected
		}
	}
	return append(toks, token{kind: kEOF}), nil
}

// lexString reads a quoted string at the start of s and returns its
// decoded value and the number of bytes consumed. The only escapes are
// \" \' and \\; any other backslash sequence is refused, so the end of the
// string cannot be read differently by Jira.
func lexString(s string) (string, int, error) {
	quote := s[0]
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		switch {
		case c == quote:
			return b.String(), i + 1, nil
		case c == '\\':
			if i+1 >= len(s) {
				return "", 0, ErrRejected
			}
			switch s[i+1] {
			case '"', '\'', '\\':
				b.WriteByte(s[i+1])
				i += 2
			default:
				return "", 0, ErrRejected
			}
		case c < 0x80:
			if c < 0x20 || c == 0x7f {
				return "", 0, ErrRejected
			}
			b.WriteByte(c)
			i++
		default:
			r, n := utf8.DecodeRuneInString(s[i:])
			// Letters, digits and combining marks only: no Unicode
			// quotes, spaces, separators or format characters (bidi
			// controls, zero-width joiners).
			if r == utf8.RuneError || !(unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r)) {
				return "", 0, ErrRejected
			}
			b.WriteRune(r)
			i += n
		}
	}
	return "", 0, ErrRejected // unterminated
}
