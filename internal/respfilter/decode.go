package respfilter

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

// MaxDepth bounds nesting in a response. It is far deeper than request
// bodies allow, because Jira's ADF documents and JSON custom fields nest.
const MaxDepth = 256

// rule says what to do with one JSON value on a filtered path.
type rule struct {
	// must: the value must be of the kind the rule expects (an object
	// when drop/members/captureKey is set, an array when elems/keep is
	// set); otherwise the body is undecodable. Without must, a value of
	// another kind passes unchanged.
	must bool

	drop       map[string]bool  // object: members removed
	members    map[string]*rule // object: rules for particular members
	captureKey bool             // object: record a top-level string "key"

	elems *rule                           // array: rule for every element
	keep  func(elem []byte) (bool, error) // array: whether an element stays
}

func (r *rule) wantsObject() bool { return r.drop != nil || r.members != nil || r.captureKey }
func (r *rule) wantsArray() bool  { return r.elems != nil || r.keep != nil }

// filter copies body to a new buffer, applying r. It refuses invalid JSON
// or UTF-8, trailing data, EXACT duplicate object keys at any depth (keys
// that differ only in case are allowed: Jira field ids may) and nesting
// deeper than MaxDepth. Kept values are copied byte for byte. It returns
// the filtered body and, with captureKey, the top-level "key" string.
func filter(body []byte, r *rule) (out []byte, key string, err error) {
	// json.Valid checks the syntax, so the scanner below can assume a
	// well-formed document and only track structure.
	if !utf8.Valid(body) || !json.Valid(body) {
		return nil, "", ErrUndecodable
	}
	s := &scanner{b: body, out: make([]byte, 0, len(body))}
	s.ws()
	if err := s.value(r, 0, true); err != nil {
		return nil, "", err
	}
	s.ws()
	if s.i != len(s.b) {
		return nil, "", ErrUndecodable
	}
	return s.out, s.key, nil
}

type scanner struct {
	b   []byte
	i   int
	out []byte
	key string
}

func (s *scanner) ws() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

// skipString moves past a string starting at s.i (a '"') and reports
// whether it contained an escape.
func (s *scanner) skipString() (escaped bool) {
	s.i++ // opening quote
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case '\\':
			escaped = true
			s.i += 2
		case '"':
			s.i++
			return escaped
		default:
			s.i++
		}
	}
	return escaped
}

// walk moves past one value without copying it, but still enforces the
// duplicate-key and depth rules inside it.
func (s *scanner) walk(depth int) error {
	switch s.b[s.i] {
	case '{':
		if depth >= MaxDepth {
			return ErrUndecodable
		}
		s.i++
		var seen keySet
		s.ws()
		if s.b[s.i] == '}' {
			s.i++
			return nil
		}
		for {
			k, err := s.readKey()
			if err != nil {
				return err
			}
			if !seen.add(k) {
				return ErrUndecodable
			}
			s.ws()
			s.i++ // ':'
			s.ws()
			if err := s.walk(depth + 1); err != nil {
				return err
			}
			s.ws()
			if s.b[s.i] == ',' {
				s.i++
				s.ws()
				continue
			}
			s.i++ // '}'
			return nil
		}
	case '[':
		if depth >= MaxDepth {
			return ErrUndecodable
		}
		s.i++
		s.ws()
		if s.b[s.i] == ']' {
			s.i++
			return nil
		}
		for {
			if err := s.walk(depth + 1); err != nil {
				return err
			}
			s.ws()
			if s.b[s.i] == ',' {
				s.i++
				s.ws()
				continue
			}
			s.i++ // ']'
			return nil
		}
	case '"':
		s.skipString()
	default: // number, true, false, null
		for s.i < len(s.b) {
			switch s.b[s.i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return nil
			}
			s.i++
		}
	}
	return nil
}

// readKey reads an object key at s.i and returns it decoded. A key with
// no escape is returned as a slice of the body, without allocating.
func (s *scanner) readKey() ([]byte, error) {
	start := s.i
	escaped := s.skipString()
	raw := s.b[start:s.i]
	if !escaped {
		return raw[1 : len(raw)-1], nil
	}
	var k string
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, ErrUndecodable
	}
	return []byte(k), nil
}

// value copies (and filters) the value at s.i into s.out.
func (s *scanner) value(r *rule, depth int, top bool) error {
	c := s.b[s.i]
	switch {
	case r != nil && c == '{' && r.wantsObject():
		return s.object(r, depth, top)
	case r != nil && c == '[' && r.wantsArray():
		return s.array(r, depth)
	case r != nil && r.must:
		return ErrUndecodable
	}
	start := s.i
	if err := s.walk(depth); err != nil {
		return err
	}
	s.out = append(s.out, s.b[start:s.i]...)
	return nil
}

func (s *scanner) object(r *rule, depth int, top bool) error {
	if depth >= MaxDepth {
		return ErrUndecodable
	}
	s.i++
	s.out = append(s.out, '{')
	var seen keySet
	first := true
	s.ws()
	if s.b[s.i] == '}' {
		s.i++
		s.out = append(s.out, '}')
		return nil
	}
	for {
		keyStart := s.i
		k, err := s.readKey()
		if err != nil {
			return err
		}
		keyRaw := s.b[keyStart:s.i]
		if !seen.add(k) {
			return ErrUndecodable
		}
		s.ws()
		s.i++ // ':'
		s.ws()
		name := string(k) // short; used for map lookups below
		switch {
		case r.drop[name]:
			if err := s.walk(depth + 1); err != nil {
				return err
			}
		default:
			if !first {
				s.out = append(s.out, ',')
			}
			first = false
			s.out = append(s.out, keyRaw...)
			s.out = append(s.out, ':')
			valStart := s.i
			if err := s.value(r.members[name], depth+1, false); err != nil {
				return err
			}
			if top && r.captureKey && name == "key" && s.b[valStart] == '"' {
				var v string
				if json.Unmarshal(s.b[valStart:s.i], &v) == nil {
					s.key = v
				}
			}
		}
		s.ws()
		if s.b[s.i] == ',' {
			s.i++
			s.ws()
			continue
		}
		s.i++ // '}'
		s.out = append(s.out, '}')
		return nil
	}
}

func (s *scanner) array(r *rule, depth int) error {
	if depth >= MaxDepth {
		return ErrUndecodable
	}
	s.i++
	s.out = append(s.out, '[')
	first := true
	s.ws()
	if s.b[s.i] == ']' {
		s.i++
		s.out = append(s.out, ']')
		return nil
	}
	for {
		start := s.i
		mark := len(s.out)
		if !first {
			s.out = append(s.out, ',')
		}
		if err := s.value(r.elems, depth+1, false); err != nil {
			return err
		}
		keepIt := true
		if r.keep != nil {
			var err error
			if keepIt, err = r.keep(s.b[start:s.i]); err != nil {
				return err
			}
		}
		if keepIt {
			first = false
		} else {
			s.out = s.out[:mark]
		}
		s.ws()
		if s.b[s.i] == ',' {
			s.i++
			s.ws()
			continue
		}
		s.i++ // ']'
		s.out = append(s.out, ']')
		return nil
	}
}

// keySet records an object's keys. Most objects have a few keys, so a
// slice is scanned first; a map takes over past 16.
type keySet struct {
	small [][]byte
	big   map[string]struct{}
}

func (k *keySet) add(key []byte) bool {
	if k.big != nil {
		if _, dup := k.big[string(key)]; dup {
			return false
		}
		k.big[string(key)] = struct{}{}
		return true
	}
	for _, have := range k.small {
		if bytes.Equal(have, key) {
			return false
		}
	}
	k.small = append(k.small, key)
	if len(k.small) > 16 {
		k.big = make(map[string]struct{}, 32)
		for _, have := range k.small {
			k.big[string(have)] = struct{}{}
		}
		k.small = nil
	}
	return true
}

// topField returns the string value of member name in the object elem,
// which is already validated.
func topField(elem []byte, name string) (string, bool, error) {
	s := &scanner{b: elem}
	s.ws()
	if s.i >= len(s.b) || s.b[s.i] != '{' {
		return "", false, ErrUndecodable
	}
	s.i++
	s.ws()
	if s.b[s.i] == '}' {
		return "", false, nil
	}
	for {
		k, err := s.readKey()
		if err != nil {
			return "", false, err
		}
		s.ws()
		s.i++
		s.ws()
		start := s.i
		if err := s.walk(0); err != nil {
			return "", false, err
		}
		if string(k) == name && s.b[start] == '"' {
			var v string
			if err := json.Unmarshal(s.b[start:s.i], &v); err != nil {
				return "", false, ErrUndecodable
			}
			return v, true, nil
		}
		s.ws()
		if s.b[s.i] == ',' {
			s.i++
			s.ws()
			continue
		}
		return "", false, nil
	}
}
