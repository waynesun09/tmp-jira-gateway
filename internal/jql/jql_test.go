package jql

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

var grant = map[string]bool{"ABC": true, "DEF": true}

// The queries fullsend sends with no custom poll query: the poller's own
// fallback (internal/jirapoll) and the CLI's scoped form
// (config.ScopeJQLToProject with the default predicate).
const (
	pollerDefault = `project = "ABC" AND statusCategory != Done ORDER BY updated DESC`
	cliDefault    = `project = "ABC" AND (statusCategory != Done) ORDER BY updated DESC`
)

func TestAcceptsFullsendDefaults(t *testing.T) {
	for _, q := range []string{pollerDefault, cliDefault} {
		res, err := Validate(q, grant)
		if err != nil {
			t.Fatalf("Validate(%q) = %v, want accepted", q, err)
		}
		if len(res.Projects) != 1 || res.Projects[0] != "ABC" {
			t.Fatalf("Validate(%q) projects = %v", q, res.Projects)
		}
	}
}

func TestAccepted(t *testing.T) {
	for _, q := range []string{
		`project = ABC`,
		`project = 'ABC'`,
		`project IN ("ABC", "DEF")`,
		`project in (ABC,DEF) and status = "In Progress"`,
		`Project = ABC AND Status = Open`,
		`project = ABC AND status IN (Open, "To Do") AND labels = fullsend`,
		`project = ABC AND labels NOT IN (wontfix, "do-not-run")`,
		`project = ABC AND labels IS EMPTY`,
		`project = ABC AND assignee IS NOT EMPTY`,
		`project = ABC AND assignee = EMPTY`,
		`project = ABC AND assignee != NULL`,
		`project = ABC AND issuetype = Bug`,
		`project = ABC AND updated >= -7d`,
		`project = ABC AND updated > "2026-01-01" AND updated <= "2026-02-01 10:00"`,
		`project = ABC AND (status = Open AND (labels = a))`,
		`(project = ABC) AND status = Open`,
		`status = Open AND project = ABC`,
		"project = ABC AND status = \"\u00dcbersetzung\"",
		`project = ABC AND status = "say \"hi\""`,
		`project = ABC ORDER BY updated DESC, created ASC, key`,
		`project = ABC order by priority`,
		"project = ABC\n\tAND status = Open",
		`project = ABC AND project = DEF`,
	} {
		if _, err := Validate(q, grant); err != nil {
			t.Errorf("Validate(%q) = %v, want accepted", q, err)
		}
	}
}

func TestRejected(t *testing.T) {
	for _, q := range []string{
		``,
		`   `,
		`ORDER BY updated DESC`,
		`status = Open`,                     // no project clause
		`project = OTHER`,                   // foreign project
		`project = abc`,                     // keys are case-sensitive here
		`project = 10000`,                   // numeric id
		`project = "My Project"`,            // project name
		`project IN (ABC, OTHER)`,           // one foreign key
		`project = ABC AND project = OTHER`, // duplicate clause, foreign key
		`project = ABC OR project = OTHER`,  // OR
		`project = ABC or project = OTHER`,  // case-variant OR
		`project = ABC Or status = Open`,    // case-variant OR
		`project = ABC AND status = Open) OR (project = OTHER`,   // escape attempt
		`project = ABC AND (status = Open) OR (project = OTHER)`, // escape attempt
		`project = ABC AND (status = Open OR project = OTHER)`,   // OR inside parens
		`project = ABC || project = OTHER`,                       // JQL || is OR
		`project = ABC | project = OTHER`,
		`project = ABC && status = Open`, // && is accepted by Jira but not here
		`project = ABC AND NOT status = Open`,
		`project = ABC AND !(status = Open)`,
		`project != ABC`,
		`project NOT IN (OTHER)`,
		`project IS EMPTY`,
		`project = ABC AND project IS EMPTY`,
		`project ~ ABC`,
		`project = ABC AND summary ~ "x"`,            // unknown field
		`project = ABC AND text ~ "x"`,               // text clause
		`project = ABC AND issue = OTHER-1`,          // issue clause
		`project = ABC AND key = OTHER-1`,            // key clause
		`project = ABC AND parent = OTHER-1`,         // parent clause
		`project = ABC AND filter = 10000`,           // filter clause
		`project = ABC AND reporter = x`,             // outside the contract's field set
		`project = ABC AND cf[10000] = x`,            // custom field
		`project = ABC AND "status" = Open`,          // quoted field name
		`project = ABC AND assignee = currentUser()`, // function
		`project in projectsWhereUserHasRole("x")`,
		`project = ABC AND status WAS Open`,
		`project = ABC AND status CHANGED`,
		`project = ABC AND status = was`,      // keyword as value
		`project = ABC AND status IN ()`,      // empty list
		`project = ABC AND status IN (Open,)`, // trailing comma
		`project = ABC AND status > Open`,     // range op on status
		`project = ABC AND labels ~ x`,        // ~ on labels
		`project = ABC AND labels !~ x`,
		`project = ABC AND updated IN (a)`,
		`project = ABC AND`,
		`AND project = ABC`,
		`project = ABC AND AND status = Open`,
		`project = ABC ORDER BY`,
		`project = ABC ORDER BY summary`,
		`project = ABC ORDER BY updated DESC AND project = OTHER`,
		`project = ABC ORDER updated`,
		`project = ABC AND ((((status = Open))))`, // too deep
		`project = ABC AND (status = Open`,        // unbalanced
		`project = ABC AND status = Open)`,
		`project = "ABC`,                        // unbalanced quote
		`project = ABC AND status = "Open`,      // unbalanced quote
		`project = ABC AND status = 'Open"`,     // mismatched quote
		`project = ABC AND status = "a\nb"`,     // unknown escape
		`project = ABC AND status = "a\u0022b"`, // unicode escape
		`project = "AB\C"`,
		"project = ABC AND status = \"a\x00b\"", // control character
		"project = ABC AND status = Open",       // NBSP outside quotes
		"project = ABC AND status = \"a​b\"",    // zero-width space in string
		"project = ABC AND status = \"a‮b\"",    // bidi override in string
		"project = ABC AND status = \"“Open”\"", // smart quotes
		"project = ＡBC",                         // fullwidth A
		"project = ABC ＯR project = OTHER",      // fullwidth OR
		"proKject = ABC",                        // Kelvin sign
		"project = ABC AND status = Open\xff",   // invalid UTF-8
		`project = ABC; project = OTHER`,
		`project = ABC # comment`,
		`project = ABC -- comment`,
		`project = ABC /* c */`,
		`project = ABC AND status = Open.x`,
		`project = ABC AND labels = a*`,
		`project = ABC AND labels = @x`,
		`project = ABC AND labels = [x]`,
	} {
		_, err := Validate(q, grant)
		if !errors.Is(err, ErrRejected) {
			t.Errorf("Validate(%q) = %v, want ErrRejected", q, err)
		}
	}
}

func TestRejectsLongQuery(t *testing.T) {
	q := pollerDefault + strings.Repeat(" ", MaxQueryBytes)
	if _, err := Validate(q, grant); !errors.Is(err, ErrRejected) {
		t.Fatalf("long query accepted")
	}
	many := "project = ABC" + strings.Repeat(" AND status = Open", 200)
	if _, err := Validate(many, grant); !errors.Is(err, ErrRejected) {
		t.Fatalf("query with too many tokens accepted")
	}
}

func TestEmptyGrantRejectsEverything(t *testing.T) {
	if _, err := Validate(pollerDefault, map[string]bool{}); err == nil {
		t.Fatal("accepted with an empty grant")
	}
}

// outsideQuotes returns q with every quoted string removed, using a scanner
// that shares no code with the lexer. It is only meaningful for queries the
// lexer accepted (escapes limited to \" \' \\).
func outsideQuotes(q string) (string, []string) {
	var out strings.Builder
	var strs []string
	for i := 0; i < len(q); i++ {
		c := q[i]
		if c != '"' && c != '\'' {
			out.WriteByte(c)
			continue
		}
		j := i + 1
		var s strings.Builder
		for j < len(q) && q[j] != c {
			if q[j] == '\\' {
				j++
			}
			s.WriteByte(q[j])
			j++
		}
		strs = append(strs, s.String())
		out.WriteString(" _S_ ")
		i = j
	}
	return out.String(), strs
}

var (
	forbiddenWordRe = regexp.MustCompile(`(?i)\b(or|was|changed)\b`)
	notRe           = regexp.MustCompile(`(?i)\bnot\b`)
	notAllowedRe    = regexp.MustCompile(`(?i)\b(is\s+not|not\s+in)\b`)
	projectRe       = regexp.MustCompile(`(?i)\bproject\s*(=|in\b)`)
)

// checkConfined is the fuzz invariant, computed independently of the
// parser: an accepted query has no OR/NOT/history operator and no boolean
// punctuation outside quotes, names at least one project clause, and
// every project it reports is granted.
func checkConfined(t *testing.T, q string, res *Result) {
	t.Helper()
	outside, _ := outsideQuotes(q)
	for i := 0; i < len(outside); i++ {
		if outside[i] >= 0x80 {
			t.Fatalf("accepted %q with non-ASCII outside quotes", q)
		}
	}
	if forbiddenWordRe.MatchString(outside) {
		t.Fatalf("accepted %q with OR/WAS/CHANGED outside quotes", q)
	}
	if n, m := len(notRe.FindAllString(outside, -1)), len(notAllowedRe.FindAllString(outside, -1)); n != m {
		t.Fatalf("accepted %q with a bare NOT", q)
	}
	if strings.ContainsAny(outside, "|&;[]{}*/#@%^$+?") {
		t.Fatalf("accepted %q with operator punctuation outside quotes", q)
	}
	if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(outside, "!=", ""), "!~", ""), "!") {
		t.Fatalf("accepted %q with a bare !", q)
	}
	if !projectRe.MatchString(outside) {
		t.Fatalf("accepted %q without a project clause", q)
	}
	if res == nil || len(res.Projects) == 0 {
		t.Fatalf("accepted %q but reported no projects", q)
	}
	for _, p := range res.Projects {
		if !grant[p] {
			t.Fatalf("accepted %q naming project %q outside the grant", q, p)
		}
	}
}

func TestInvariantOnAccepted(t *testing.T) {
	for _, q := range []string{pollerDefault, cliDefault, `project IN (ABC, DEF) AND labels IS NOT EMPTY`} {
		res, err := Validate(q, grant)
		if err != nil {
			t.Fatal(err)
		}
		checkConfined(t, q, res)
	}
}

func FuzzValidate(f *testing.F) {
	for _, s := range []string{
		pollerDefault,
		cliDefault,
		`project = "ABC" AND (status = Open) OR (project = OTHER)`,
		`project = "ABC" AND status = Open) OR (project = OTHER`,
		`status = Open) OR (project = OTHER`,
		`project = ABC AND project = OTHER`,
		`project IN (ABC, OTHER)`,
		`project = ABC or project = OTHER`,
		`project = ABC oR project = OTHER`,
		`PROJECT = ABC AnD STATUS = Open OrDeR bY updated`,
		`project = ABC || project = OTHER`,
		`project = ABC AND NOT project = OTHER`,
		"project = ABC ＯR project = OTHER",
		"project = \"ABC​\"",
		"proKject = ABC",
		"project = ABC AND status = \"“Open” OR project = OTHER\"",
		`project = "ABC`,
		`project = "ABC" AND status = "Open`,
		`project = 'ABC" OR project = "OTHER'`,
		`project = "ABC\" OR project = OTHER"`,
		`project = ABC AND status = "a\\" OR project = OTHER`,
		`project = ABC AND assignee = currentUser()`,
		`project = ABC AND ((status = Open))`,
		`project in (ABC,DEF) AND labels NOT IN (a,"b") AND updated >= -1d ORDER BY key ASC`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, q string) {
		res, err := Validate(q, grant)
		if err != nil {
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("unexpected error type %v", err)
			}
			return
		}
		checkConfined(t, q, res)
		// Accepting is deterministic and does not depend on surrounding
		// whitespace.
		if _, err := Validate(" "+q+" ", grant); err != nil {
			t.Fatalf("accepted %q but not with surrounding spaces", q)
		}
	})
}
