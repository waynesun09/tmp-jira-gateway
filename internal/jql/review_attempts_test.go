package jql

import (
	"errors"
	"testing"
)

// TestReviewAttempts runs a reviewer's bypass attempts (unicode, escapes,
// whitespace, reserved words, project shapes). Each must be refused, or,
// if accepted, pass the independent confinement check.
func TestReviewAttempts(t *testing.T) {
	g := map[string]bool{"ABC": true}
	cases := []string{
		// unicode / escapes
		`project = "ABC"`,
		`project = "ABC" OR project = "OTHER"`,
		"project = ABC",
		"project = \"ABC \"",
		"project = ＂ABC＂",
		"project = \"АBC\"", // Cyrillic A
		"project = \"ABC​\"",
		"project = \"ABĆ\"",                   // combining mark appended
		"project = ABC AND status = \"Opeń\"", // combining mark in value (accepted, harmless)
		"project = ABC AND status = \"١\"",     // Arabic-Indic digit
		`project = "AB\"C"`,
		`project = "ABC\\"`,
		`project = 'ABC' AND status = "it\'s"`,
		`project = "ABC" AND status = "a\tb"`,
		`project = "ABC" AND status = "a\ b"`,
		// whitespace / comments
		"project = ABC\tAND\nstatus = Open\r",
		"project = ABC\vAND status = Open",
		"project = ABC\fAND status = Open",
		"project = ABC AND status = Open\n-- x",
		"project = ABC /**/",
		// reserved words as fields / values
		`order = x AND project = ABC`,
		`project = ABC AND by = x`,
		`project = ABC AND and = x`,
		`project = ABC AND status = "OR"`,
		`project = ABC AND status = select`,
		`project = ABC AND status = empty`,
		`project = ABC AND status != NULL`,
		`project = ABC AND updated >= EMPTY`,
		`project = ABC AND updated IS NOT NULL`,
		`project = ABC AND labels IN (EMPTY)`,
		`project = ABC AND project IN (ABC)`,
		`project = ABC ORDER BY updated DESC, project`,
		`project = ABC ORDER BY updated DESC DESC`,
		`project = ABC ORDER BY "updated"`,
		`project = ABC ORDER BY cf[1]`,
		`project = ABC ORDER BY updated, key ASC`,
		// project shapes
		`project = ABC-1`,
		`project = A`,
		`project = ABC_`,
		`project = "ABC "`,
		`project = " ABC"`,
		`project = ""`,
		`project IN (ABC, ABC)`,
		`project IN ABC`,
		`project = = ABC`,
		`project == ABC`,
		`project=ABC`,
		`project=ABC AND status=Open`,
		`(project = ABC AND status = Open) AND (labels = x)`,
		`(project = ABC`,
		`project = ABC AND ()`,
		`project = ABC AND status = Open AND`,
		`project = ABC AND statusCategory = 3`,
		`project = ABC AND updated > -1d AND updated < now`,
		`project = ABC AND updated > now()`,
		`project = ABC AND assignee = "5b10ac8d82e05b22cc7d4ef5"`,
		`project = ABC AND assignee IN ("a", membersOf("x"))`,
		`project = ABC AND issuetype IN standardIssueTypes()`,
		`project = ABC AND labels = "x" OR labels = "y"`,
		`issuetype = Bug AND project IN (ABC)`,
		`project = ABC AND status ~ Open`,
		`project = ABC AND updated = -1d`,
		`project = ABC AND labels = -`,
		`project = ABC AND labels = --`,
		`project = ABC AND labels = a-b`,
		`project = ABC AND labels = 1e10`,
	}
	for _, q := range cases {
		res, err := Validate(q, g)
		if err != nil {
			if !errors.Is(err, ErrRejected) && !errors.Is(err, ErrNotGranted) {
				t.Errorf("%+q: unexpected error %v", q, err)
			}
			continue
		}
		checkConfinedTo(t, q, res, g)
	}
}
