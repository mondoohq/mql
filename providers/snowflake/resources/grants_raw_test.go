// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// grantRowCells builds the cell map a QueryUnsafe result hands back, where every value is
// a pointer to an any.
func grantRowCells(pairs map[string]any) map[string]*any {
	out := make(map[string]*any, len(pairs))
	for k, v := range pairs {
		out[k] = &v
	}
	return out
}

func TestSplitQualifiedName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"unqualified", "ANALYST", []string{"ANALYST"}},
		{"two parts", "DB.SCH", []string{"DB", "SCH"}},
		{"three parts", "DB.SCH.T", []string{"DB", "SCH", "T"}},
		{
			// A dot inside quotes is part of the name, not a separator.
			"quoted part containing a dot",
			`DB."my.schema".T`,
			[]string{"DB", `"my.schema"`, "T"},
		},
		{
			// A function carries its argument list in its name, and an argument
			// type can itself contain a dot.
			"function arguments are one part",
			"SNOWFLAKE.CORE.ACCEPTED_VALUES(TABLE(DATE))",
			[]string{"SNOWFLAKE", "CORE", "ACCEPTED_VALUES(TABLE(DATE))"},
		},
		{"empty", "", []string{""}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitQualifiedName(tc.in))
		})
	}
}

func TestQuoteQualifiedName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// This is the shape the SDK's FullyQualifiedName produced, and what the
		// name field of a grant has always reported.
		{"three parts", "DB.SCH.T", `"DB"."SCH"."T"`},
		{"account object", "UKB48668", `"UKB48668"`},
		{"already quoted parts are left alone", `"DB"."SCH"`, `"DB"."SCH"`},
		{"mixed quoting", `DB."my.schema"`, `"DB"."my.schema"`},
		{
			"function with table argument",
			"SNOWFLAKE.CORE.ACCEPTED_VALUES(TABLE(DATE))",
			`"SNOWFLAKE"."CORE"."ACCEPTED_VALUES(TABLE(DATE))"`,
		},
		// An account-level privilege carries no object name; it must stay empty
		// rather than become a pair of quotes around nothing.
		{"empty stays empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, quoteQualifiedName(tc.in))
		})
	}
}

func TestIdentifierName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"unqualified", "ANALYST", "ANALYST"},
		{"qualified takes the last part", "DB.SCH.T", "T"},
		{"quoting is removed", `"ANALYST"`, "ANALYST"},
		{"quoted last part", `"DB"."SCH"."my table"`, "my table"},
		{"embedded quotes are unescaped", `"say ""hi"""`, `say "hi"`},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, identifierName(tc.in))
		})
	}
}

func TestParseGrantRows(t *testing.T) {
	created := time.Date(2026, 8, 11, 12, 14, 31, 0, time.UTC)

	rows := []map[string]*any{
		grantRowCells(map[string]any{
			"created_on":   created,
			"privilege":    "SELECT",
			"granted_on":   "TABLE",
			"name":         "DB.SCH.T",
			"granted_to":   "ROLE",
			"grantee_name": "ANALYST",
			"grant_option": "false",
			"granted_by":   "ACCOUNTADMIN",
		}),
	}

	grants := parseGrantRows(rows)
	require.Len(t, grants, 1)

	g := grants[0]
	assert.Equal(t, "SELECT", g.privilege)
	assert.Equal(t, "TABLE", g.grantedOn)
	assert.Equal(t, "ROLE", g.grantedTo)
	assert.Equal(t, `"DB"."SCH"."T"`, g.name)
	assert.Equal(t, "ANALYST", g.granteeName)
	assert.Equal(t, "ACCOUNTADMIN", g.grantedBy)
	assert.False(t, g.grantOption)
	assert.Equal(t, llx.TimeData(created), g.createdOn)
}

// A grant on a function whose argument is a table is the row that made the
// SDK's typed reader panic, so it has to survive parsing intact.
func TestParseGrantRowsFunctionWithTableArgument(t *testing.T) {
	rows := []map[string]*any{
		grantRowCells(map[string]any{
			"privilege":    "USAGE",
			"granted_on":   "FUNCTION",
			"name":         "SNOWFLAKE.CORE.ACCEPTED_VALUES(TABLE(DATE))",
			"granted_to":   "ROLE",
			"grantee_name": "ACCOUNTADMIN",
			"grant_option": "true",
		}),
	}

	grants := parseGrantRows(rows)
	require.Len(t, grants, 1)
	assert.Equal(t, `"SNOWFLAKE"."CORE"."ACCEPTED_VALUES(TABLE(DATE))"`, grants[0].name)
	assert.Equal(t, "FUNCTION", grants[0].grantedOn)
	assert.True(t, grants[0].grantOption)
}

// A future grant names the object type it will apply to in grant_on/grant_to;
// granted_on/granted_to are empty until the object exists.
func TestParseGrantRowsFutureGrant(t *testing.T) {
	rows := []map[string]*any{
		grantRowCells(map[string]any{
			"privilege":    "SELECT",
			"granted_on":   "",
			"grant_on":     "TABLE",
			"name":         "DB.SCH.<TABLE>",
			"granted_to":   "",
			"grant_to":     "ROLE",
			"grantee_name": "ANALYST",
			"grant_option": "false",
		}),
	}

	grants := parseGrantRows(rows)
	require.Len(t, grants, 1)
	assert.Equal(t, "TABLE", grants[0].grantedOn, "grant_on stands in for granted_on")
	assert.Equal(t, "ROLE", grants[0].grantedTo, "grant_to stands in for granted_to")
}

// An absent timestamp must stay null rather than become the zero time, which
// would report the year 1 as the moment the grant was made.
func TestParseGrantRowsMissingCreatedOn(t *testing.T) {
	grants := parseGrantRows([]map[string]*any{
		grantRowCells(map[string]any{"privilege": "USAGE", "granted_on": "DATABASE"}),
	})
	require.Len(t, grants, 1)
	assert.Equal(t, llx.NilData, grants[0].createdOn)
}

func TestParseGrantRowsEmpty(t *testing.T) {
	assert.Empty(t, parseGrantRows(nil))
	assert.Empty(t, parseGrantRows([]map[string]*any{}))
}
