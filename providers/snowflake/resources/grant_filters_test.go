// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func TestGrantedRoleNames(t *testing.T) {
	grants := []snowflakeGrant{
		{grantedOn: "ROLE", name: `"ANALYST"`},
		// Privileges on other object types are not steps in the hierarchy.
		{grantedOn: "TABLE", name: `"DB"."SCH"."T"`},
		{grantedOn: "DATABASE", name: `"DB"`},
		{grantedOn: "ROLE", name: `"REPORTER"`},
		// A repeat is one edge, not two.
		{grantedOn: "ROLE", name: `"ANALYST"`},
		// A role grant with no name cannot be followed.
		{grantedOn: "ROLE", name: ""},
	}

	assert.Equal(t, []string{"ANALYST", "REPORTER"}, grantedRoleNames(grants))
}

func TestGrantedRoleNamesQuotedName(t *testing.T) {
	// The name arrives qualified and quoted; the hierarchy walk needs the bare
	// role name to look it up.
	grants := []snowflakeGrant{{grantedOn: "ROLE", name: `"my role"`}}
	assert.Equal(t, []string{"my role"}, grantedRoleNames(grants))
}

func TestGrantedRoleNamesEmpty(t *testing.T) {
	assert.Empty(t, grantedRoleNames(nil))
}

func TestGranteeNames(t *testing.T) {
	// SHOW GRANTS OF ROLE reports users and roles in one result set, so the
	// grantee kind is the only thing separating them.
	grants := []snowflakeGrant{
		{grantedTo: "USER", granteeName: "TAS50"},
		{grantedTo: "ROLE", granteeName: "SYSADMIN"},
		{grantedTo: "USER", granteeName: "SVC_ETL"},
		{grantedTo: "USER", granteeName: "TAS50"},
	}

	assert.Equal(t, []string{"TAS50", "SVC_ETL"}, granteeNames(grants, sdk.ObjectTypeUser))
	assert.Equal(t, []string{"SYSADMIN"}, granteeNames(grants, sdk.ObjectTypeRole))
}

func TestGranteeNamesNoMatch(t *testing.T) {
	grants := []snowflakeGrant{{grantedTo: "ROLE", granteeName: "SYSADMIN"}}
	assert.Empty(t, granteeNames(grants, sdk.ObjectTypeUser))
}

func TestUnsafeTime(t *testing.T) {
	stamp := time.Date(2026, 8, 11, 12, 14, 31, 0, time.UTC)

	t.Run("a timestamp column arrives as a time", func(t *testing.T) {
		var v any = stamp
		assert.Equal(t, llx.TimeData(stamp), unsafeTime(&v))
	})

	t.Run("a string form is parsed", func(t *testing.T) {
		var v any = "2026-08-11 12:14:31.000 -0700"
		got := unsafeTime(&v)
		assert.NotEqual(t, llx.NilData, got, "a parsable timestamp is not null")
	})

	// An absent value must stay null. Coercing it to the zero time would report
	// the year 1 as a real moment.
	t.Run("a missing cell is null", func(t *testing.T) {
		assert.Equal(t, llx.NilData, unsafeTime(nil))
	})

	t.Run("a nil cell is null", func(t *testing.T) {
		var v any
		assert.Equal(t, llx.NilData, unsafeTime(&v))
	})
}
