// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

// edgesFrom turns a static adjacency map into an edgeFunc.
func edgesFrom(graph map[string][]string) edgeFunc {
	return func(name string) ([]string, error) {
		return graph[name], nil
	}
}

func TestWalkRoles(t *testing.T) {
	t.Run("transitive reach excludes the seed", func(t *testing.T) {
		// ANALYST -> REPORTER -> PUBLIC
		graph := map[string][]string{
			"ANALYST":  {"REPORTER"},
			"REPORTER": {"PUBLIC"},
		}

		reached, err := walkRoles(edgesFrom(graph), []string{"ANALYST"})
		require.NoError(t, err)
		assert.Equal(t, []string{"REPORTER", "PUBLIC"}, reached)
	})

	t.Run("a role reachable by two paths appears once", func(t *testing.T) {
		// Both branches of the diamond land on PUBLIC.
		graph := map[string][]string{
			"ADMIN":    {"ANALYST", "REPORTER"},
			"ANALYST":  {"PUBLIC"},
			"REPORTER": {"PUBLIC"},
		}

		reached, err := walkRoles(edgesFrom(graph), []string{"ADMIN"})
		require.NoError(t, err)
		assert.Equal(t, []string{"ANALYST", "REPORTER", "PUBLIC"}, reached)
	})

	t.Run("a cycle terminates", func(t *testing.T) {
		// Snowflake rejects a grant that would close a loop, but the walk must
		// not depend on the server for termination.
		graph := map[string][]string{
			"A": {"B"},
			"B": {"C"},
			"C": {"A"},
		}

		reached, err := walkRoles(edgesFrom(graph), []string{"A"})
		require.NoError(t, err)
		assert.Equal(t, []string{"B", "C"}, reached)
	})

	t.Run("seeds are never reported as reached", func(t *testing.T) {
		graph := map[string][]string{
			"ADMIN":   {"ANALYST"},
			"ANALYST": {"ADMIN"},
		}

		reached, err := walkRoles(edgesFrom(graph), []string{"ADMIN", "ANALYST"})
		require.NoError(t, err)
		assert.Empty(t, reached)
	})

	t.Run("multiple seeds merge without duplicates", func(t *testing.T) {
		graph := map[string][]string{
			"ANALYST":  {"PUBLIC"},
			"REPORTER": {"PUBLIC"},
		}

		reached, err := walkRoles(edgesFrom(graph), []string{"ANALYST", "REPORTER"})
		require.NoError(t, err)
		assert.Equal(t, []string{"PUBLIC"}, reached)
	})

	t.Run("an edge lookup failure is reported", func(t *testing.T) {
		boom := errors.New("insufficient privileges")
		_, err := walkRoles(func(string) ([]string, error) { return nil, boom }, []string{"ADMIN"})
		assert.ErrorIs(t, err, boom)
	})
}

func TestCollectRoleHolders(t *testing.T) {
	// SYSADMIN is granted to PLATFORM, which is granted to dana. bob holds
	// ACCOUNTADMIN directly. Walking up from ACCOUNTADMIN must find both.
	parents := map[string][]string{
		"ACCOUNTADMIN": {"SYSADMIN"},
		"SYSADMIN":     {"PLATFORM"},
	}
	holders := map[string][]string{
		"ACCOUNTADMIN": {"bob"},
		"PLATFORM":     {"dana"},
	}

	users, err := collectRoleHolders(edgesFrom(parents), edgesFrom(holders), "ACCOUNTADMIN")
	require.NoError(t, err)
	assert.Equal(t, []string{"bob", "dana"}, users)
}

func TestCollectRoleHoldersDeduplicatesUsers(t *testing.T) {
	// carol reaches the role down two separate branches.
	parents := map[string][]string{
		"ACCOUNTADMIN": {"OPS", "SECURITY"},
	}
	holders := map[string][]string{
		"OPS":      {"carol"},
		"SECURITY": {"carol", "erin"},
	}

	users, err := collectRoleHolders(edgesFrom(parents), edgesFrom(holders), "ACCOUNTADMIN")
	require.NoError(t, err)
	assert.Equal(t, []string{"carol", "erin"}, users)
}

func TestCollectRoleHoldersWithNoHolders(t *testing.T) {
	users, err := collectRoleHolders(edgesFrom(nil), edgesFrom(nil), "ORGADMIN")
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestMemoGrants(t *testing.T) {
	newCache := func() *snowflakeGrantCache {
		return &snowflakeGrantCache{toRole: map[string]grantResult[snowflakeGrant]{}}
	}

	t.Run("a success is fetched once", func(t *testing.T) {
		cache := newCache()
		calls := 0
		fetch := func() ([]snowflakeGrant, error) {
			calls++
			return []snowflakeGrant{{privilege: "SELECT"}}, nil
		}

		for range 3 {
			grants, err := memoGrants(cache, cache.toRole, "ANALYST", fetch)
			require.NoError(t, err)
			require.Len(t, grants, 1)
		}
		assert.Equal(t, 1, calls)
	})

	t.Run("a failure is fetched once and reported every time", func(t *testing.T) {
		// A role the scanning session cannot read is reached once per role
		// whose hierarchy passes through it; retrying would multiply the
		// statements against an account already refusing them.
		cache := newCache()
		boom := errors.New("insufficient privileges")
		calls := 0
		fetch := func() ([]snowflakeGrant, error) {
			calls++
			return nil, boom
		}

		for range 3 {
			_, err := memoGrants(cache, cache.toRole, "LOCKED", fetch)
			assert.ErrorIs(t, err, boom)
		}
		assert.Equal(t, 1, calls)
	})

	t.Run("names are memoized independently", func(t *testing.T) {
		cache := newCache()
		calls := 0
		fetch := func() ([]snowflakeGrant, error) {
			calls++
			return nil, nil
		}

		_, err := memoGrants(cache, cache.toRole, "ANALYST", fetch)
		require.NoError(t, err)
		_, err = memoGrants(cache, cache.toRole, "REPORTER", fetch)
		require.NoError(t, err)
		assert.Equal(t, 2, calls)
	})
}

func TestNameSet(t *testing.T) {
	s := newNameSet("a")

	assert.False(t, s.add("a"), "a name already present is not added again")
	assert.False(t, s.add(""), "an empty name is never recorded")
	assert.True(t, s.add("b"))
	assert.Equal(t, []string{"a", "b"}, s.order, "insertion order is preserved")
}

func TestParseUserRoleGrants(t *testing.T) {
	createdOn := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	cell := func(v any) *any { return &v }

	rows := []map[string]*any{
		{
			"created_on": cell(createdOn),
			"role":       cell("ANALYST"),
			"granted_by": cell("SECURITYADMIN"),
		},
		{
			// Quoted identifiers reach us with the quotes attached.
			"role":       cell(`"Mixed Case Role"`),
			"granted_by": cell(""),
			"created_on": cell(nil),
		},
		{
			// A row with no role names nothing and is dropped.
			"role":       cell(""),
			"granted_by": cell("SECURITYADMIN"),
			"created_on": cell(createdOn),
		},
	}

	grants := parseUserRoleGrants(rows)
	require.Len(t, grants, 2)

	assert.Equal(t, "ANALYST", grants[0].role)
	assert.Equal(t, "SECURITYADMIN", grants[0].grantedBy)
	assert.Equal(t, &createdOn, grants[0].createdOn.Value)

	assert.Equal(t, "Mixed Case Role", grants[1].role)
	assert.Equal(t, types.Nil, grants[1].createdOn.Type, "a missing timestamp resolves to null")
}

func TestSnowflakeGrantID(t *testing.T) {
	grant := snowflakeGrant{
		privilege:   "SELECT",
		grantedOn:   string(sdk.ObjectTypeTable),
		name:        `"DB"."SCH"."T"`,
		grantedTo:   string(sdk.ObjectTypeRole),
		granteeName: "ANALYST",
	}

	assert.Equal(t, `ANALYST/ROLE/SELECT/TABLE/"DB"."SCH"."T"`, snowflakeGrantID(grant))

	// The same privilege on a different object is a different grant.
	other := grant
	other.name = `"DB"."SCH"."OTHER"`
	assert.NotEqual(t, snowflakeGrantID(grant), snowflakeGrantID(other))

	// The same object granted to a different role is a different grant.
	otherGrantee := grant
	otherGrantee.granteeName = "REPORTER"
	assert.NotEqual(t, snowflakeGrantID(grant), snowflakeGrantID(otherGrantee))
}

func TestSnowflakeGrantIDWithoutName(t *testing.T) {
	// Account-level privileges carry no object name.
	grant := snowflakeGrant{
		privilege:   "CREATE INTEGRATION",
		grantedOn:   string(sdk.ObjectTypeAccount),
		grantedTo:   string(sdk.ObjectTypeRole),
		granteeName: "ANALYST",
	}

	assert.Equal(t, "ANALYST/ROLE/CREATE INTEGRATION/ACCOUNT/", snowflakeGrantID(grant))
}
