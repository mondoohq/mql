// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabaseIndexKey(t *testing.T) {
	t.Run("a bare name is its own key", func(t *testing.T) {
		assert.Equal(t, "PROD", databaseIndexKey("PROD"))
	})

	t.Run("a quoted identifier keys the same as the bare name", func(t *testing.T) {
		// SHOW output quotes identifiers in some result sets and not others, so
		// the key has to survive the round trip either way.
		assert.Equal(t, databaseIndexKey("PROD"), databaseIndexKey(`"PROD"`))
	})

	t.Run("case is preserved, not folded", func(t *testing.T) {
		// Snowflake stores an unquoted identifier upper-cased and reports the
		// stored form, so the two are different objects, not two spellings of
		// one. Folding here would make a lowercase-named database shadow an
		// uppercase one.
		assert.NotEqual(t, databaseIndexKey("PROD"), databaseIndexKey("prod"))
	})

	t.Run("an empty name has an empty key", func(t *testing.T) {
		assert.Equal(t, "", databaseIndexKey(""))
	})
}

func TestSchemaIndexKey(t *testing.T) {
	t.Run("the key is qualified by database", func(t *testing.T) {
		// PUBLIC exists in every database, so an unqualified key would collapse
		// them all onto one entry.
		assert.NotEqual(t, schemaIndexKey("PROD", "PUBLIC"), schemaIndexKey("STAGING", "PUBLIC"))
	})

	t.Run("quoted parts key the same as bare parts", func(t *testing.T) {
		assert.Equal(t, schemaIndexKey("PROD", "PUBLIC"), schemaIndexKey(`"PROD"`, `"PUBLIC"`))
	})

	t.Run("either coordinate empty yields an empty key", func(t *testing.T) {
		assert.Equal(t, "", schemaIndexKey("", "PUBLIC"))
		assert.Equal(t, "", schemaIndexKey("PROD", ""))
		assert.Equal(t, "", schemaIndexKey("", ""))
	})

	t.Run("a dot in a name cannot collide with a different split", func(t *testing.T) {
		assert.NotEqual(t, schemaIndexKey("PROD.PUBLIC", "T"), schemaIndexKey("PROD", "PUBLIC.T"))
	})
}

func TestWarehouseIndexKey(t *testing.T) {
	assert.Equal(t, "COMPUTE_WH", warehouseIndexKey("COMPUTE_WH"))
	assert.Equal(t, warehouseIndexKey("COMPUTE_WH"), warehouseIndexKey(`"COMPUTE_WH"`))
	assert.Equal(t, "", warehouseIndexKey(""))
}

func TestBuildDatabaseIndex(t *testing.T) {
	index := buildDatabaseIndex([]sdk.Database{
		{Name: "PROD", Owner: "SYSADMIN"},
		{Name: `"QUOTED_DB"`, Owner: "ACCOUNTADMIN"},
		{Name: "", Owner: "NOBODY"},
	})

	t.Run("a listed database is found by name", func(t *testing.T) {
		db, ok := lookupIndexed(index, databaseIndexKey("PROD"))
		require.True(t, ok)
		assert.Equal(t, "SYSADMIN", db.Owner)
	})

	t.Run("a quoted listing is found by its bare name", func(t *testing.T) {
		db, ok := lookupIndexed(index, databaseIndexKey("QUOTED_DB"))
		require.True(t, ok)
		assert.Equal(t, "ACCOUNTADMIN", db.Owner)
	})

	t.Run("a nameless row is dropped rather than keyed empty", func(t *testing.T) {
		// An empty key would otherwise be handed out for every empty lookup.
		assert.Len(t, index, 2)
	})

	t.Run("a name the account does not list is a miss", func(t *testing.T) {
		_, ok := lookupIndexed(index, databaseIndexKey("ABSENT"))
		assert.False(t, ok)
	})

	t.Run("a differently cased name is a miss, not a wrong hit", func(t *testing.T) {
		// The resolver falls back to the per-name lookup on this, which is what
		// the behavior was before the index existed.
		_, ok := lookupIndexed(index, databaseIndexKey("prod"))
		assert.False(t, ok)
	})
}

func TestBuildSchemaIndex(t *testing.T) {
	index := buildSchemaIndex([]sdk.Schema{
		{Name: "PUBLIC", DatabaseName: "PROD", Owner: "SYSADMIN"},
		{Name: "PUBLIC", DatabaseName: "STAGING", Owner: "DEVELOPER"},
		{Name: "PUBLIC", DatabaseName: ""},
		{Name: "", DatabaseName: "PROD"},
	})

	t.Run("same-named schemas in different databases stay distinct", func(t *testing.T) {
		prod, ok := lookupIndexed(index, schemaIndexKey("PROD", "PUBLIC"))
		require.True(t, ok)
		assert.Equal(t, "SYSADMIN", prod.Owner)

		staging, ok := lookupIndexed(index, schemaIndexKey("STAGING", "PUBLIC"))
		require.True(t, ok)
		assert.Equal(t, "DEVELOPER", staging.Owner)
	})

	t.Run("a row missing either coordinate is dropped", func(t *testing.T) {
		assert.Len(t, index, 2)
	})

	t.Run("a schema in an unlisted database is a miss", func(t *testing.T) {
		_, ok := lookupIndexed(index, schemaIndexKey("ARCHIVE", "PUBLIC"))
		assert.False(t, ok)
	})
}

func TestBuildWarehouseIndex(t *testing.T) {
	index := buildWarehouseIndex([]sdk.Warehouse{
		{Name: "COMPUTE_WH", Owner: "SYSADMIN"},
		{Name: ""},
	})

	wh, ok := lookupIndexed(index, warehouseIndexKey("COMPUTE_WH"))
	require.True(t, ok)
	assert.Equal(t, "SYSADMIN", wh.Owner)

	assert.Len(t, index, 1)

	_, ok = lookupIndexed(index, warehouseIndexKey("ABSENT_WH"))
	assert.False(t, ok)
}

func TestLookupIndexed(t *testing.T) {
	t.Run("a nil index misses instead of panicking", func(t *testing.T) {
		// This is the shape of an index whose listing failed: nothing was built,
		// so every lookup has to fall through to the per-item path.
		var index map[string]sdk.Database
		_, ok := lookupIndexed(index, "PROD")
		assert.False(t, ok)
	})

	t.Run("an empty key misses", func(t *testing.T) {
		index := map[string]sdk.Database{"": {Name: "surprise"}}
		_, ok := lookupIndexed(index, "")
		assert.False(t, ok)
	})

	t.Run("a miss returns the zero value", func(t *testing.T) {
		index := map[string]sdk.Database{"PROD": {Name: "PROD"}}
		db, ok := lookupIndexed(index, "ABSENT")
		assert.False(t, ok)
		assert.Equal(t, sdk.Database{}, db)
	})
}

// TestMemoIndex covers the memo the account indexes are built on. MQL evaluates
// blocks in goroutines, so many resources reach the same index at once; the
// listing must run once and every reader must observe the same map and the same
// error.
func TestMemoIndex(t *testing.T) {
	t.Run("a successful listing runs once and is shared", func(t *testing.T) {
		var (
			memo  memoIndex[sdk.Database]
			calls atomic.Int64
		)
		build := func() (map[string]sdk.Database, error) {
			calls.Add(1)
			return buildDatabaseIndex([]sdk.Database{{Name: "PROD"}}), nil
		}

		results := make([]map[string]sdk.Database, 32)
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				got, err := memo.get(build)
				assert.NoError(t, err)
				results[i] = got
			}(i)
		}
		wg.Wait()

		assert.Equal(t, int64(1), calls.Load())
		for i := range results {
			_, ok := lookupIndexed(results[i], databaseIndexKey("PROD"))
			assert.True(t, ok)
		}
	})

	t.Run("a failed listing is memoized, not retried per reader", func(t *testing.T) {
		var (
			memo  memoIndex[sdk.Database]
			calls atomic.Int64
		)
		build := func() (map[string]sdk.Database, error) {
			calls.Add(1)
			return nil, assert.AnError
		}

		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				got, err := memo.get(build)
				assert.Error(t, err)
				// A failed listing leaves a nil index, which every lookup has to
				// treat as a miss so the caller falls back.
				_, ok := lookupIndexed(got, databaseIndexKey("PROD"))
				assert.False(t, ok)
			})
		}
		wg.Wait()

		assert.Equal(t, int64(1), calls.Load())
	})
}
