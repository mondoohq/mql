// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const bigqueryScope = "https://www.googleapis.com/auth/bigquery"

// listedTable stands in for what dataset.tables() produces: a table carrying its
// full metadata.
func listedTable(t *testing.T, runtime *plugin.Runtime, project, dataset, table string, numRows int64) *mqlGcpProjectBigqueryServiceTable {
	t.Helper()
	res, err := CreateResource(runtime, "gcp.project.bigqueryService.table", map[string]*llx.RawData{
		"id":        llx.StringData(table),
		"projectId": llx.StringData(project),
		"datasetId": llx.StringData(dataset),
		"name":      llx.StringData(table),
		"location":  llx.StringData("US"),
		"numRows":   llx.IntData(numRows),
	})
	require.NoError(t, err)
	return res.(*mqlGcpProjectBigqueryServiceTable)
}

// serveTableMetadata answers the BigQuery tables.get call for one table.
func serveTableMetadata(env *testEnv, project, dataset, table string, numRows int64, calls *int) {
	path := fmt.Sprintf("/bigquery/v2/projects/%s/datasets/%s/tables/%s", project, dataset, table)
	env.Mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			*calls++
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"kind": "bigquery#table",
			"tableReference": {"projectId": %q, "datasetId": %q, "tableId": %q},
			"friendlyName": %q,
			"location": "US",
			"type": "TABLE",
			"numRows": "%d",
			"numBytes": "8192"
		}`, project, dataset, table, table, numRows)
	})
}

// TestBaseTableResolutionDoesNotPoisonTheListedTable is the regression test.
//
// gcp.project.bigqueryService.table has no init, so building one from a bare
// project/dataset/table reference produces a resource whose every other field is
// unset. The runtime cache is first-writer-wins on the table's id, so that
// stand-in does not merely shortchange its own reader: it takes the key, and the
// later full listing of the same table is handed the stand-in back instead of
// the metadata it just fetched.
//
// This bites across datasets, where a snapshot in one dataset references a base
// table in another and the reference is resolved before that dataset is listed.
func TestBaseTableResolutionDoesNotPoisonTheListedTable(t *testing.T) {
	env := setupTestEnv(t, []string{bigqueryScope})
	serveTableMetadata(env, "test-project", "prod", "orders", 4200, nil)

	// A snapshot in dataset "snaps" whose base table lives in dataset "prod".
	snapshot := listedTable(t, env.Runtime, "test-project", "snaps", "orders_snapshot", 0)
	ref := &bigquery.Table{ProjectID: "test-project", DatasetID: "prod", TableID: "orders"}

	// Resolved before dataset "prod" is ever listed.
	resolved, err := snapshot.resolveBaseTable(ref)
	require.NoError(t, err)
	require.NotNil(t, resolved)

	// Dataset "prod" is listed afterwards, with the base table's real metadata.
	listed := listedTable(t, env.Runtime, "test-project", "prod", "orders", 4200)

	assert.True(t, listed.NumRows.IsSet(),
		"numRows must be set on the listed table")
	assert.Equal(t, int64(4200), listed.NumRows.Data,
		"listing a table after its reference was resolved must yield real metadata, not a reference stand-in")
}

// TestBaseTableResolutionReusesAListedTable pins that an already-listed base
// table costs no API call. Resolving through the referenced dataset's table list
// would instead cost one call per table in that dataset to answer one reference.
func TestBaseTableResolutionReusesAListedTable(t *testing.T) {
	env := setupTestEnv(t, []string{bigqueryScope})
	calls := 0
	serveTableMetadata(env, "test-project", "prod", "orders", 4200, &calls)

	listedTable(t, env.Runtime, "test-project", "prod", "orders", 4200)
	snapshot := listedTable(t, env.Runtime, "test-project", "snaps", "orders_snapshot", 0)

	resolved, err := snapshot.resolveBaseTable(&bigquery.Table{
		ProjectID: "test-project", DatasetID: "prod", TableID: "orders",
	})
	require.NoError(t, err)
	require.NotNil(t, resolved)

	assert.Equal(t, int64(4200), resolved.NumRows.Data,
		"a resolved base table must be the real table")
	assert.Zero(t, calls, "an already-listed base table must not be re-fetched")
}

// TestBaseTableResolutionFetchesAnUnlistedTable covers the miss path: a base
// table in a dataset this query never listed still resolves to real metadata.
func TestBaseTableResolutionFetchesAnUnlistedTable(t *testing.T) {
	env := setupTestEnv(t, []string{bigqueryScope})
	calls := 0
	serveTableMetadata(env, "test-project", "prod", "orders", 77, &calls)

	snapshot := listedTable(t, env.Runtime, "test-project", "snaps", "orders_snapshot", 0)
	resolved, err := snapshot.resolveBaseTable(&bigquery.Table{
		ProjectID: "test-project", DatasetID: "prod", TableID: "orders",
	})
	require.NoError(t, err)
	require.NotNil(t, resolved)

	assert.Equal(t, int64(77), resolved.NumRows.Data)
	assert.Equal(t, "orders", resolved.Name.Data)
	assert.Equal(t, 1, calls, "exactly one table is fetched, not the whole dataset")
}

// TestBaseTableResolutionToleratesAMissingBaseTable keeps a snapshot readable
// after its base table is deleted. The reference outlives the table, so this is
// an ordinary state and must not fail the listing that contains the snapshot.
func TestBaseTableResolutionToleratesAMissingBaseTable(t *testing.T) {
	env := setupTestEnv(t, []string{bigqueryScope})
	env.Mux.HandleFunc("/bigquery/v2/projects/test-project/datasets/prod/tables/gone",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"code":404,"message":"Not found: Table gone"}}`)
		})

	snapshot := listedTable(t, env.Runtime, "test-project", "snaps", "orders_snapshot", 0)
	resolved, err := snapshot.resolveBaseTable(&bigquery.Table{
		ProjectID: "test-project", DatasetID: "prod", TableID: "gone",
	})

	require.NoError(t, err, "a deleted base table must not fail the query")
	assert.Nil(t, resolved, "a deleted base table resolves to null")
}

// TestBaseTableResolutionToleratesAForbiddenBaseTable covers the other half of
// "nothing to read here": a base table in a project this caller cannot see.
// Like a deleted table, it resolves to null rather than failing the listing.
func TestBaseTableResolutionToleratesAForbiddenBaseTable(t *testing.T) {
	env := setupTestEnv(t, []string{bigqueryScope})
	env.Mux.HandleFunc("/bigquery/v2/projects/other-project/datasets/prod/tables/orders",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":{"code":403,"message":"Access Denied: Table orders"}}`)
		})

	snapshot := listedTable(t, env.Runtime, "test-project", "snaps", "orders_snapshot", 0)
	resolved, err := snapshot.resolveBaseTable(&bigquery.Table{
		ProjectID: "other-project", DatasetID: "prod", TableID: "orders",
	})

	require.NoError(t, err, "an unreadable base table must not fail the query")
	assert.Nil(t, resolved, "an unreadable base table resolves to null")
}

// TestBaseTableResolutionSurfacesRealFailures is the counterweight to the two
// tolerate tests. Only "gone" and "cannot see it" mean null; anything else is a
// failure to read a table that exists, and folding it into null would report an
// absent base table as fact. A check asserting a snapshot has no base table
// would then pass on a failed request rather than on a real answer.
func TestBaseTableResolutionSurfacesRealFailures(t *testing.T) {
	env := setupTestEnv(t, []string{bigqueryScope})
	env.Mux.HandleFunc("/bigquery/v2/projects/test-project/datasets/prod/tables/orders",
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"code":400,"message":"Invalid request"}}`)
		})

	snapshot := listedTable(t, env.Runtime, "test-project", "snaps", "orders_snapshot", 0)
	resolved, err := snapshot.resolveBaseTable(&bigquery.Table{
		ProjectID: "test-project", DatasetID: "prod", TableID: "orders",
	})

	require.Error(t, err, "a failure that is not a missing or unreadable table must surface")
	assert.Nil(t, resolved)
}

// TestResolveBaseTableHandlesAbsentReference keeps the null path intact for a
// table that is neither a snapshot nor a clone.
func TestResolveBaseTableHandlesAbsentReference(t *testing.T) {
	env := setupTestEnv(t, []string{bigqueryScope})
	table := listedTable(t, env.Runtime, "test-project", "prod", "orders", 1)

	resolved, err := table.resolveBaseTable(nil)
	require.NoError(t, err)
	assert.Nil(t, resolved, "a table with no base-table reference resolves to nothing")
}

// TestBigqueryTableCacheKeyMatchesResourceId pins the cache key against the
// identity the runtime actually stores the resource under. If id() changes shape
// and the key does not, every lookup silently misses: correctness survives but
// the fetch-avoidance does not, and the miss is invisible.
func TestBigqueryTableCacheKeyMatchesResourceId(t *testing.T) {
	env := setupTestEnv(t, []string{bigqueryScope})
	table := listedTable(t, env.Runtime, "p", "d", "tbl", 1)

	id, err := table.id()
	require.NoError(t, err)
	assert.Equal(t, "gcp.project.bigqueryService.table\x00"+id, bigqueryTableCacheKey("p", "d", "tbl"))

	cached, ok := env.Runtime.Resources.Get(bigqueryTableCacheKey("p", "d", "tbl"))
	require.True(t, ok, "the key must find the resource the runtime stored")
	assert.Same(t, table, cached)
}
