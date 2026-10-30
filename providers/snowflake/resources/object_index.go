// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// Account-wide name indexes for the objects other resources point at.
//
// A reference such as snowflake.table.database is resolved through NewResource,
// and NewResource runs the target's init before the runtime cache is consulted.
// The init issues a statement, so a reference held by N objects costs N
// statements even though every one of them resolves against the same small set
// of objects. Listing an account's tables and reading each one's database was
// one SHOW DATABASES LIKE per table.
//
// Each index is one account-wide statement, memoized on the account resource
// together with its error, so an unreadable listing is not retried per item.
// This mirrors the roleIndex and userIndex the role hierarchy already uses.
//
// A miss is never an answer. An index that could not be read, an index that was
// truncated (SHOW output is row-capped, so a very large account can produce a
// partial listing), and a name the account simply does not list all fall
// through to the per-item lookup that was there before, which is what keeps the
// change monotonic: the same references resolve, with fewer statements.
//
// Tables and stages are deliberately not indexed. Their references have a
// single caller each (a materialized view's source table, a stream's table, an
// external table's stage), and the per-item lookups they use are already scoped
// with IN SCHEMA plus LIKE. An account-wide SHOW TABLES or SHOW STAGES walks
// every schema in the account, so for those two an index would be more work
// than the lookups it replaces, and on an account big enough for the row cap to
// bite it would be paid on top of them.

// memoIndex holds one account-wide name index and the outcome of building it.
//
// The failure is memoized alongside the value: a scanning role that cannot read
// the listing cannot read it on the next item either, so retrying would
// multiply statements against exactly the account already refusing them.
type memoIndex[T any] struct {
	once  sync.Once
	index map[string]T
	err   error
}

// get returns the memoized index, running build on the first call. MQL
// evaluates blocks in goroutines, so many resources reach the same index at
// once; sync.Once is what makes them share one listing rather than race to
// issue their own, and it establishes the happens-before that lets every reader
// see the finished map.
func (m *memoIndex[T]) get(build func() (map[string]T, error)) (map[string]T, error) {
	m.once.Do(func() {
		m.index, m.err = build()
	})
	return m.index, m.err
}

// lookupIndexed returns the entry an index holds for key. A nil index (the
// listing failed, so nothing was built), an empty key, and a name that is not
// present are all reported the same way, because the caller treats all three as
// a miss and falls back.
func lookupIndexed[T any](index map[string]T, key string) (T, bool) {
	var zero T
	if index == nil || key == "" {
		return zero, false
	}
	entry, ok := index[key]
	if !ok {
		return zero, false
	}
	return entry, true
}

// databaseIndexKey normalizes a database name into its index key. Snowflake
// reports identifiers quoted in some result sets and bare in others, so both the
// build and the lookup go through the SDK's identifier type rather than using
// the raw string.
func databaseIndexKey(name string) string {
	return sdk.NewAccountObjectIdentifier(name).Name()
}

// schemaIndexKey normalizes a database/schema pair into its index key. Schemas
// are only unique within a database, so the key is the qualified name.
func schemaIndexKey(databaseName, name string) string {
	if databaseName == "" || name == "" {
		return ""
	}
	return sdk.NewDatabaseObjectIdentifier(databaseName, name).FullyQualifiedName()
}

// warehouseIndexKey normalizes a warehouse name into its index key.
func warehouseIndexKey(name string) string {
	return sdk.NewAccountObjectIdentifier(name).Name()
}

func buildDatabaseIndex(databases []sdk.Database) map[string]sdk.Database {
	index := make(map[string]sdk.Database, len(databases))
	for i := range databases {
		key := databaseIndexKey(databases[i].Name)
		if key == "" {
			continue
		}
		index[key] = databases[i]
	}
	return index
}

func buildSchemaIndex(schemas []sdk.Schema) map[string]sdk.Schema {
	index := make(map[string]sdk.Schema, len(schemas))
	for i := range schemas {
		key := schemaIndexKey(schemas[i].DatabaseName, schemas[i].Name)
		if key == "" {
			continue
		}
		index[key] = schemas[i]
	}
	return index
}

func buildWarehouseIndex(warehouses []sdk.Warehouse) map[string]sdk.Warehouse {
	index := make(map[string]sdk.Warehouse, len(warehouses))
	for i := range warehouses {
		key := warehouseIndexKey(warehouses[i].Name)
		if key == "" {
			continue
		}
		index[key] = warehouses[i]
	}
	return index
}

// databaseIndex maps database names to the SHOW DATABASES row describing them.
func (r *mqlSnowflakeAccount) databaseIndex() (map[string]sdk.Database, error) {
	return r.cachedDatabaseIndex.get(func() (map[string]sdk.Database, error) {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		databases, err := conn.Client().Databases.Show(context.Background(), &sdk.ShowDatabaseRequest{})
		if err != nil {
			return nil, err
		}
		return buildDatabaseIndex(databases), nil
	})
}

// schemaIndex maps qualified schema names to the SHOW SCHEMAS row describing
// them.
func (r *mqlSnowflakeAccount) schemaIndex() (map[string]sdk.Schema, error) {
	return r.cachedSchemaIndex.get(func() (map[string]sdk.Schema, error) {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		schemas, err := conn.Client().Schemas.Show(context.Background(), &sdk.ShowSchemaRequest{
			In: &sdk.ExtendedIn{Account: new(true)},
		})
		if err != nil {
			return nil, err
		}
		return buildSchemaIndex(schemas), nil
	})
}

// warehouseIndex maps warehouse names to the SHOW WAREHOUSES row describing
// them.
func (r *mqlSnowflakeAccount) warehouseIndex() (map[string]sdk.Warehouse, error) {
	return r.cachedWarehouseIndex.get(func() (map[string]sdk.Warehouse, error) {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		warehouses, err := conn.Client().Warehouses.Show(context.Background(), &sdk.ShowWarehouseRequest{})
		if err != nil {
			return nil, err
		}
		return buildWarehouseIndex(warehouses), nil
	})
}

// indexedDatabase returns the indexed row for a database name, or false when the
// caller should fall back to the per-name lookup.
func indexedDatabase(runtime *plugin.Runtime, name string) (sdk.Database, bool) {
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return sdk.Database{}, false
	}
	index, err := account.databaseIndex()
	if err != nil {
		return sdk.Database{}, false
	}
	return lookupIndexed(index, databaseIndexKey(name))
}

// indexedSchema returns the indexed row for a database/schema pair, or false
// when the caller should fall back to the per-name lookup.
func indexedSchema(runtime *plugin.Runtime, databaseName, name string) (sdk.Schema, bool) {
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return sdk.Schema{}, false
	}
	index, err := account.schemaIndex()
	if err != nil {
		return sdk.Schema{}, false
	}
	return lookupIndexed(index, schemaIndexKey(databaseName, name))
}

// indexedWarehouse returns the indexed row for a warehouse name, or false when
// the caller should fall back to the per-name lookup.
func indexedWarehouse(runtime *plugin.Runtime, name string) (sdk.Warehouse, bool) {
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return sdk.Warehouse{}, false
	}
	index, err := account.warehouseIndex()
	if err != nil {
		return sdk.Warehouse{}, false
	}
	return lookupIndexed(index, warehouseIndexKey(name))
}
