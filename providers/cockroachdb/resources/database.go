// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/jackc/pgx/v5"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// publicRole is the pseudo-role that stands for every role in a grant.
const publicRole = "public"

type mqlCockroachdbDatabaseInternal struct {
	cacheOwner string
}

func (r *mqlCockroachdbDatabase) id() (string, error) {
	return "cockroachdb.database/" + r.Name.Data, nil
}

func (r *mqlCockroachdbCluster) databases() ([]any, error) {
	rows, err := query(r.MqlRuntime, `SELECT database_name, owner, COALESCE(primary_region, ''), regions, COALESCE(survival_goal, '')
		FROM [SHOW DATABASES] ORDER BY database_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, owner, primaryRegion, survivalGoal string
		var regions []string
		if err := rows.Scan(&name, &owner, &primaryRegion, &regions, &survivalGoal); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.database", map[string]*llx.RawData{
			"name":          llx.StringData(name),
			"primaryRegion": llx.StringData(primaryRegion),
			"regions":       llx.ArrayData(toAnySlice(regions), types.String),
			"survivalGoal":  llx.StringData(survivalGoal),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlCockroachdbDatabase).cacheOwner = owner
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlCockroachdbDatabase) owner() (*mqlCockroachdbRole, error) {
	return resolveRole(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

func (r *mqlCockroachdbDatabase) grants() ([]any, error) {
	id := r.__id
	return grantList(r.MqlRuntime, id,
		`SELECT grantee, privilege_type, is_grantable FROM [SHOW GRANTS ON DATABASE `+
			pgx.Identifier{r.Name.Data}.Sanitize()+`] ORDER BY grantee, privilege_type`)
}

type mqlCockroachdbTableInternal struct {
	cacheOwner string
}

func (r *mqlCockroachdbTable) id() (string, error) {
	return "cockroachdb.table/" + r.Database.Data + "/" + r.Schema.Data + "/" + r.Name.Data, nil
}

func (r *mqlCockroachdbDatabase) tables() ([]any, error) {
	rows, err := query(r.MqlRuntime, `SELECT schema_name, table_name, owner FROM [SHOW TABLES FROM `+
		pgx.Identifier{r.Name.Data}.Sanitize()+`] WHERE type = 'table' ORDER BY schema_name, table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var schema, name, owner string
		if err := rows.Scan(&schema, &name, &owner); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.table", map[string]*llx.RawData{
			"name":     llx.StringData(name),
			"schema":   llx.StringData(schema),
			"database": llx.StringData(r.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlCockroachdbTable).cacheOwner = owner
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlCockroachdbTable) owner() (*mqlCockroachdbRole, error) {
	return resolveRole(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

func (r *mqlCockroachdbTable) grants() ([]any, error) {
	table := pgx.Identifier{r.Database.Data, r.Schema.Data, r.Name.Data}.Sanitize()
	return grantList(r.MqlRuntime, r.__id,
		`SELECT grantee, privilege_type, is_grantable FROM [SHOW GRANTS ON TABLE `+table+`] ORDER BY grantee, privilege_type`)
}

// grantList reads grantee, privilege, grantable rows into grant resources
// under the given parent.
func grantList(runtime *plugin.Runtime, parentID string, sql string) ([]any, error) {
	rows, err := query(runtime, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var grantee, privilege string
		var grantable bool
		if err := rows.Scan(&grantee, &privilege, &grantable); err != nil {
			return nil, err
		}
		res, err := CreateResource(runtime, "cockroachdb.grant", map[string]*llx.RawData{
			"__id":        llx.StringData(parentID + "/grant/" + grantee + "/" + privilege),
			"grantee":     llx.StringData(grantee),
			"privilege":   llx.StringData(privilege),
			"isGrantable": llx.BoolData(grantable),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlCockroachdbGrant) role() (*mqlCockroachdbRole, error) {
	if r.Grantee.Data == publicRole {
		r.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRole(r.MqlRuntime, r.Grantee.Data, &r.Role)
}
