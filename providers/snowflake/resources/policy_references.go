// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// queryPolicyReferences returns every entity a governance policy is attached
// to, as reported by INFORMATION_SCHEMA.POLICY_REFERENCES. It is shared by the
// masking-policy and row-access-policy resources, which both expose a
// references() field backed by the same table function.
//
// INFORMATION_SCHEMA.POLICY_REFERENCES is database-scoped, so we address the
// function through the policy's own database. The database name is a SQL
// identifier and cannot be bound as a parameter (Snowflake's parser resolves it
// at compile time), so we escape it (`"` -> `""`) and quote it inline. The
// POLICY_NAME argument IS bindable: gosnowflake supports `?` inside table
// functions (see github.com/snowflakedb/gosnowflake doc.go), and it works for
// named arguments too. We pass the policy's fully qualified name there.
func queryPolicyReferences(runtime *plugin.Runtime, databaseName, schemaName, name string) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	db := conn.Client().GetConn()
	ctx := context.Background()

	fqName := sdk.NewSchemaObjectIdentifier(databaseName, schemaName, name).FullyQualifiedName()
	quotedDB := `"` + strings.ReplaceAll(databaseName, `"`, `""`) + `"`
	q := `SELECT POLICY_DB, POLICY_SCHEMA, POLICY_NAME, POLICY_KIND,
                  REF_DATABASE_NAME, REF_SCHEMA_NAME, REF_ENTITY_NAME, REF_ENTITY_DOMAIN,
                  REF_COLUMN_NAME, REF_ARG_COLUMN_NAMES,
                  TAG_DATABASE, TAG_SCHEMA, TAG_NAME,
                  POLICY_STATUS
           FROM TABLE(` + quotedDB + `.INFORMATION_SCHEMA.POLICY_REFERENCES(POLICY_NAME => ?))`

	rows, err := db.QueryxContext(ctx, q, fqName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []any{}
	for rows.Next() {
		var pdb, pschema, pname, pkind, refdb, refschema, refname, refdomain, refcol, refargs, tagdb, tagschema, tagname, status *string
		if err := rows.Scan(&pdb, &pschema, &pname, &pkind, &refdb, &refschema, &refname, &refdomain, &refcol, &refargs, &tagdb, &tagschema, &tagname, &status); err != nil {
			return nil, err
		}
		ref, err := newMqlSnowflakePolicyReference(runtime, fqName, pdb, pschema, pname, pkind, refdb, refschema, refname, refdomain, refcol, refargs, tagdb, tagschema, tagname, status)
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
