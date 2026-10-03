// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mssql/connection"
)

func (r *mqlMssql) id() (string, error) {
	return "mssql", nil
}

// mssqlConnection returns the active connection for a resource's runtime.
func mssqlConnection(runtime *plugin.Runtime) *connection.MssqlConnection {
	return runtime.Connection.(*connection.MssqlConnection)
}

// mssqlClient returns the shared database handle for a resource's runtime.
func mssqlClient(runtime *plugin.Runtime) (*sql.DB, error) {
	return mssqlConnection(runtime).Client()
}

func mssqlContext() context.Context {
	return context.Background()
}

// quoteName brackets a SQL Server identifier and escapes embedded brackets so
// it is safe to interpolate a database or object name into a query.
func quoteName(name string) string {
	return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
}

// sidString renders a binary security identifier in canonical S-1-5-... form so
// it joins to the identifier an Active Directory graph uses. Values that are
// not valid NT SIDs (for example the 16-byte SID of a SQL login) fall back to a
// 0x hex string, and an empty SID renders as an empty string.
func sidString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// Guard the length before indexing the revision and sub-authority-count
	// bytes; short principal SIDs would otherwise panic.
	if len(b) < 8 {
		return "0x" + strings.ToUpper(hex.EncodeToString(b))
	}
	revision := b[0]
	subCount := int(b[1])
	if revision != 1 || len(b) != 8+4*subCount {
		return "0x" + strings.ToUpper(hex.EncodeToString(b))
	}
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(b[i])
	}
	s := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subCount; i++ {
		off := 8 + 4*i
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[off:off+4]))
	}
	return s
}

// isActiveDirectoryType reports whether a SQL Server principal type maps to a
// Windows/Active Directory principal.
func isActiveDirectoryType(typeDesc string) bool {
	switch typeDesc {
	case "WINDOWS_LOGIN", "WINDOWS_GROUP", "WINDOWS_USER", "EXTERNAL_USER", "EXTERNAL_GROUP":
		return true
	default:
		return false
	}
}

// --- stable identifier builders ---------------------------------------------

func serverPrincipalID(instanceID, name string) string {
	return name + "@" + instanceID
}

func databaseIdentifier(instanceID, database string) string {
	return instanceID + "\\" + database
}

func databasePrincipalID(databaseID, name string) string {
	return name + "@" + databaseID
}

// permissionResourceID mints a stable, unique cache key for a permission row so
// each grant on a principal is a distinct resource rather than colliding on a
// shared id. majorID and minorID identify the securable within its class (for
// example the login an IMPERSONATE applies to, or the table and column of an
// object grant), so the same permission on two securables stays two rows.
func permissionResourceID(parentID, class string, majorID, minorID int64, permission, state, grantee string) string {
	return fmt.Sprintf("%s/perm/%s/%d/%d/%s/%s/%s", parentID, class, majorID, minorID, permission, state, grantee)
}

// securableName returns the name of the securable a permission applies to.
// The server itself has no name, and a DATABASE-class permission applies to
// the database it was read from; every other class carries the name resolved
// from its catalog view.
func securableName(class, database, resolved string) string {
	switch class {
	case "SERVER":
		return ""
	case "DATABASE":
		return database
	default:
		return resolved
	}
}

// auditedAction renders one row of an audit specification: an action group by
// its name, and an object-level action as the specification writes it, for
// example "SELECT ON OBJECT::dbo.t1 BY public".
func auditedAction(name, class, securable, principal string, isGroup bool) string {
	if isGroup {
		return name
	}
	prefix := class
	if class == "OBJECT_OR_COLUMN" {
		prefix = "OBJECT"
	}
	out := name + " ON " + prefix + "::" + securable
	if principal != "" {
		out += " BY " + principal
	}
	return out
}

// nullInt maps a nullable integer column to an int, or null when the column
// is NULL (for example a value the scanning login cannot see).
func nullInt(v sql.NullInt64) *llx.RawData {
	if !v.Valid {
		return llx.NilData
	}
	return llx.IntData(v.Int64)
}

// nullString maps a nullable string column to a string, or null when NULL.
func nullString(v sql.NullString) *llx.RawData {
	if !v.Valid {
		return llx.NilData
	}
	return llx.StringData(v.String)
}

// --- shared builders --------------------------------------------------------

// permissionRow is one row of sys.server_permissions or
// sys.database_permissions with its securable resolved to a name.
type permissionRow struct {
	class, permission, state, grantee string
	majorID, minorID                  int64
	securable, column                 string
}

// scanPermissionRow reads a row selected by serverPermissionsFor or
// databasePermissionsFor.
func scanPermissionRow(rows *sql.Rows, database string) (permissionRow, error) {
	var r permissionRow
	err := rows.Scan(&r.class, &r.majorID, &r.minorID, &r.permission, &r.state, &r.grantee, &r.securable, &r.column)
	r.securable = securableName(r.class, database, r.securable)
	return r, err
}

// newMssqlPermission creates a permission resource with a composite __id.
func newMssqlPermission(runtime *plugin.Runtime, parentID string, r permissionRow) (*mqlMssqlPermission, error) {
	res, err := CreateResource(runtime, "mssql.permission", map[string]*llx.RawData{
		"__id":           llx.StringData(permissionResourceID(parentID, r.class, r.majorID, r.minorID, r.permission, r.state, r.grantee)),
		"permissionName": llx.StringData(r.permission),
		"state":          llx.StringData(r.state),
		"class":          llx.StringData(r.class),
		"granteeName":    llx.StringData(r.grantee),
		"securableName":  llx.StringData(r.securable),
		"columnName":     llx.StringData(r.column),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMssqlPermission), nil
}

// serverPermissionsFor lists the explicit server-level permissions granted to a
// single principal, or all server permissions when principalID is nil.
func serverPermissionsFor(runtime *plugin.Runtime, parentID string, principalID *int64) ([]any, error) {
	client, err := mssqlClient(runtime)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT p.class_desc, CONVERT(BIGINT, p.major_id), CONVERT(BIGINT, p.minor_id),
			p.permission_name, p.state_desc, ISNULL(pr.name, ''),
			ISNULL(CASE p.class
				WHEN 101 THEN sp.name
				WHEN 105 THEN e.name
			END, ''), ''
		FROM sys.server_permissions p
		LEFT JOIN sys.server_principals pr ON p.grantee_principal_id = pr.principal_id
		LEFT JOIN sys.server_principals sp ON p.class = 101 AND p.major_id = sp.principal_id
		LEFT JOIN sys.endpoints e ON p.class = 105 AND p.major_id = e.endpoint_id`
	if principalID != nil {
		query += "\n\t\tWHERE p.grantee_principal_id = @p1"
	}

	var rows *sql.Rows
	if principalID != nil {
		rows, err = client.QueryContext(mssqlContext(), query, sql.Named("p1", *principalID))
	} else {
		rows, err = client.QueryContext(mssqlContext(), query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		row, err := scanPermissionRow(rows, "")
		if err != nil {
			return nil, err
		}
		p, err := newMssqlPermission(runtime, parentID, row)
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// databasePermissionsFor lists the explicit database-level permissions granted
// to a single principal, or all database permissions when principalID is nil.
func databasePermissionsFor(runtime *plugin.Runtime, database, parentID string, principalID *int64) ([]any, error) {
	client, err := mssqlClient(runtime)
	if err != nil {
		return nil, err
	}
	db := quoteName(database)

	query := `
		SELECT p.class_desc, CONVERT(BIGINT, p.major_id), CONVERT(BIGINT, p.minor_id),
			p.permission_name, p.state_desc, ISNULL(pr.name, ''),
			ISNULL(CASE p.class
				WHEN 1 THEN COALESCE(os.name + '.' + o.name,
					OBJECT_SCHEMA_NAME(p.major_id, DB_ID(@dbname)) + '.' + OBJECT_NAME(p.major_id, DB_ID(@dbname)))
				WHEN 3 THEN s.name
				WHEN 4 THEN tp.name
				WHEN 5 THEN asm.name
				WHEN 6 THEN ts.name + '.' + ty.name
				WHEN 24 THEN sk.name
				WHEN 25 THEN cert.name
				WHEN 26 THEN ak.name
			END, ''),
			ISNULL(c.name, '')
		FROM ` + db + `.sys.database_permissions p
		LEFT JOIN ` + db + `.sys.database_principals pr ON p.grantee_principal_id = pr.principal_id
		LEFT JOIN ` + db + `.sys.all_objects o ON p.class = 1 AND p.major_id = o.object_id
		LEFT JOIN ` + db + `.sys.schemas os ON o.schema_id = os.schema_id
		LEFT JOIN ` + db + `.sys.all_columns c ON p.class = 1 AND p.minor_id > 0 AND p.major_id = c.object_id AND p.minor_id = c.column_id
		LEFT JOIN ` + db + `.sys.schemas s ON p.class = 3 AND p.major_id = s.schema_id
		LEFT JOIN ` + db + `.sys.database_principals tp ON p.class = 4 AND p.major_id = tp.principal_id
		LEFT JOIN ` + db + `.sys.assemblies asm ON p.class = 5 AND p.major_id = asm.assembly_id
		LEFT JOIN ` + db + `.sys.types ty ON p.class = 6 AND p.major_id = ty.user_type_id
		LEFT JOIN ` + db + `.sys.schemas ts ON ty.schema_id = ts.schema_id
		LEFT JOIN ` + db + `.sys.symmetric_keys sk ON p.class = 24 AND p.major_id = sk.symmetric_key_id
		LEFT JOIN ` + db + `.sys.certificates cert ON p.class = 25 AND p.major_id = cert.certificate_id
		LEFT JOIN ` + db + `.sys.asymmetric_keys ak ON p.class = 26 AND p.major_id = ak.asymmetric_key_id`
	if principalID != nil {
		query += "\n\t\tWHERE p.grantee_principal_id = @p1"
	}

	var rows *sql.Rows
	if principalID != nil {
		rows, err = client.QueryContext(mssqlContext(), query, sql.Named("p1", *principalID), sql.Named("dbname", database))
	} else {
		rows, err = client.QueryContext(mssqlContext(), query, sql.Named("dbname", database))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		row, err := scanPermissionRow(rows, database)
		if err != nil {
			return nil, err
		}
		p, err := newMssqlPermission(runtime, parentID, row)
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}
