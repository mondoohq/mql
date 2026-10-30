// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// snowflakeGrant is one row of any SHOW GRANTS variant, read straight from the
// result set.
//
// The SDK's typed reader cannot be used for this statement. Its row converter
// parses the name column into an object identifier, and for a grant on a
// function whose argument is a table it reaches
// datatypes.(*TableDataType).ToLegacyDataTypeSql on a nil receiver and panics.
// Snowflake ships built-in data metric functions with exactly that shape
// (SNOWFLAKE.CORE.ACCEPTED_VALUES(TABLE(DATE)) and its siblings) and grants them
// to ACCOUNTADMIN on every account, so any SHOW GRANTS whose result reaches
// those rows takes the whole field down.
//
// Recovering from the panic would not do: it fires part way through converting
// the result set, so what survives is an empty grant list, and a field that
// reports no privileges where privileges exist is worse than one that errors.
// MQL's three-valued logic makes that failure silent, since an assertion over an
// empty list passes.
type snowflakeGrant struct {
	createdOn   *llx.RawData
	privilege   string
	grantedOn   string
	grantedTo   string
	name        string
	granteeName string
	grantedBy   string
	grantOption bool
}

// showGrantsRaw runs a SHOW GRANTS statement and reads its rows directly.
// Callers build the statement with identifiers rendered by the SDK, so names
// reach it already quoted rather than interpolated raw.
func showGrantsRaw(conn *connection.SnowflakeConnection, statement string) ([]snowflakeGrant, error) {
	rows, err := conn.Client().QueryUnsafe(context.Background(), statement)
	if err != nil {
		return nil, err
	}
	return parseGrantRows(rows), nil
}

// parseGrantRows reads the rows of a SHOW GRANTS result.
//
// A future grant names the object type it will apply to in grant_on/grant_to;
// granted_on/granted_to stay empty until the object exists, so each pair falls
// back to the future form.
func parseGrantRows(rows []map[string]*any) []snowflakeGrant {
	grants := make([]snowflakeGrant, 0, len(rows))
	for _, row := range rows {
		grantedOn := unsafeString(row["granted_on"])
		if grantedOn == "" {
			grantedOn = unsafeString(row["grant_on"])
		}
		grantedTo := unsafeString(row["granted_to"])
		if grantedTo == "" {
			grantedTo = unsafeString(row["grant_to"])
		}

		grants = append(grants, snowflakeGrant{
			createdOn:   unsafeTime(row["created_on"]),
			privilege:   unsafeString(row["privilege"]),
			grantedOn:   grantedOn,
			grantedTo:   grantedTo,
			name:        quoteQualifiedName(unsafeString(row["name"])),
			granteeName: identifierName(unsafeString(row["grantee_name"])),
			grantedBy:   identifierName(unsafeString(row["granted_by"])),
			grantOption: unsafeBool(row["grant_option"]),
		})
	}
	return grants
}

// splitQualifiedName splits a qualified object name on its part separators.
// A dot inside double quotes belongs to the name, and a dot inside parentheses
// belongs to an argument list (a function's arguments arrive as part of its
// name), so neither separates parts.
func splitQualifiedName(name string) []string {
	parts := []string{}
	var current strings.Builder
	inQuotes := false
	depth := 0

	for _, r := range name {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == '(' && !inQuotes:
			depth++
			current.WriteRune(r)
		case r == ')' && !inQuotes:
			if depth > 0 {
				depth--
			}
			current.WriteRune(r)
		case r == '.' && !inQuotes && depth == 0:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	parts = append(parts, current.String())
	return parts
}

// quoteQualifiedName renders a name the way the SDK's FullyQualifiedName does,
// with every part double quoted. The value is what the name field of a grant
// reports, so it is kept in that shape rather than normalized.
func quoteQualifiedName(name string) string {
	if name == "" {
		return ""
	}
	parts := splitQualifiedName(name)
	for i, part := range parts {
		if strings.HasPrefix(part, `"`) && strings.HasSuffix(part, `"`) && len(part) > 1 {
			continue
		}
		parts[i] = `"` + part + `"`
	}
	return strings.Join(parts, ".")
}

// identifierName returns the bare last part of a qualified name, without the
// quoting an identifier carries when it needs it.
func identifierName(name string) string {
	parts := splitQualifiedName(name)
	last := parts[len(parts)-1]
	if len(last) > 1 && strings.HasPrefix(last, `"`) && strings.HasSuffix(last, `"`) {
		last = last[1 : len(last)-1]
		last = strings.ReplaceAll(last, `""`, `"`)
	}
	return last
}
