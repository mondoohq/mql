// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"time"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk/datatypes"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

func (r *mqlSnowflake) id() (string, error) {
	return "snowflake", nil
}

// snowflakeTimeLayouts are the timestamp formats Snowflake renders in the
// string CreatedOn fields that some SDK types leave unparsed (e.g. row-access
// policies, managed accounts). SHOW output uses a space-separated timestamp
// with a numeric zone offset; we also accept RFC3339 as a fallback.
var snowflakeTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02 15:04:05.999999999 -0700",
	"2006-01-02 15:04:05.999 -0700",
	"2006-01-02 15:04:05 -0700",
}

// parseSnowflakeTime converts a Snowflake SHOW timestamp string into time
// RawData, trying each known layout. It returns null RawData for an empty
// string or an unrecognized format so the field resolves to null rather than
// erroring the whole query.
func parseSnowflakeTime(value string) *llx.RawData {
	value = strings.TrimSpace(value)
	if value == "" {
		return llx.NilData
	}
	for _, layout := range snowflakeTimeLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return llx.TimeData(t)
		}
	}
	return llx.NilData
}

// snowflakeTime converts a timestamp the SDK exposes as a plain time.Time into
// time RawData, resolving the zero time to null.
//
// Several SHOW responses read nullable timestamp columns into sql.NullTime and
// only copy the value through when it is valid (for example a dynamic table's
// last_suspended_on, or an external table's last_refreshed_on). A column that
// is NULL therefore reaches us as the zero time rather than as an absent value,
// and rendering it directly would report 0001-01-01T00:00:00Z as though the
// event had happened at the dawn of the common era.
func snowflakeTime(value time.Time) *llx.RawData {
	if value.IsZero() {
		return llx.NilData
	}
	return llx.TimeData(value)
}

// legacyDataTypeName renders a parsed Snowflake data type as its base type name
// without arguments (VARCHAR rather than VARCHAR(16777216)), the form these
// fields have always reported. A type the SDK could not parse is empty.
func legacyDataTypeName(dt datatypes.DataType) string {
	if dt == nil {
		return ""
	}
	return dt.ToLegacyDataTypeSql()
}

// snowflakeTimePtr is snowflakeTime for an optional timestamp, which the SDK
// leaves nil when Snowflake reports no value.
func snowflakeTimePtr(value *time.Time) *llx.RawData {
	if value == nil {
		return llx.NilData
	}
	return snowflakeTime(*value)
}

// splitCommaList parses a comma-separated value from Snowflake DESCRIBE output
// (e.g. STORAGE_ALLOWED_LOCATIONS) into a slice. Snowflake sometimes wraps the
// list in square brackets, so those are stripped first. Empty entries are
// dropped so a trailing comma or an empty value yields an empty slice.
func splitCommaList(value string) []any {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if value == "" {
		return []any{}
	}
	parts := strings.Split(value, ",")
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// snowflakeSchemaObjectID renders the fully qualified name of a schema-scoped
// object as the cache key for its resource. It quotes each part the way
// Snowflake does, so a name containing a dot cannot collide with a different
// database/schema/name split. The SDK's ID().FullyQualifiedName() produces the
// same shape but panics on identifiers it fails to parse, so the id is built
// from the raw parts instead.
func snowflakeSchemaObjectID(databaseName, schemaName, name string) string {
	return `"` + databaseName + `"."` + schemaName + `"."` + name + `"`
}

func (r *mqlSnowflake) currentRole() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	current, err := client.ContextFunctions.CurrentSessionDetails(ctx)
	if err != nil {
		return "", err
	}
	return current.Role, nil
}
