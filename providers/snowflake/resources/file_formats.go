// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeFileFormatInternal struct {
	cacheOwner string
}

func (r *mqlSnowflakeAccount) fileFormats() ([]any, error) {
	return listSnowflakeFileFormats(r.MqlRuntime, sdk.In{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) fileFormats() ([]any, error) {
	return listSnowflakeFileFormats(r.MqlRuntime, sdk.In{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeFileFormats fetches file formats within the given scope
// (account-wide or a single database) and maps them to resources.
func listSnowflakeFileFormats(runtime *plugin.Runtime, in sdk.In) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	formats, err := conn.Client().FileFormats.Show(context.Background(), sdk.NewShowFileFormatRequest().WithIn(in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(formats))
	for i := range formats {
		mqlFormat, err := newMqlSnowflakeFileFormat(runtime, formats[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlFormat)
	}
	return list, nil
}

func newMqlSnowflakeFileFormat(runtime *plugin.Runtime, format sdk.FileFormat) (*mqlSnowflakeFileFormat, error) {
	databaseName := format.DatabaseName
	schemaName := format.SchemaName
	name := format.Name

	options, err := fileFormatOptionsToDict(format.FormatOptions)
	if err != nil {
		log.Warn().Err(err).Str("fileFormat", snowflakeSchemaObjectID(databaseName, schemaName, name)).Msg("snowflake> could not parse file format options")
	}

	r, err := CreateResource(runtime, "snowflake.fileFormat", map[string]*llx.RawData{
		"__id":          llx.StringData(snowflakeSchemaObjectID(databaseName, schemaName, name)),
		"name":          llx.StringData(name),
		"databaseName":  llx.StringData(databaseName),
		"schemaName":    llx.StringData(schemaName),
		"ownerRoleType": llx.StringData(format.OwnerRoleType),
		"type":          llx.StringData(string(format.Type)),
		"options":       llx.DictData(options),
		"comment":       llx.StringData(format.Comment),
		"createdAt":     snowflakeTime(format.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlFormat := r.(*mqlSnowflakeFileFormat)
	mqlFormat.cacheOwner = format.Owner
	return mqlFormat, nil
}

// fileFormatOptionsToDict decodes the format_options column of SHOW FILE
// FORMATS, a JSON object keyed by the Snowflake option name that holds only the
// options of the format's own type. TYPE is dropped because the format type is
// its own field.
//
// Numbers are decoded as int64 when integral and float64 otherwise, so a
// SKIP_HEADER of 1 compares equal to 1 in MQL rather than to 1.0. A column that
// is empty or does not parse yields a nil map, which the caller stores as a
// null dict rather than an empty one: no options were read, which is not the
// same as a format with no options set.
func fileFormatOptionsToDict(formatOptions string) (map[string]any, error) {
	if strings.TrimSpace(formatOptions) == "" {
		return nil, nil
	}

	dec := json.NewDecoder(strings.NewReader(formatOptions))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	out := make(map[string]any, len(raw))
	for key, value := range raw {
		if key == "TYPE" {
			continue
		}
		out[key] = jsonNumbersToNative(value)
	}
	return out, nil
}

// jsonNumbersToNative replaces every json.Number in a decoded JSON value with
// an int64 or float64, the numeric types a dict can carry.
func jsonNumbersToNative(value any) any {
	switch v := value.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		if f, err := v.Float64(); err == nil {
			return f
		}
		return v.String()
	case []any:
		for i := range v {
			v[i] = jsonNumbersToNative(v[i])
		}
		return v
	case map[string]any:
		for k := range v {
			v[k] = jsonNumbersToNative(v[k])
		}
		return v
	}
	return value
}

func (r *mqlSnowflakeFileFormat) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeFileFormat) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeFileFormat) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

// resolveFileFormatRef resolves a fully qualified file format name (the form
// Snowflake reports in SHOW output) to its file format. A name that cannot be
// parsed, or a format the caller cannot see, resolves to null rather than
// failing the surrounding query.
func resolveFileFormatRef(runtime *plugin.Runtime, fqn string, field *plugin.TValue[*mqlSnowflakeFileFormat]) (*mqlSnowflakeFileFormat, error) {
	if fqn == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id, err := sdk.ParseSchemaObjectIdentifier(fqn)
	if err != nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	formats, err := conn.Client().FileFormats.Show(context.Background(), sdk.NewShowFileFormatRequest().
		WithLike(sdk.Like{Pattern: new(id.Name())}).
		WithIn(sdk.In{Schema: sdk.NewDatabaseObjectIdentifier(id.DatabaseName(), id.SchemaName())}))
	if err != nil {
		return nil, err
	}
	for i := range formats {
		if formats[i].Name == id.Name() && formats[i].DatabaseName == id.DatabaseName() &&
			formats[i].SchemaName == id.SchemaName() {
			return newMqlSnowflakeFileFormat(runtime, formats[i])
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
