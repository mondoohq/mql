// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	glue_types "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// mqlAwsGlueDatabaseTableInternal keeps the parts of the GetTables record the
// column and reference fields read, so they need no further call.
type mqlAwsGlueDatabaseTableInternal struct {
	cacheColumns       []glue_types.Column
	cachePartitionKeys []glue_types.Column
	cacheLocation      string
	// cacheDatabase is the database whose tables() listed the table.
	cacheDatabase *mqlAwsGlueDatabase
}

// glueColumnRow is one column of a Glue table, in position order.
type glueColumnRow struct {
	name           string
	position       int64
	typeName       string
	comment        string
	isPartitionKey bool
	parameters     map[string]any
}

// glueColumns orders the storage columns first and the partition keys after
// them, numbered from 1 (ADR 059), as Athena and Hive present a partitioned
// table.
func glueColumns(cols, parts []glue_types.Column) []glueColumnRow {
	out := make([]glueColumnRow, 0, len(cols)+len(parts))
	add := func(c glue_types.Column, partition bool) {
		params := map[string]any{}
		for k, v := range c.Parameters {
			params[k] = v
		}
		out = append(out, glueColumnRow{
			name:           convert.ToValue(c.Name),
			position:       int64(len(out) + 1),
			typeName:       convert.ToValue(c.Type),
			comment:        convert.ToValue(c.Comment),
			isPartitionKey: partition,
			parameters:     params,
		})
	}
	for _, c := range cols {
		add(c, false)
	}
	for _, c := range parts {
		add(c, true)
	}
	return out
}

// glueS3Uri returns the location as an s3:// URI. Hadoop's s3a:// and s3n://
// schemes name the same bucket; any other location (a JDBC URL, a file path, an
// empty location) returns "".
func glueS3Uri(location string) string {
	for _, scheme := range []string{"s3://", "s3a://", "s3n://"} {
		if len(location) >= len(scheme) && strings.EqualFold(location[:len(scheme)], scheme) {
			return "s3://" + location[len(scheme):]
		}
	}
	return ""
}

// glueColumnID keys a column by its position, not its name: a crawler can
// list one name both as a storage column and as a partition key, and a name
// may hold "/".
func glueColumnID(tableID string, position int64) string {
	return tableID + "/column/" + strconv.FormatInt(position, 10)
}

func (a *mqlAwsGlueDatabaseTable) columns() ([]any, error) {
	list := []any{}
	for _, c := range glueColumns(a.cacheColumns, a.cachePartitionKeys) {
		res, err := CreateResource(a.MqlRuntime, "aws.glue.database.table.column", map[string]*llx.RawData{
			"__id":           llx.StringData(glueColumnID(a.__id, c.position)),
			"name":           llx.StringData(c.name),
			"position":       llx.IntData(c.position),
			"typeName":       llx.StringData(c.typeName),
			"comment":        llx.StringData(c.comment),
			"isPartitionKey": llx.BoolData(c.isPartitionKey),
			"parameters":     llx.MapData(c.parameters, types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (a *mqlAwsGlueDatabaseTable) s3Bucket() (*mqlAwsS3Bucket, error) {
	return s3BucketRefFromUri(a.MqlRuntime, glueS3Uri(a.cacheLocation), &a.S3Bucket)
}

func (a *mqlAwsGlueDatabaseTable) database() (*mqlAwsGlueDatabase, error) {
	if a.cacheDatabase != nil {
		return a.cacheDatabase, nil
	}
	// Not reached through a database's tables(): resolve against the
	// account's already-listed databases rather than a lookup per table.
	res, err := NewResource(a.MqlRuntime, "aws.glue", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	dbs := res.(*mqlAwsGlue).GetDatabases()
	if dbs.Error != nil {
		return nil, dbs.Error
	}
	if db := findGlueDatabase(dbs.Data, a.Region.Data, a.CatalogId.Data, a.DatabaseName.Data); db != nil {
		return db, nil
	}
	a.Database.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// findGlueDatabase returns the database with the given region, catalog and
// name from a databases() list, or nil.
func findGlueDatabase(list []any, region, catalogID, name string) *mqlAwsGlueDatabase {
	for _, x := range list {
		db, ok := x.(*mqlAwsGlueDatabase)
		if !ok {
			continue
		}
		if db.Region.Data == region && db.CatalogId.Data == catalogID && db.Name.Data == name {
			return db
		}
	}
	return nil
}
