// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	glue_types "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestGlueColumns(t *testing.T) {
	// Synthetic: the shape of a crawler-built table partitioned by year and
	// month; no live catalog was read for this change.
	cols := []glue_types.Column{
		{Name: aws.String("customer_id"), Type: aws.String("bigint"), Comment: aws.String("primary key")},
		{Name: aws.String("email"), Type: aws.String("string")},
		{Name: aws.String("address"), Type: aws.String("struct<street:string,zip:string>"), Parameters: map[string]string{"pii": "true"}},
	}
	parts := []glue_types.Column{
		{Name: aws.String("year"), Type: aws.String("string")},
		{Name: aws.String("month"), Type: aws.String("string")},
	}
	got := glueColumns(cols, parts)
	require.Len(t, got, 5)

	names := []string{}
	for i, c := range got {
		names = append(names, c.name)
		assert.Equal(t, int64(i), c.position, "position of %s", c.name)
		assert.Equal(t, i >= 3, c.isPartitionKey, "isPartitionKey of %s", c.name)
	}
	assert.Equal(t, []string{"customer_id", "email", "address", "year", "month"}, names)
	assert.Equal(t, "primary key", got[0].comment)
	assert.Equal(t, "", got[1].comment, "a nil Comment reads as empty")
	assert.Equal(t, "struct<street:string,zip:string>", got[2].typeName)
	assert.Equal(t, map[string]any{"pii": "true"}, got[2].parameters)
	assert.Equal(t, map[string]any{}, got[1].parameters, "nil Parameters read as an empty map")
}

func TestGlueColumnsWithoutStorageDescriptor(t *testing.T) {
	// Synthetic: a table whose record has no StorageDescriptor and no
	// partition keys, so nothing was cached.
	assert.Empty(t, glueColumns(nil, nil))

	// Synthetic: partition keys alone are numbered from 0.
	got := glueColumns(nil, []glue_types.Column{{Name: aws.String("dt"), Type: aws.String("date")}})
	require.Len(t, got, 1)
	assert.Equal(t, int64(0), got[0].position)
	assert.True(t, got[0].isPartitionKey)
}

func TestGlueS3Uri(t *testing.T) {
	// Synthetic: location spellings the Data Catalog accepts.
	cases := map[string]string{
		"s3://bucket/path/":        "s3://bucket/path/",
		"s3a://bucket/path":        "s3://bucket/path",
		"s3n://bucket":             "s3://bucket",
		"S3://bucket/p":            "s3://bucket/p",
		"jdbc:mysql://host/db.tbl": "",
		"file:///tmp/x":            "",
		"":                         "",
		"s3":                       "",
	}
	for in, want := range cases {
		assert.Equal(t, want, glueS3Uri(in), "glueS3Uri(%q)", in)
	}
	// The bucket the normalised URI names is the one s3BucketRefFromUri reads.
	assert.Equal(t, "bucket", s3BucketNameFromUri(glueS3Uri("s3a://bucket/path")))
	assert.Equal(t, "", s3BucketNameFromUri(glueS3Uri("jdbc:postgresql://host/db")))
}

func TestGlueTableDatabaseFromList(t *testing.T) {
	// Synthetic: two databases of the same name in two regions and in two
	// catalogs; the table resolves to the one matching all three.
	db := func(region, catalog, name string) *mqlAwsGlueDatabase {
		return &mqlAwsGlueDatabase{
			Region:    plugin.TValue[string]{Data: region, State: plugin.StateIsSet},
			CatalogId: plugin.TValue[string]{Data: catalog, State: plugin.StateIsSet},
			Name:      plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		}
	}
	east := db("us-east-1", "111111111111", "sales")
	west := db("us-west-2", "111111111111", "sales")
	shared := db("us-east-1", "222222222222", "sales")
	list := []any{west, shared, east}

	assert.Same(t, east, findGlueDatabase(list, "us-east-1", "111111111111", "sales"))
	assert.Same(t, west, findGlueDatabase(list, "us-west-2", "111111111111", "sales"))
	assert.Same(t, shared, findGlueDatabase(list, "us-east-1", "222222222222", "sales"))
	assert.Nil(t, findGlueDatabase(list, "eu-west-1", "111111111111", "sales"))
	assert.Nil(t, findGlueDatabase(list, "us-east-1", "111111111111", "marketing"))
	assert.Nil(t, findGlueDatabase(nil, "us-east-1", "111111111111", "sales"))
}

func TestGlueTableDatabaseFromParent(t *testing.T) {
	// Synthetic: a table listed by a database's tables() returns that
	// database without a lookup.
	parent := &mqlAwsGlueDatabase{}
	table := &mqlAwsGlueDatabaseTable{}
	table.cacheDatabase = parent
	got, err := table.database()
	require.NoError(t, err)
	assert.Same(t, parent, got)
}
