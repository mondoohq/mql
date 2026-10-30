// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGcsBucketFromURI pins the parsing behind the bucket references on
// BigLake tables and Cloud SQL on-premises configurations.
//
// The failure that matters is the silent one: returning a wrong bucket name
// resolves to a real but unrelated bucket, and the reference then reports that
// bucket's IAM policy as if it governed this table's data. Every input that
// does not clearly name a bucket must return "" so the field reads null.
func TestGcsBucketFromURI(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{name: "bucket and object prefix", uri: "gs://my-lake/warehouse/table/", want: "my-lake"},
		{name: "bucket only, trailing slash", uri: "gs://my-lake/", want: "my-lake"},
		{name: "bucket only, no trailing slash", uri: "gs://my-lake", want: "my-lake"},
		{name: "single object", uri: "gs://db-dumps/prod-2026-08-17.sql.gz", want: "db-dumps"},
		{name: "dotted bucket name", uri: "gs://logs.example.com/access/", want: "logs.example.com"},
		{name: "wildcard object glob", uri: "gs://my-lake/data/*.parquet", want: "my-lake"},

		// Shapes seen without the scheme.
		{name: "scheme-less with path", uri: "db-dumps/prod.sql", want: "db-dumps"},
		{name: "bare bucket name", uri: "my-lake", want: "my-lake"},

		// Nothing resolvable -- all must read as null, not as a guess.
		{name: "empty", uri: "", want: ""},
		{name: "whitespace only", uri: "   ", want: ""},
		{name: "scheme only", uri: "gs://", want: ""},
		{name: "scheme with empty first segment", uri: "gs:///object", want: ""},
		{name: "leading slash", uri: "/object", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, gcsBucketFromURI(tt.uri))
		})
	}
}
