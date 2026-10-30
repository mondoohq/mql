// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	athena_types "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAthenaBucketFromS3Location(t *testing.T) {
	// resultBucket() feeds the output into aws.s3.bucket by name, so anything
	// that isn't a well-formed s3:// URI must yield "" (→ null bucket), never a
	// bogus bucket name.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "bucket with prefix", in: "s3://my-results-bucket/queries/2024/", want: "my-results-bucket"},
		{name: "bucket with trailing slash", in: "s3://my-results-bucket/", want: "my-results-bucket"},
		{name: "bucket only", in: "s3://my-results-bucket", want: "my-results-bucket"},
		{name: "empty string", in: "", want: ""},
		{name: "missing scheme", in: "my-results-bucket/queries", want: ""},
		{name: "wrong scheme", in: "https://example.com/path", want: ""},
		{name: "scheme only", in: "s3://", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, athenaBucketFromS3Location(tc.in))
		})
	}
}

func TestAthenaLambdaArnFromParams(t *testing.T) {
	const fnArn = "arn:aws:lambda:us-east-1:123456789012:function:my-connector"
	const metaArn = "arn:aws:lambda:us-east-1:123456789012:function:my-metadata"

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{name: "nil map", params: nil, want: ""},
		{name: "empty map", params: map[string]any{}, want: ""},
		{name: "function key", params: map[string]any{"function": fnArn}, want: fnArn},
		{name: "metadata-function key", params: map[string]any{"metadata-function": metaArn}, want: metaArn},
		{
			name:   "function preferred over metadata-function",
			params: map[string]any{"function": fnArn, "metadata-function": metaArn},
			want:   fnArn,
		},
		{
			name:   "record-function alone is ignored",
			params: map[string]any{"record-function": "arn:aws:lambda:us-east-1:123456789012:function:records"},
			want:   "",
		},
		{name: "non-arn value", params: map[string]any{"function": "just-a-name"}, want: ""},
		{name: "non-string value", params: map[string]any{"function": 42}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, athenaLambdaArnFromParams(tc.params))
		})
	}
}

func TestAthenaColumnsToDict(t *testing.T) {
	t.Run("empty slice returns empty list", func(t *testing.T) {
		assert.Empty(t, athenaColumnsToDict(nil))
		assert.Empty(t, athenaColumnsToDict([]athena_types.Column{}))
	})

	t.Run("maps name, type, and comment", func(t *testing.T) {
		cols := []athena_types.Column{
			{Name: aws.String("id"), Type: aws.String("bigint"), Comment: aws.String("primary key")},
			{Name: aws.String("created_at"), Type: aws.String("timestamp")}, // nil comment
		}
		got := athenaColumnsToDict(cols)
		require.Len(t, got, 2)

		first, ok := got[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "id", first["name"])
		assert.Equal(t, "bigint", first["type"])
		assert.Equal(t, "primary key", first["comment"])

		second, ok := got[1].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "created_at", second["name"])
		assert.Equal(t, "timestamp", second["type"])
		// nil *string comment must degrade to "" rather than panic.
		assert.Equal(t, "", second["comment"])
	})
}
