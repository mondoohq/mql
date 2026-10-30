// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodebuildBucketName(t *testing.T) {
	// CodeBuild artifact/cache/log locations are bare "bucket" or
	// "bucket/prefix" strings (occasionally with an s3:// scheme). The typed
	// aws.s3.bucket ref must resolve to just the bucket, and anything without a
	// bucket must yield "" (→ null ref) rather than a bogus name.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "bare bucket", in: "my-artifacts-bucket", want: "my-artifacts-bucket"},
		{name: "bucket with prefix", in: "my-artifacts-bucket/builds/out", want: "my-artifacts-bucket"},
		{name: "s3 scheme with prefix", in: "s3://my-artifacts-bucket/builds", want: "my-artifacts-bucket"},
		{name: "s3 scheme bucket only", in: "s3://my-artifacts-bucket", want: "my-artifacts-bucket"},
		{name: "empty", in: "", want: ""},
		{name: "scheme only", in: "s3://", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, codebuildBucketName(tc.in))
		})
	}
}
