// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripURLCredentialsInText(t *testing.T) {
	cases := map[string]string{
		"connection refused": "connection refused",
		"":                   "",
		"GET https://user:pw@host.example.com/b?sig=abc failed":     "GET https://host.example.com/b failed",
		`dial "http://host:9000/x?token=1" and s3://k:s@bucket/key`: `dial "http://host:9000/x" and s3://bucket/key`,
		"no credentials in https://host.example.com/path here":      "no credentials in https://host.example.com/path here",
	}
	for in, want := range cases {
		assert.Equal(t, want, stripURLCredentialsInText(in), in)
	}
}
