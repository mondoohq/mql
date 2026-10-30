// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDirectoryServiceDirectoryArn(t *testing.T) {
	cases := []struct {
		name        string
		region      string
		accountID   string
		directoryID string
		want        string
	}{
		{
			name:        "microsoft ad",
			region:      "us-east-1",
			accountID:   "123456789012",
			directoryID: "d-1234567890",
			want:        "arn:aws:ds:us-east-1:123456789012:directory/d-1234567890",
		},
		{
			name:        "other region",
			region:      "eu-central-1",
			accountID:   "210987654321",
			directoryID: "d-abcdef0123",
			want:        "arn:aws:ds:eu-central-1:210987654321:directory/d-abcdef0123",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, directoryServiceDirectoryArn(tc.region, tc.accountID, tc.directoryID))
		})
	}
}
