// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	dstypes "github.com/aws/aws-sdk-go-v2/service/directoryservice/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSharedDirectoryArgs(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	t.Run("all fields", func(t *testing.T) {
		args := sharedDirectoryArgs("us-east-1", "d-1234567890", dstypes.SharedDirectory{
			OwnerAccountId:      aws.String("123456789012"),
			OwnerDirectoryId:    aws.String("d-1234567890"),
			SharedAccountId:     aws.String("210987654321"),
			SharedDirectoryId:   aws.String("d-abcdef0123"),
			ShareMethod:         dstypes.ShareMethodHandshake,
			ShareStatus:         dstypes.ShareStatusPendingAcceptance,
			ShareNotes:          aws.String("invite"),
			CreatedDateTime:     &created,
			LastUpdatedDateTime: &updated,
		})
		assert.Equal(t, "aws.directoryservice.directory.sharedDirectory/us-east-1/d-1234567890/210987654321", args["__id"].Value)
		assert.Equal(t, "210987654321", args["sharedAccountId"].Value)
		assert.Equal(t, "d-abcdef0123", args["sharedDirectoryId"].Value)
		assert.Equal(t, "HANDSHAKE", args["shareMethod"].Value)
		assert.Equal(t, "PendingAcceptance", args["shareStatus"].Value)
		assert.Equal(t, "invite", args["shareNotes"].Value)
		require.IsType(t, &time.Time{}, args["createdAt"].Value)
		assert.True(t, created.Equal(*args["createdAt"].Value.(*time.Time)))
		assert.True(t, updated.Equal(*args["updatedAt"].Value.(*time.Time)))
	})

	t.Run("unset optional fields", func(t *testing.T) {
		args := sharedDirectoryArgs("us-east-1", "d-1234567890", dstypes.SharedDirectory{
			SharedAccountId: aws.String("210987654321"),
			ShareMethod:     dstypes.ShareMethodOrganizations,
			ShareStatus:     dstypes.ShareStatusShared,
		})
		assert.Equal(t, "ORGANIZATIONS", args["shareMethod"].Value)
		assert.Equal(t, "Shared", args["shareStatus"].Value)
		assert.Nil(t, args["shareNotes"].Value)
		assert.Nil(t, args["sharedDirectoryId"].Value)
		assert.Nil(t, args["createdAt"].Value)
		assert.Nil(t, args["updatedAt"].Value)
	})
}
