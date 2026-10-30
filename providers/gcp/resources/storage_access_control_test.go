// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/storage/v1"
)

func TestBucketAclEntries(t *testing.T) {
	entries := bucketAclEntries([]*storage.BucketAccessControl{
		{Entity: "allUsers", Role: "READER"},
		{
			Entity:      "project-owners-1234",
			EntityId:    "abc",
			Role:        "OWNER",
			Email:       "owner@example.com",
			Domain:      "example.com",
			ProjectTeam: &storage.BucketAccessControlProjectTeam{ProjectNumber: "1234", Team: "owners"},
		},
		// A nil entry must be skipped, not panic the scan.
		nil,
	})

	require.Len(t, entries, 2)
	// allUsers is the anonymous grant an exposure audit is looking for.
	assert.Equal(t, "allUsers", entries[0].entity)
	assert.Equal(t, "READER", entries[0].role)
	assert.Equal(t, "", entries[0].entityId)

	assert.Equal(t, "project-owners-1234", entries[1].entity)
	assert.Equal(t, "OWNER", entries[1].role)
	assert.Equal(t, "owner@example.com", entries[1].email)
	assert.Equal(t, "example.com", entries[1].domain)
	assert.Equal(t, "1234", entries[1].projectTeamId)
	assert.Equal(t, "owners", entries[1].projectTeamRole)
}

func TestObjectAclEntries(t *testing.T) {
	entries := objectAclEntries([]*storage.ObjectAccessControl{
		nil,
		{
			Entity:      "allAuthenticatedUsers",
			Role:        "READER",
			ProjectTeam: &storage.ObjectAccessControlProjectTeam{ProjectNumber: "99", Team: "viewers"},
		},
	})

	require.Len(t, entries, 1)
	assert.Equal(t, "allAuthenticatedUsers", entries[0].entity)
	assert.Equal(t, "READER", entries[0].role)
	assert.Equal(t, "99", entries[0].projectTeamId)
	assert.Equal(t, "viewers", entries[0].projectTeamRole)
}

// Uniform bucket-level access removes the legacy ACL outright: GCS sends no acl
// or defaultObjectAcl at all, not an empty one. That nil is what the accessors
// report as null, and the distinction matters — an empty list claims the bucket
// has an ACL that grants nothing, which would let a "no public entity in the
// ACL" check pass on a bucket whose ACL was never read.
func TestBucketAclAbsentUnderUniformBucketLevelAccess(t *testing.T) {
	ubla := []byte(`{
	  "name": "ubla-bucket",
	  "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": true}}
	}`)

	var bucket storage.Bucket
	require.NoError(t, json.Unmarshal(ubla, &bucket))

	require.NotNil(t, bucket.IamConfiguration)
	require.NotNil(t, bucket.IamConfiguration.UniformBucketLevelAccess)
	assert.True(t, bucket.IamConfiguration.UniformBucketLevelAccess.Enabled)
	assert.Nil(t, bucket.Acl)
	assert.Nil(t, bucket.DefaultObjectAcl)
}

// Without uniform bucket-level access the same call carries the ACL, so nil is
// a real signal rather than the normal state of the field.
func TestBucketAclPresentWithoutUniformBucketLevelAccess(t *testing.T) {
	legacy := []byte(`{
	  "name": "legacy-bucket",
	  "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": false}},
	  "acl": [{"entity": "allUsers", "role": "READER"}],
	  "defaultObjectAcl": [{"entity": "project-viewers-1", "role": "READER"}]
	}`)

	var bucket storage.Bucket
	require.NoError(t, json.Unmarshal(legacy, &bucket))

	require.Len(t, bucket.Acl, 1)
	assert.Equal(t, "allUsers", bucket.Acl[0].Entity)
	require.Len(t, bucket.DefaultObjectAcl, 1)
	assert.Equal(t, "project-viewers-1", bucket.DefaultObjectAcl[0].Entity)
}

// An IP filter with mode Disabled is not enforced no matter what sources it
// lists, so mode has to decode as itself rather than being inferred from the
// presence of sources.
func TestBucketIpFilterDecode(t *testing.T) {
	payload := []byte(`{
	  "ipFilter": {
	    "mode": "Enabled",
	    "allowAllServiceAgentAccess": true,
	    "allowCrossOrgVpcs": false,
	    "publicNetworkSource": {"allowedIpCidrRanges": ["203.0.113.0/24"]},
	    "vpcNetworkSources": [
	      {
	        "network": "projects/p1/global/networks/vpc-a",
	        "allowedIpCidrRanges": ["10.0.0.0/8"]
	      }
	    ]
	  }
	}`)

	var bucket storage.Bucket
	require.NoError(t, json.Unmarshal(payload, &bucket))

	require.NotNil(t, bucket.IpFilter)
	assert.Equal(t, "Enabled", bucket.IpFilter.Mode)
	assert.True(t, bucket.IpFilter.AllowAllServiceAgentAccess)
	assert.False(t, bucket.IpFilter.AllowCrossOrgVpcs)
	require.NotNil(t, bucket.IpFilter.PublicNetworkSource)
	assert.Equal(t, []string{"203.0.113.0/24"}, bucket.IpFilter.PublicNetworkSource.AllowedIpCidrRanges)
	require.Len(t, bucket.IpFilter.VpcNetworkSources, 1)
	assert.Equal(t, "projects/p1/global/networks/vpc-a", bucket.IpFilter.VpcNetworkSources[0].Network)
	assert.Equal(t, []string{"10.0.0.0/8"}, bucket.IpFilter.VpcNetworkSources[0].AllowedIpCidrRanges)

	// The bare "projects/..." form is what the filter reports, and the network
	// resolver has to accept it, or every VPC source resolves to nothing.
	project, name, ok := parseNetworkURL(bucket.IpFilter.VpcNetworkSources[0].Network)
	require.True(t, ok)
	assert.Equal(t, "p1", project)
	assert.Equal(t, "vpc-a", name)
}
