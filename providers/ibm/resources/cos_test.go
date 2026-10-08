// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/IBM/ibm-cos-sdk-go/aws"
	"github.com/IBM/ibm-cos-sdk-go/aws/awserr"
	"github.com/IBM/ibm-cos-sdk-go/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitLocationConstraint(t *testing.T) {
	for lc, want := range map[string][2]string{
		"us-south-smart":       {"us-south", "smart"},
		"us-standard":          {"us", "standard"},
		"ams03-onerate_active": {"ams03", "onerate_active"},
		"eu-de-cold":           {"eu-de", "cold"},
		"nolocationconstraint": {"nolocationconstraint", ""},
		"":                     {"", ""},
	} {
		loc, class := splitLocationConstraint(lc)
		assert.Equal(t, want, [2]string{loc, class}, lc)
	}
}

func TestBucketCRN(t *testing.T) {
	assert.Equal(t,
		"crn:v1:bluemix:public:cloud-object-storage:global:a/acc:guid:bucket:logs",
		bucketCRN("crn:v1:bluemix:public:cloud-object-storage:global:a/acc:guid::", "logs"))
}

func TestBucketConfigDecode(t *testing.T) {
	var cfg bucketConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "b", "time_updated": "2026-10-07T09:19:13.710Z",
		"object_count": 3, "bytes_used": 42, "hard_quota": 1000,
		"firewall": {"allowed_ip": ["10.0.0.1"], "denied_ip": ["10.0.0.2"], "allowed_network_type": ["private"]},
		"activity_tracking": {"read_data_events": true, "write_data_events": false, "management_events": true},
		"metrics_monitoring": {"usage_metrics_enabled": true, "request_metrics_enabled": false}
	}`), &cfg))
	assert.Equal(t, int64(3), *cfg.ObjectCount)
	assert.Equal(t, int64(1000), *cfg.HardQuota)
	assert.Equal(t, []string{"10.0.0.2"}, cfg.Firewall.DeniedIP, "the SDK model drops denied_ip")
	assert.Equal(t, []string{"private"}, cfg.Firewall.AllowedNetworkType, "the SDK model drops allowed_network_type")
	assert.True(t, isTrue(cfg.ActivityTracking.ReadDataEvents))
	assert.False(t, isTrue(cfg.ActivityTracking.WriteDataEvents))
	assert.True(t, isTrue(cfg.MetricsMonitoring.UsageMetricsEnabled))

	var bare bucketConfig
	require.NoError(t, json.Unmarshal([]byte(`{"name": "b"}`), &bare))
	assert.Nil(t, bare.HardQuota, "no quota is unlimited, not zero")
	assert.Nil(t, bare.Firewall)
	assert.Nil(t, bare.ActivityTracking)
}

func TestGrantsAllUsers(t *testing.T) {
	owner := &s3.Grant{Grantee: &s3.Grantee{ID: aws.String("owner"), Type: aws.String("CanonicalUser")}, Permission: aws.String("FULL_CONTROL")}
	public := &s3.Grant{Grantee: &s3.Grantee{URI: aws.String(allUsersURI), Type: aws.String("Group")}, Permission: aws.String("READ")}
	assert.False(t, grantsAllUsers([]*s3.Grant{owner}))
	assert.True(t, grantsAllUsers([]*s3.Grant{owner, public}))
	assert.False(t, grantsAllUsers([]*s3.Grant{nil, {Grantee: nil}}))
}

func TestPublicAccessGrant(t *testing.T) {
	pub := map[string]string{"access_group_id": publicAccessGroupID}
	assert.True(t, publicAccessGrant(pub, map[string]string{"serviceName": "cloud-object-storage", "serviceInstance": "g1", "resourceType": "bucket", "resource": "b1"}, "g1", "b1"))
	assert.True(t, publicAccessGrant(pub, map[string]string{"serviceName": "cloud-object-storage", "serviceInstance": "g1"}, "g1", "b1"), "a grant on the instance covers its buckets")
	assert.True(t, publicAccessGrant(pub, map[string]string{"accountId": "acc"}, "g1", "b1"), "a grant on all services covers the bucket")
	assert.False(t, publicAccessGrant(pub, map[string]string{"serviceName": "cloud-object-storage", "serviceInstance": "g1", "resource": "other"}, "g1", "b1"))
	assert.False(t, publicAccessGrant(pub, map[string]string{"serviceName": "cloud-object-storage", "serviceInstance": "g2"}, "g1", "b1"))
	assert.False(t, publicAccessGrant(pub, map[string]string{"serviceName": "kms"}, "g1", "b1"))
	assert.False(t, publicAccessGrant(map[string]string{"access_group_id": "AccessGroupId-123"}, map[string]string{}, "g1", "b1"), "another group is not public")
	assert.False(t, publicAccessGrant(map[string]string{"iam_id": "IBMid-1"}, map[string]string{}, "g1", "b1"))
}

func TestNotConfigured(t *testing.T) {
	assert.True(t, notConfigured(awserr.New("NoSuchWebsiteConfiguration", "none", nil)))
	assert.True(t, notConfigured(awserr.New("ObjectLockConfigurationNotFoundError", "none", nil)))
	assert.False(t, notConfigured(awserr.New("AccessDenied", "no", nil)), "a refusal is not an absent configuration")
	assert.False(t, notConfigured(errors.New("timeout")))
	assert.False(t, notConfigured(nil))
}
