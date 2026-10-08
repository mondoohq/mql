// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/IBM/platform-services-go-sdk/atrackerv2"
	"github.com/stretchr/testify/assert"
)

func TestTargetArgsCos(t *testing.T) {
	tg := *unmarshal[atrackerv2.Target](t, `{
		"id": "t1", "name": "cos", "target_type": "cloud_object_storage", "region": "us-south",
		"cos_endpoint": {"endpoint": "s3.private.us-south.cloud-object-storage.appdomain.cloud",
			"target_crn": "crn:cos::", "bucket": "logs", "service_to_service_enabled": true},
		"write_status": {"status": "failed", "last_failure": "2026-10-07T09:19:15.029Z", "reason_for_last_failure": "denied"}
	}`, atrackerv2.UnmarshalTarget)
	args := targetArgs(tg)
	assert.Equal(t, "failed", args["writeStatus"].Value)
	assert.NotNil(t, args["lastFailureAt"].Value)
	assert.Equal(t, "denied", args["lastFailureReason"].Value)
	assert.Equal(t, true, args["serviceToServiceEnabled"].Value)
	assert.Equal(t, "s3.private.us-south.cloud-object-storage.appdomain.cloud", args["cosEndpoint"].Value)

	bucket, crn := targetDestination(tg)
	assert.Equal(t, "logs", bucket)
	assert.Equal(t, "crn:cos::", crn)
}

func TestTargetArgsCloudLogs(t *testing.T) {
	tg := *unmarshal[atrackerv2.Target](t, `{
		"id": "t2", "name": "logs", "target_type": "cloud_logs", "region": "eu-de",
		"cloudlogs_endpoint": {"target_crn": "crn:logs::"},
		"write_status": {"status": "success"}
	}`, atrackerv2.UnmarshalTarget)
	args := targetArgs(tg)
	assert.Equal(t, "success", args["writeStatus"].Value)
	assert.Nil(t, args["lastFailureAt"].Value, "a target that never failed has no failure time")
	assert.Equal(t, "", args["cosEndpoint"].Value)

	bucket, crn := targetDestination(tg)
	assert.Equal(t, "", bucket, "only Cloud Object Storage targets write to a bucket")
	assert.Equal(t, "crn:logs::", crn)
}
