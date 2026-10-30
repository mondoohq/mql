// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	ecsclient "github.com/alibabacloud-go/ecs-20140526/v7/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEcsImdsV2Required(t *testing.T) {
	tests := []struct {
		name     string
		tokens   *string
		expected bool
	}{
		{"required", new("required"), true},
		{"case insensitive", new("Required"), true},
		{"whitespace tolerated", new(" required "), true},
		// optional still answers the token-less IMDSv1 request that a
		// server-side request forgery can reach
		{"optional", new("optional"), false},
		{"absent", nil, false},
		{"empty", new(""), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, ecsImdsV2Required(test.tokens))
		})
	}
}

func TestEcsDiskEncrypted(t *testing.T) {
	// the launch template API returns this member as a string, not a boolean
	assert.True(t, ecsDiskEncrypted(new("true")))
	assert.True(t, ecsDiskEncrypted(new("True")))
	assert.False(t, ecsDiskEncrypted(new("false")))
	// an unread setting must not report encryption nobody confirmed
	assert.False(t, ecsDiskEncrypted(nil))
	assert.False(t, ecsDiskEncrypted(new("")))
	assert.False(t, ecsDiskEncrypted(new("1")))
}

// TestLaunchTemplateDataDecode pins the struct tags the flattening depends on.
// A mistyped tag would decode to a zero value, so a template demanding IMDSv2
// would report imdsV2Required false, and a template with user data would report
// none.
func TestLaunchTemplateDataDecode(t *testing.T) {
	payload := `{
      "VersionNumber": 3,
      "DefaultVersion": true,
      "LaunchTemplateId": "lt-bp67acfmxazb4p",
      "LaunchTemplateData": {
        "InstanceType": "ecs.g6.large",
        "ImageId": "m-bp67acfmxazb4p",
        "RamRoleName": "deploy-role",
        "KeyPairName": "ops",
        "HttpTokens": "required",
        "HttpEndpoint": "enabled",
        "HttpPutResponseHopLimit": 2,
        "UserData": "ZWNobyBoZWxsbw==",
        "VpcId": "vpc-bp67acfmxazb4p",
        "VSwitchId": "vsw-bp67acfmxazb4p",
        "InternetMaxBandwidthOut": 100,
        "SecurityGroupId": "sg-legacy",
        "SecurityGroupIds": {"SecurityGroupId": ["sg-new-1", "sg-new-2"]},
        "SystemDisk": {"Category": "cloud_essd", "Encrypted": "true", "KMSKeyId": "key-1"}
      }
    }`

	var version ecsclient.DescribeLaunchTemplateVersionsResponseBodyLaunchTemplateVersionSetsLaunchTemplateVersionSet
	require.NoError(t, json.Unmarshal([]byte(payload), &version))

	assert.Equal(t, int64(3), tea.Int64Value(version.VersionNumber))
	assert.True(t, tea.BoolValue(version.DefaultVersion))

	data := version.LaunchTemplateData
	require.NotNil(t, data)
	assert.Equal(t, "deploy-role", tea.StringValue(data.RamRoleName))
	assert.True(t, ecsImdsV2Required(data.HttpTokens))
	assert.Equal(t, int32(2), tea.Int32Value(data.HttpPutResponseHopLimit))
	// user data arrives base64-encoded and must reach the field as script text
	assert.Equal(t, "echo hello", decodeUserData(tea.StringValue(data.UserData)))
	assert.Equal(t, int32(100), tea.Int32Value(data.InternetMaxBandwidthOut))

	// the API carries security groups in two shapes; both must be collected or
	// a template's groups read as fewer than it applies
	assert.Equal(t, "sg-legacy", tea.StringValue(data.SecurityGroupId))
	require.NotNil(t, data.SecurityGroupIds)
	assert.Equal(t, []string{"sg-new-1", "sg-new-2"}, strPtrsToStrings(data.SecurityGroupIds.SecurityGroupId))

	require.NotNil(t, data.SystemDisk)
	assert.True(t, ecsDiskEncrypted(data.SystemDisk.Encrypted))
	assert.Equal(t, "key-1", tea.StringValue(data.SystemDisk.KMSKeyId))
}

// TestLaunchTemplateDataAbsent checks that a version carrying no launch data,
// and one whose members are absent, read as the safe values.
func TestLaunchTemplateDataAbsent(t *testing.T) {
	var version ecsclient.DescribeLaunchTemplateVersionsResponseBodyLaunchTemplateVersionSetsLaunchTemplateVersionSet
	require.NoError(t, json.Unmarshal([]byte(`{"VersionNumber":1,"LaunchTemplateData":{}}`), &version))

	data := version.LaunchTemplateData
	require.NotNil(t, data)
	// no metadata-service hardening claimed for a template that says nothing
	assert.False(t, ecsImdsV2Required(data.HttpTokens))
	assert.False(t, ecsDiskEncrypted(nil))
	assert.Equal(t, "", decodeUserData(tea.StringValue(data.UserData)))
	assert.Nil(t, data.SecurityGroupIds)
	// a version that is not the default must not read as the default
	assert.False(t, tea.BoolValue(version.DefaultVersion))
}
