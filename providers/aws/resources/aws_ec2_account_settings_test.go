// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestEmptyStringToNil(t *testing.T) {
	assert.Equal(t, llx.NilData, emptyStringToNil(""))
	assert.Equal(t, llx.StringData("required"), emptyStringToNil("required"))
}

// A region with no account-level defaults must report null for every setting. An
// empty string would compare equal to neither "required" nor "optional" while
// still looking like a value that was read, which is how a missing guardrail
// gets mistaken for a permissive one.
func TestInstanceMetadataDefaultArgsWithoutDefaults(t *testing.T) {
	args := instanceMetadataDefaultArgs(instanceMetadataDefaultsResult{region: "us-east-1"})

	assert.Equal(t, llx.StringData("us-east-1"), args["region"])
	assert.Equal(t, llx.BoolData(false), args["managedByDeclarativePolicy"])
	for _, field := range []string{
		"httpTokens", "httpEndpoint", "httpPutResponseHopLimit",
		"instanceMetadataTags", "httpTokensEnforced",
	} {
		assert.Equal(t, llx.NilData, args[field], "expected %s to be null", field)
	}
}

func TestInstanceMetadataDefaultArgs(t *testing.T) {
	args := instanceMetadataDefaultArgs(instanceMetadataDefaultsResult{
		region: "eu-central-1",
		defaults: &ec2types.InstanceMetadataDefaultsResponse{
			HttpTokens:              ec2types.HttpTokensStateRequired,
			HttpEndpoint:            ec2types.InstanceMetadataEndpointStateEnabled,
			HttpPutResponseHopLimit: aws.Int32(2),
			InstanceMetadataTags:    ec2types.InstanceMetadataTagsStateDisabled,
			ManagedBy:               ec2types.ManagedByDeclarativePolicy,
		},
	})

	assert.Equal(t, llx.StringData("required"), args["httpTokens"])
	assert.Equal(t, llx.StringData("enabled"), args["httpEndpoint"])
	assert.Equal(t, llx.StringData("disabled"), args["instanceMetadataTags"])
	assert.Equal(t, int64(2), args["httpPutResponseHopLimit"].Value)
	assert.Equal(t, llx.BoolData(true), args["managedByDeclarativePolicy"])
	// The API left HttpTokensEnforced unset, which must stay null.
	assert.Equal(t, llx.NilData, args["httpTokensEnforced"])
}

// An account-level default that is not pinned by an organization declarative
// policy reports managedByDeclarativePolicy false rather than null.
func TestInstanceMetadataDefaultArgsAccountManaged(t *testing.T) {
	args := instanceMetadataDefaultArgs(instanceMetadataDefaultsResult{
		region: "us-west-2",
		defaults: &ec2types.InstanceMetadataDefaultsResponse{
			HttpTokens: ec2types.HttpTokensStateOptional,
			ManagedBy:  ec2types.ManagedByAccount,
		},
	})

	assert.Equal(t, llx.StringData("optional"), args["httpTokens"])
	assert.Equal(t, llx.BoolData(false), args["managedByDeclarativePolicy"])
}

func TestInstanceUserDataPresent(t *testing.T) {
	tests := []struct {
		name     string
		userData string
		want     bool
	}{
		{"script", "#!/bin/bash\necho hello", true},
		{"empty", "", false},
		{"whitespace only", "  \n\t ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := &mqlAwsEc2Instance{UserData: setString(tt.userData)}
			got, err := instance.userDataPresent()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
