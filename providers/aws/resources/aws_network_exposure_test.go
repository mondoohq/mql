// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestSecurityGroupCount(t *testing.T) {
	assert.Equal(t, 0, securityGroupCount(nil), "a nil TValue means no groups")
	assert.Equal(t, 0, securityGroupCount(&plugin.TValue[[]any]{}))
	assert.Equal(t, 0, securityGroupCount(&plugin.TValue[[]any]{Data: []any{}}))
	assert.Equal(t, 2, securityGroupCount(&plugin.TValue[[]any]{Data: []any{1, 2}}))
}

// securityGroupsTValue builds a resolved security-group list holding one group
// with a single ingress rule, open to the internet or not.
func securityGroupsTValue(runtime *plugin.Runtime, open bool) *plugin.TValue[[]any] {
	perm := &mqlAwsEc2SecuritygroupIppermission{
		MqlRuntime:           runtime,
		IncludesPublicSource: plugin.TValue[bool]{Data: open, State: plugin.StateIsSet},
	}
	sg := &mqlAwsEc2Securitygroup{
		MqlRuntime:    runtime,
		IpPermissions: plugin.TValue[[]any]{Data: []any{perm}, State: plugin.StateIsSet},
	}
	return &plugin.TValue[[]any]{Data: []any{sg}, State: plugin.StateIsSet}
}

func nullPublicAccess() *plugin.TValue[bool] {
	return &plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
}

// TestBuildNetworkExposureNullPublicAccess pins the safe-verdict rule: a
// public-access toggle that was never read (an Aurora cluster, which carries no
// PubliclyAccessible at all, or a detail call that was denied) must leave both
// publiclyAccessible and internetReachable null on the exposure. Reporting false
// there claims the resource is shielded from the internet on evidence nobody
// has, and silently passes an audit.
func TestBuildNetworkExposureNullPublicAccess(t *testing.T) {
	tests := []struct {
		name               string
		publiclyAccessible *plugin.TValue[bool]
		sgsOpen            bool
		noSecurityGroups   bool
		wantSgAllows       bool
	}{
		{
			name:               "null public access with no security groups",
			publiclyAccessible: nullPublicAccess(),
			noSecurityGroups:   true,
		},
		{
			name:               "null public access with a security group that allows ingress",
			publiclyAccessible: nullPublicAccess(),
			sgsOpen:            true,
			wantSgAllows:       true,
		},
		{
			name:               "null public access with a closed security group",
			publiclyAccessible: nullPublicAccess(),
		},
		{
			name:               "absent public access TValue",
			publiclyAccessible: nil,
			sgsOpen:            true,
			wantSgAllows:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := testRuntime()
			var sgs *plugin.TValue[[]any]
			if !tt.noSecurityGroups {
				sgs = securityGroupsTValue(runtime, tt.sgsOpen)
			}

			exposure, err := buildNetworkExposure(runtime, tt.name+"/exposure", tt.publiclyAccessible, sgs)
			require.NoError(t, err)
			require.NotNil(t, exposure)

			assert.True(t, exposure.PubliclyAccessible.IsNull(), "publiclyAccessible must stay null")
			assert.True(t, exposure.PubliclyAccessible.IsSet(), "publiclyAccessible must be marked resolved")
			assert.True(t, exposure.InternetReachable.IsNull(), "internetReachable must stay null")
			assert.True(t, exposure.InternetReachable.IsSet(), "internetReachable must be marked resolved")

			// The security-group half of the answer was read, so it is still
			// reported even though the public-access half was not.
			assert.False(t, exposure.SecurityGroupAllowsIngress.IsNull())
			assert.Equal(t, tt.wantSgAllows, exposure.SecurityGroupAllowsIngress.Data)
		})
	}
}

// TestBuildNetworkExposureKnownPublicAccess covers the verdicts for a
// public-access toggle that was actually read.
//
// The no-security-groups case is a regression guard: an internet-facing NLB has
// no security groups (they cannot be attached after creation, and Gateway Load
// Balancers never support them), so requiring an open security-group rule
// reported every such load balancer as unreachable.
func TestBuildNetworkExposureKnownPublicAccess(t *testing.T) {
	tests := []struct {
		name                  string
		publiclyAccessible    bool
		sgsOpen               bool
		noSecurityGroups      bool
		wantInternetReachable bool
		wantSgAllows          bool
	}{
		{
			name:                  "private resource with an open group is not reachable",
			publiclyAccessible:    false,
			sgsOpen:               true,
			wantInternetReachable: false,
			wantSgAllows:          true,
		},
		{
			name:                  "public resource with an open group is reachable",
			publiclyAccessible:    true,
			sgsOpen:               true,
			wantInternetReachable: true,
			wantSgAllows:          true,
		},
		{
			name:                  "public resource whose group is closed is not reachable",
			publiclyAccessible:    true,
			sgsOpen:               false,
			wantInternetReachable: false,
			wantSgAllows:          false,
		},
		{
			name:                  "public load balancer with no security groups is reachable",
			publiclyAccessible:    true,
			noSecurityGroups:      true,
			wantInternetReachable: true,
			wantSgAllows:          false,
		},
		{
			name:                  "private resource with no security groups is not reachable",
			publiclyAccessible:    false,
			noSecurityGroups:      true,
			wantInternetReachable: false,
			wantSgAllows:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := testRuntime()
			var sgs *plugin.TValue[[]any]
			if !tt.noSecurityGroups {
				sgs = securityGroupsTValue(runtime, tt.sgsOpen)
			}

			exposure, err := buildNetworkExposure(runtime, tt.name+"/exposure", knownPublicAccess(tt.publiclyAccessible), sgs)
			require.NoError(t, err)
			require.NotNil(t, exposure)

			assert.False(t, exposure.PubliclyAccessible.IsNull(), "a read toggle is never null")
			assert.Equal(t, tt.publiclyAccessible, exposure.PubliclyAccessible.Data)
			assert.False(t, exposure.InternetReachable.IsNull(), "a read toggle yields a verdict")
			assert.Equal(t, tt.wantInternetReachable, exposure.InternetReachable.Data)
			assert.Equal(t, tt.wantSgAllows, exposure.SecurityGroupAllowsIngress.Data)
			assert.Len(t, exposure.OpenIngressRules.Data, map[bool]int{true: 1, false: 0}[tt.wantSgAllows])
		})
	}
}

func TestPublicAccessIsUnknown(t *testing.T) {
	assert.True(t, publicAccessIsUnknown(nil), "an absent TValue is unknown")
	assert.True(t, publicAccessIsUnknown(&plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}))
	assert.True(t, publicAccessIsUnknown(&plugin.TValue[bool]{Data: true, State: plugin.StateIsSet | plugin.StateIsNull}),
		"a null state wins over whatever the zero-value data says")
	assert.False(t, publicAccessIsUnknown(knownPublicAccess(false)))
	assert.False(t, publicAccessIsUnknown(knownPublicAccess(true)))
}
