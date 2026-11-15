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

func TestCidrsAdmitInternet(t *testing.T) {
	tests := []struct {
		name  string
		cidrs []any
		want  bool
	}{
		{"empty list, EKS applies 0.0.0.0/0", nil, true},
		{"IPv4 default", []any{"0.0.0.0/0"}, true},
		{"IPv6 default alongside a narrow range", []any{"203.0.113.0/24", "::/0"}, true},
		{"IPv6 default written as ::0/0", []any{"::0/0"}, true},
		{"whitespace-padded default", []any{" 0.0.0.0/0 "}, true},
		{"unparseable entry", []any{"not-a-cidr"}, true},
		{"unparseable entry beside a narrow range", []any{"203.0.113.7/32", "0.0.0.0"}, true},
		{"IPv4 halves", []any{"128.0.0.0/1", "0.0.0.0/1"}, true},
		{"IPv6 halves", []any{"::/1", "8000::/1"}, true},
		{"IPv4 quarters with an overlap", []any{"0.0.0.0/2", "64.0.0.0/2", "0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"}, true},
		{"unmasked host bits", []any{"10.1.2.3/0"}, true},
		{"IPv4-mapped IPv6 default", []any{"::ffff:0.0.0.0/96"}, true},
		{"single address", []any{"203.0.113.7/32"}, false},
		{"lower IPv4 half only", []any{"0.0.0.0/1"}, false},
		{"upper IPv6 half only", []any{"8000::/1"}, false},
		{"broad but not total", []any{"0.0.0.0/8", "10.0.0.0/8"}, false},
		{"halves missing one address", []any{"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/4", "240.0.0.0/5", "248.0.0.0/6", "252.0.0.0/7", "254.0.0.0/8", "255.0.0.0/9", "255.128.0.0/10", "255.192.0.0/11", "255.224.0.0/12", "255.240.0.0/13", "255.248.0.0/14", "255.252.0.0/15", "255.254.0.0/16", "255.255.0.0/17", "255.255.128.0/18", "255.255.192.0/19", "255.255.224.0/20", "255.255.240.0/21", "255.255.248.0/22", "255.255.252.0/23", "255.255.254.0/24", "255.255.255.0/25", "255.255.255.128/26", "255.255.255.192/27", "255.255.255.224/28", "255.255.255.240/29", "255.255.255.248/30", "255.255.255.252/31", "255.255.255.254/32"}, false},
		{"IPv4 and IPv6 halves do not combine", []any{"0.0.0.0/1", "8000::/1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cidrsAdmitInternet(tt.cidrs))
		})
	}
}

// eksClusterForExposure builds a cluster with every field exposure() reads
// already resolved, so no AWS call is made.
func eksClusterForExposure(runtime *plugin.Runtime, publicAccess *plugin.TValue[bool], cidrs []any, sgs *plugin.TValue[[]any]) *mqlAwsEksCluster {
	c := &mqlAwsEksCluster{MqlRuntime: runtime}
	c.Arn = plugin.TValue[string]{Data: "arn:aws:eks:us-east-1:000000000000:cluster/test", State: plugin.StateIsSet}
	c.EndpointPublicAccess = *publicAccess
	c.PublicAccessCidrs = plugin.TValue[[]any]{Data: cidrs, State: plugin.StateIsSet}
	if sgs == nil {
		sgs = &plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	}
	c.ClusterSecurityGroups = *sgs
	return c
}

// TestEksClusterExposure pins that the public endpoint's verdict follows
// publicAccessCidrs and not the cluster security groups, which apply only to
// the private endpoint.
func TestEksClusterExposure(t *testing.T) {
	tests := []struct {
		name                  string
		publicAccess          bool
		cidrs                 []any
		sgsOpen               *bool
		wantInternetReachable bool
		wantSgAllows          bool
	}{
		{
			name:                  "public endpoint restricted to one address is not reachable",
			publicAccess:          true,
			cidrs:                 []any{"203.0.113.7/32"},
			wantInternetReachable: false,
		},
		{
			name:                  "public endpoint open to the internet behind a closed security group is reachable",
			publicAccess:          true,
			cidrs:                 []any{"0.0.0.0/0"},
			sgsOpen:               new(false),
			wantInternetReachable: true,
		},
		{
			name:                  "public endpoint open over IPv6 is reachable",
			publicAccess:          true,
			cidrs:                 []any{"::/0"},
			wantInternetReachable: true,
		},
		{
			name:                  "restricted public endpoint with a world-open security group is not reachable",
			publicAccess:          true,
			cidrs:                 []any{"203.0.113.0/24"},
			sgsOpen:               new(true),
			wantInternetReachable: false,
			wantSgAllows:          true,
		},
		{
			name:                  "public endpoint with no CIDRs listed is reachable",
			publicAccess:          true,
			cidrs:                 []any{},
			wantInternetReachable: true,
		},
		{
			name:                  "private-only endpoint is not reachable",
			publicAccess:          false,
			cidrs:                 []any{"0.0.0.0/0"},
			sgsOpen:               new(true),
			wantInternetReachable: false,
			wantSgAllows:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := testRuntime()
			var sgs *plugin.TValue[[]any]
			if tt.sgsOpen != nil {
				sgs = securityGroupsTValue(runtime, *tt.sgsOpen)
			}
			cluster := eksClusterForExposure(runtime, knownPublicAccess(tt.publicAccess), tt.cidrs, sgs)

			exposure, err := cluster.exposure()
			require.NoError(t, err)
			require.NotNil(t, exposure)

			assert.Equal(t, tt.publicAccess, exposure.PubliclyAccessible.Data)
			assert.False(t, exposure.InternetReachable.IsNull())
			assert.Equal(t, tt.wantInternetReachable, exposure.InternetReachable.Data)
			assert.Equal(t, tt.wantSgAllows, exposure.SecurityGroupAllowsIngress.Data)
		})
	}
}

func TestEksClusterExposureNullPublicAccess(t *testing.T) {
	runtime := testRuntime()
	cluster := eksClusterForExposure(runtime, nullPublicAccess(), []any{"0.0.0.0/0"}, nil)

	exposure, err := cluster.exposure()
	require.NoError(t, err)
	assert.True(t, exposure.PubliclyAccessible.IsNull())
	assert.True(t, exposure.InternetReachable.IsNull())
}
