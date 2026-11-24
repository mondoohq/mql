// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strconv"
	"testing"

	iaas "github.com/stackitcloud/stackit-sdk-go/services/iaas/v2api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestRouteArgs(t *testing.T) {
	// Synthetic: routes shaped after the SDK's Route model; no live account was checked.
	cases := []struct {
		name, payload           string
		destination, typ, value string
		internet                bool
	}{
		{"internet next hop", `{"id":"11111111-1111-4111-8111-111111111111","destination":{"type":"cidrv4","value":"0.0.0.0/0"},"nexthop":{"type":"internet"}}`,
			"0.0.0.0/0", "internet", "", true},
		{"ipv4 next hop", `{"id":"22222222-2222-4222-8222-222222222222","destination":{"type":"cidrv4","value":"10.1.0.0/16"},"nexthop":{"type":"ipv4","value":"10.0.0.1"}}`,
			"10.1.0.0/16", "ipv4", "10.0.0.1", false},
		{"blackhole next hop", `{"id":"33333333-3333-4333-8333-333333333333","destination":{"type":"cidrv6","value":"2001:db8::/32"},"nexthop":{"type":"blackhole"}}`,
			"2001:db8::/32", "blackhole", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r iaas.Route
			require.NoError(t, json.Unmarshal([]byte(tc.payload), &r))
			args := routeArgs("rt-1", &r)
			assert.Equal(t, tc.destination, args["destination"].Value)
			assert.Equal(t, tc.typ, args["nexthopType"].Value)
			assert.Equal(t, tc.value, args["nexthopValue"].Value)
			assert.Equal(t, tc.internet, args["nexthopInternet"].Value)
		})
	}
}

func TestQuotaEntries(t *testing.T) {
	// Synthetic: no live account was checked.
	assert.Nil(t, quotaEntries(nil))
	var resp iaas.QuotaListResponse
	q := func(l, u int) string { return `{"limit":` + itoa(l) + `,"usage":` + itoa(u) + `}` }
	require.NoError(t, json.Unmarshal([]byte(`{"quotas":{"backupGigabytes":`+q(1, 0)+`,"backups":`+q(2, 0)+
		`,"gigabytes":`+q(3, 0)+`,"networks":`+q(4, 0)+`,"nics":`+q(5, 0)+`,"publicIps":`+q(6, 5)+
		`,"ram":`+q(7, 0)+`,"securityGroupRules":`+q(8, 0)+`,"securityGroups":`+q(9, 0)+
		`,"snapshots":`+q(10, 0)+`,"vcpu":`+q(11, 3)+`,"volumes":`+q(12, 0)+`}}`), &resp))
	quotas := resp.GetQuotas()
	entries := quotaEntries(&quotas)
	require.Len(t, entries, 12)
	byName := map[string]iaas.Quota{}
	for _, e := range entries {
		byName[e.name] = e.quota
	}
	assert.Equal(t, int64(6), byName["publicIps"].Limit)
	assert.Equal(t, int64(5), byName["publicIps"].Usage)
	assert.Equal(t, int64(11), byName["vcpu"].Limit)
	assert.Equal(t, int64(3), byName["vcpu"].Usage)
	assert.Equal(t, int64(12), byName["volumes"].Limit)
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestPublicRangeCidrs(t *testing.T) {
	// Synthetic: no live account was checked.
	got := publicRangeCidrs([]iaas.PublicNetwork{
		{Cidr: "193.148.160.0/19", Region: "eu01"},
		{Cidr: "", Region: "eu01"},
		{Cidr: "193.148.160.0/19", Region: "eu02"},
		{Cidr: "45.129.40.0/21", Region: "eu02"},
	})
	assert.Equal(t, []string{"193.148.160.0/19", "45.129.40.0/21"}, got)
}

func TestServerAttachedVolumes(t *testing.T) {
	// Synthetic: a data volume kept on deletion and one whose setting is not
	// reported; no live account was checked.
	serverID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	volA := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	volB := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	base := "GET /v2/projects/" + fakeProjectID + "/regions/" + fakeRegion
	runtime, api := fakeRuntime(t, map[string]fakeAnswer{
		base + "/servers/" + serverID + "/volume-attachments": json200(`{"items":[` +
			`{"volumeId":"` + volA + `","deleteOnTermination":false},{"volumeId":"` + volB + `"}]}`),
		base + "/volumes": json200(`{"items":[{"id":"` + volA + `","name":"data","availabilityZone":"eu01-1"}]}`),
	})
	res, err := CreateResource(runtime, "stackit.server", map[string]*llx.RawData{"id": llx.StringData(serverID)})
	require.NoError(t, err)
	attached := res.(*mqlStackitServer).GetAttachedVolumes()
	require.NoError(t, attached.Error)
	require.Len(t, attached.Data, 2)

	a := attached.Data[0].(*mqlStackitServerAttachedVolume)
	assert.False(t, a.DeleteOnTermination.Data)
	assert.False(t, a.GetDeleteOnTermination().IsNull())
	vol := a.GetVolume()
	require.NoError(t, vol.Error)
	require.NotNil(t, vol.Data)
	assert.Equal(t, "data", vol.Data.Name.Data)

	b := attached.Data[1].(*mqlStackitServerAttachedVolume)
	assert.True(t, b.GetDeleteOnTermination().IsNull(), "an unreported setting is null, not false")
	vol = b.GetVolume()
	require.NoError(t, vol.Error)
	assert.Nil(t, vol.Data, "a volume the project list does not hold reads as null")
	assert.Equal(t, 1, api.count(base+"/volumes"), "volumes resolve through one list call")
}
