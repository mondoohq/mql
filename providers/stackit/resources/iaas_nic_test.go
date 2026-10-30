// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"

	iaas "github.com/stackitcloud/stackit-sdk-go/services/iaas/v2api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	fakeServerID  = "5f4e3d2c-1b0a-4987-8654-3210fedcba98"
	fakeServerNIC = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
	fakeRouterNIC = "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
	fakeNetworkID = "c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f"
	fakeWebSG     = "d4e5f6a7-b8c9-4d0e-9f2a-3b4c5d6e7f80"
	fakeAdminSG   = "e5f6a7b8-c9d0-4e1f-8a3b-4c5d6e7f8091"
	fakeUnusedSG  = "f6a7b8c9-d0e1-4f2a-9b4c-5d6e7f8091a2"
	fakeRouterDev = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"

	nicsPath    = "GET /v2/projects/" + fakeProjectID + "/regions/" + fakeRegion + "/nics"
	serversPath = "GET /v2/projects/" + fakeProjectID + "/regions/" + fakeRegion + "/servers"
	sgsPath     = "GET /v2/projects/" + fakeProjectID + "/regions/" + fakeRegion + "/security-groups"
)

// Synthetic: a server interface carrying two security groups and a router
// interface carrying none, shaped after the SDK's iaas NIC model; no target
// showed this.
var projectNICsBody = `{"items":[
	{"id":"` + fakeServerNIC + `","networkId":"` + fakeNetworkID + `","type":"server","device":"` + fakeServerID + `",
	 "securityGroups":["` + fakeWebSG + `","` + fakeAdminSG + `"],"ipv4":"10.0.0.5","status":"ACTIVE"},
	{"id":"` + fakeRouterNIC + `","networkId":"` + fakeNetworkID + `","type":"gateway","device":"` + fakeRouterDev + `",
	 "securityGroups":[],"ipv4":"10.0.0.1","status":"ACTIVE"}
]}`

func nic(id, nicType, device string, sgs ...string) iaas.NIC {
	n := iaas.NIC{Id: &id, Type: &nicType, SecurityGroups: sgs}
	if device != "" {
		n.Device = &device
	}
	return n
}

func TestFindNIC(t *testing.T) {
	// Synthetic: lookups against a two-interface list.
	nics := []iaas.NIC{nic(fakeServerNIC, "server", fakeServerID), nic(fakeRouterNIC, "gateway", fakeRouterDev)}
	got := findNIC(nics, fakeRouterNIC)
	require.NotNil(t, got)
	assert.Equal(t, fakeRouterNIC, got.GetId())
	assert.Nil(t, findNIC(nics, "missing"))
	assert.Nil(t, findNIC(nics, ""), "an empty id matches nothing")
}

func TestNicsWithSecurityGroup(t *testing.T) {
	// Synthetic: one group on two interfaces, one group on none.
	nics := []iaas.NIC{
		nic(fakeServerNIC, "server", fakeServerID, fakeWebSG, fakeAdminSG),
		nic(fakeRouterNIC, "gateway", fakeRouterDev, fakeWebSG),
	}
	assert.Len(t, nicsWithSecurityGroup(nics, fakeWebSG), 2)
	admin := nicsWithSecurityGroup(nics, fakeAdminSG)
	require.Len(t, admin, 1)
	assert.Equal(t, fakeServerNIC, admin[0].GetId())
	assert.Empty(t, nicsWithSecurityGroup(nics, fakeUnusedSG))
	assert.Empty(t, nicsWithSecurityGroup(nics, ""))
}

func TestNicServerID(t *testing.T) {
	// Synthetic: only a server interface's device names a server.
	s := nic(fakeServerNIC, "server", fakeServerID)
	assert.Equal(t, fakeServerID, nicServerID(&s))
	g := nic(fakeRouterNIC, "gateway", fakeRouterDev)
	assert.Equal(t, "", nicServerID(&g), "a gateway's device is not a server")
	assert.Equal(t, "", nicServerID(nil))
}

func newPublicIP(t *testing.T, runtime *plugin.Runtime, id, nicID string) *mqlStackitPublicIp {
	t.Helper()
	res, err := CreateResource(runtime, "stackit.publicIp", map[string]*llx.RawData{
		"id":                 llx.StringData(id),
		"ip":                 llx.StringData("192.0.2.10"),
		"networkInterfaceId": llx.StringData(nicID),
		"labels":             labelData(map[string]string{}),
	})
	require.NoError(t, err)
	return res.(*mqlStackitPublicIp)
}

func TestPublicIPEdges(t *testing.T) {
	routes := map[string]fakeAnswer{
		nicsPath:    json200(projectNICsBody),
		serversPath: json200(`{"items":[{"id":"` + fakeServerID + `","name":"web-1","machineType":"c1.2"}]}`),
	}

	t.Run("bound to a server interface", func(t *testing.T) {
		runtime, api := fakeRuntime(t, routes)
		ip := newPublicIP(t, runtime, "11111111-2222-4333-8444-555555555555", fakeServerNIC)

		n := ip.GetNetworkInterface()
		require.NoError(t, n.Error)
		require.NotNil(t, n.Data)
		assert.Equal(t, fakeServerNIC, n.Data.Id.Data)
		assert.Equal(t, fakeNetworkID, n.Data.NetworkId.Data)

		s := ip.GetServer()
		require.NoError(t, s.Error)
		require.NotNil(t, s.Data)
		assert.Equal(t, fakeServerID, s.Data.Id.Data)
		assert.Equal(t, "web-1", s.Data.Name.Data)
		assert.Equal(t, 1, api.count(nicsPath), "both edges share one interface list")
	})

	t.Run("bound to a gateway interface has no server", func(t *testing.T) {
		runtime, api := fakeRuntime(t, routes)
		ip := newPublicIP(t, runtime, "22222222-3333-4444-8555-666666666666", fakeRouterNIC)

		n := ip.GetNetworkInterface()
		require.NoError(t, n.Error)
		require.NotNil(t, n.Data)
		s := ip.GetServer()
		require.NoError(t, s.Error)
		assert.True(t, s.IsNull())
		assert.Equal(t, 0, api.count(serversPath), "no server list read when the interface is not a server's")
	})

	t.Run("unassigned address is null without a call", func(t *testing.T) {
		runtime, api := fakeRuntime(t, routes)
		ip := newPublicIP(t, runtime, "33333333-4444-4555-8666-777777777777", "")

		n := ip.GetNetworkInterface()
		require.NoError(t, n.Error)
		assert.True(t, n.IsNull())
		s := ip.GetServer()
		require.NoError(t, s.Error)
		assert.True(t, s.IsNull())
		assert.Equal(t, 0, api.count(nicsPath))
	})

	t.Run("interface no longer listed is null", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, routes)
		ip := newPublicIP(t, runtime, "44444444-5555-4666-8777-888888888888", "99999999-0000-4111-8222-333333333333")
		n := ip.GetNetworkInterface()
		require.NoError(t, n.Error)
		assert.True(t, n.IsNull())
	})

	t.Run("refused interface list is Forbidden", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{nicsPath: jsonStatus(http.StatusForbidden)})
		ip := newPublicIP(t, runtime, "55555555-6666-4777-8888-999999999999", fakeServerNIC)
		n := ip.GetNetworkInterface()
		require.Error(t, n.Error)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(n.Error))
	})
}

func newSecurityGroup(t *testing.T, runtime *plugin.Runtime, id string) *mqlStackitSecurityGroup {
	t.Helper()
	name := "sg-" + id[:4]
	res, err := buildSecurityGroup(runtime, &iaas.SecurityGroup{Id: &id, Name: name})
	require.NoError(t, err)
	return res.(*mqlStackitSecurityGroup)
}

func TestSecurityGroupNetworkInterfaces(t *testing.T) {
	runtime, api := fakeRuntime(t, map[string]fakeAnswer{nicsPath: json200(projectNICsBody)})

	web := newSecurityGroup(t, runtime, fakeWebSG).GetNetworkInterfaces()
	require.NoError(t, web.Error)
	require.Len(t, web.Data, 1)
	assert.Equal(t, fakeServerNIC, web.Data[0].(*mqlStackitNic).Id.Data)

	unused := newSecurityGroup(t, runtime, fakeUnusedSG).GetNetworkInterfaces()
	require.NoError(t, unused.Error)
	assert.Empty(t, unused.Data)
	assert.Equal(t, 1, api.count(nicsPath), "every group reads the one shared interface list")
}

func newRule(t *testing.T, runtime *plugin.Runtime, ruleID, remote string) *mqlStackitSecurityGroupRule {
	t.Helper()
	rule := iaas.SecurityGroupRule{Id: &ruleID, Direction: "ingress"}
	if remote != "" {
		rule.RemoteSecurityGroupId = &remote
	}
	res, err := CreateResource(runtime, "stackit.securityGroup.rule", securityGroupRuleArgs(fakeWebSG, &rule))
	require.NoError(t, err)
	return res.(*mqlStackitSecurityGroupRule)
}

func TestRuleRemoteSecurityGroup(t *testing.T) {
	// Synthetic: a web group whose rule admits the admin group.
	sgs := json200(`{"items":[
		{"id":"` + fakeWebSG + `","name":"web","stateful":true},
		{"id":"` + fakeAdminSG + `","name":"admin","stateful":true}
	]}`)

	t.Run("resolves the named group", func(t *testing.T) {
		runtime, api := fakeRuntime(t, map[string]fakeAnswer{sgsPath: sgs})
		got := newRule(t, runtime, "r-1", fakeAdminSG).GetRemoteSecurityGroup()
		require.NoError(t, got.Error)
		require.NotNil(t, got.Data)
		assert.Equal(t, fakeAdminSG, got.Data.Id.Data)
		assert.Equal(t, "admin", got.Data.Name.Data)

		again := newRule(t, runtime, "r-2", fakeWebSG).GetRemoteSecurityGroup()
		require.NoError(t, again.Error)
		assert.Equal(t, "web", again.Data.Name.Data)
		assert.Equal(t, 1, api.count(sgsPath), "rules resolve against one shared group list")
	})

	t.Run("an IP-range rule is null without a call", func(t *testing.T) {
		runtime, api := fakeRuntime(t, map[string]fakeAnswer{sgsPath: sgs})
		got := newRule(t, runtime, "r-3", "").GetRemoteSecurityGroup()
		require.NoError(t, got.Error)
		assert.True(t, got.IsNull())
		assert.Equal(t, 0, api.count(sgsPath))
	})

	t.Run("a deleted group is null", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{sgsPath: sgs})
		got := newRule(t, runtime, "r-4", fakeUnusedSG).GetRemoteSecurityGroup()
		require.NoError(t, got.Error)
		assert.True(t, got.IsNull())
	})

	t.Run("a refused group list is Forbidden", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{sgsPath: jsonStatus(http.StatusForbidden)})
		got := newRule(t, runtime, "r-5", fakeAdminSG).GetRemoteSecurityGroup()
		require.Error(t, got.Error)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(got.Error))
	})
}
