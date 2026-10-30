// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRealmSyncJobsDecodeProxmoxIntegerBooleans(t *testing.T) {
	f := newFakePVE(t)
	// Proxmox declares `enabled` a boolean and serializes it as 1 or 0. A
	// plain Go bool would stay false against the integer form, reporting a
	// running sync job as switched off.
	f.rawRoute("/cluster/jobs/realm-sync", http.StatusOK, `{"data":[
		{"id":"ldap-nightly","realm":"corp","schedule":"daily","enabled":1,
		 "remove-vanished":"entry;acl","scope":"both","last-run":1755000000,"next-run":1755086400},
		{"id":"ad-disabled","realm":"ad","schedule":"hourly","enabled":0,
		 "remove-vanished":"none","scope":"users"},
		{"id":"no-enabled-key","realm":"oidc","schedule":"weekly","scope":"groups"}
	]}`)

	jobs, readable, err := f.conn().GetRealmSyncJobs()
	require.NoError(t, err)
	require.True(t, readable)
	require.Len(t, jobs, 3)

	require.NotNil(t, jobs[0].Enabled)
	require.True(t, jobs[0].Enabled.Bool())
	require.Equal(t, "entry;acl", jobs[0].RemoveVanished)
	require.Equal(t, int64(1755000000), jobs[0].LastRun)

	require.NotNil(t, jobs[1].Enabled)
	require.False(t, jobs[1].Enabled.Bool())

	// A payload with no `enabled` key leaves the pointer nil so the caller can
	// apply the documented default instead of reading the Go zero value as an
	// explicit "off".
	require.Nil(t, jobs[2].Enabled)
	require.Zero(t, jobs[2].LastRun)
}

func TestRealmSyncJobsListedOnce(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/jobs/realm-sync", []map[string]any{
		{"id": "j1", "realm": "corp", "schedule": "daily", "enabled": 1},
	})
	conn := f.conn()
	for range 4 {
		_, readable, err := conn.GetRealmSyncJobs()
		require.NoError(t, err)
		require.True(t, readable)
	}
	// The cluster-wide accessor and every per-realm reverse edge read the same
	// memoized listing, so a fleet of realms must not re-list once each.
	require.Equal(t, []string{"/cluster/jobs/realm-sync"}, f.requests)
}

func TestUnavailableEndpointsReportUnreadableRatherThanEmpty(t *testing.T) {
	// Reporting an empty result for an endpoint the cluster does not serve, or
	// that this token cannot read, would tell an audit "no unprotected guests"
	// and "no firewall rules" about scopes nobody looked at.
	tests := []struct {
		name   string
		status int
	}{
		{"endpoint absent on this release", http.StatusNotFound},
		{"token lacks the privilege", http.StatusForbidden},
		{"token is not authenticated for this scope", http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakePVE(t)
			f.errorRoute("/cluster/backup-info/not-backed-up", tc.status, "nope")
			f.errorRoute("/cluster/jobs/realm-sync", tc.status, "nope")
			f.errorRoute("/cluster/sdn/vnets/vnet1/firewall/rules", tc.status, "nope")
			f.errorRoute("/cluster/sdn/vnets/vnet1/firewall/options", tc.status, "nope")
			conn := f.conn()

			guests, readable, err := conn.GetGuestsNotBackedUp()
			require.NoError(t, err)
			require.False(t, readable)
			require.Empty(t, guests)

			jobs, readable, err := conn.GetRealmSyncJobs()
			require.NoError(t, err)
			require.False(t, readable)
			require.Empty(t, jobs)

			rules, readable, err := conn.GetSDNVNetFirewallRules("vnet1")
			require.NoError(t, err)
			require.False(t, readable)
			require.Empty(t, rules)

			opts, readable, err := conn.GetSDNVNetFirewallOptions("vnet1")
			require.NoError(t, err)
			require.False(t, readable)
			require.Empty(t, opts)
		})
	}
}

func TestUnavailableEndpointDoesNotSwallowATransportFailure(t *testing.T) {
	// A network blip must not degrade to "not available", which would turn a
	// failed read into a null posture verdict that looks deliberate.
	f := newFakePVE(t)
	f.server.Close()
	conn := f.conn()

	_, readable, err := conn.GetGuestsNotBackedUp()
	require.Error(t, err)
	require.False(t, readable)

	_, readable, err = conn.GetSDNVNetFirewallRules("vnet1")
	require.Error(t, err)
	require.False(t, readable)
}

func TestGuestsNotBackedUpDecodesTheDocumentedShape(t *testing.T) {
	f := newFakePVE(t)
	// The endpoint keys the guest on `vmid`, and `name` is optional.
	f.rawRoute("/cluster/backup-info/not-backed-up", http.StatusOK, `{"data":[
		{"vmid":100,"name":"web","type":"qemu"},
		{"vmid":201,"type":"lxc"}
	]}`)

	guests, readable, err := f.conn().GetGuestsNotBackedUp()
	require.NoError(t, err)
	require.True(t, readable)
	require.Equal(t, []NotBackedUpGuest{
		{VMID: 100, Name: "web", Type: "qemu"},
		{VMID: 201, Name: "", Type: "lxc"},
	}, guests)
}

func TestSDNVNetFirewallDecodesRulesAndForwardOptions(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/sdn/vnets/vnet1/firewall/rules", []map[string]any{
		{"pos": 0, "type": "forward", "action": "ACCEPT", "proto": "tcp", "dport": "22", "enable": 1},
	})
	f.route("/cluster/sdn/vnets/vnet1/firewall/options", map[string]any{
		"enable": 1, "policy_forward": "DROP", "log_level_forward": "warning",
	})
	conn := f.conn()

	rules, readable, err := conn.GetSDNVNetFirewallRules("vnet1")
	require.NoError(t, err)
	require.True(t, readable)
	require.Len(t, rules, 1)
	require.Equal(t, "ACCEPT", rules[0].Action)
	require.Equal(t, "22", rules[0].Dport)

	opts, readable, err := conn.GetSDNVNetFirewallOptions("vnet1")
	require.NoError(t, err)
	require.True(t, readable)
	require.Equal(t, "DROP", opts["policy_forward"])
	require.Equal(t, "warning", opts["log_level_forward"])
}

func TestLookupRealmIndexesOnce(t *testing.T) {
	f := newFakePVE(t)
	f.route("/access/domains", []map[string]any{
		{"realm": "pam", "type": "pam", "default": 1},
		{"realm": "corp", "type": "ldap", "tfa": "oath"},
	})
	conn := f.conn()

	corp, found, err := conn.LookupRealm("corp")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "ldap", corp.Type)
	require.Equal(t, "oath", corp.TFA)

	_, found, err = conn.LookupRealm("gone")
	require.NoError(t, err)
	require.False(t, found)

	require.Equal(t, []string{"/access/domains"}, f.requests)
}
