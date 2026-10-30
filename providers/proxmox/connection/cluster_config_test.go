// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPropertyStringNames(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    []string
	}{
		{
			name:    "name and value",
			entries: []string{"name=Authorization,value=Bearer secret-token"},
			want:    []string{"Authorization"},
		},
		{
			// The value must never come along: it can be the credential.
			name:    "value ordered first",
			entries: []string{"value=Bearer secret-token,name=Authorization"},
			want:    []string{"Authorization"},
		},
		{
			name:    "several entries",
			entries: []string{"name=X-Api-Key,value=abc", "name=Content-Type,value=application/json"},
			want:    []string{"X-Api-Key", "Content-Type"},
		},
		{
			name:    "whitespace tolerated",
			entries: []string{" name=X-Trace , value=1 "},
			want:    []string{"X-Trace"},
		},
		{
			name:    "entry without a name is skipped",
			entries: []string{"value=orphan", ""},
			want:    []string{},
		},
		{
			name:    "empty name is skipped",
			entries: []string{"name=,value=x"},
			want:    []string{},
		},
		{
			name:    "nothing in, nothing out",
			entries: nil,
			want:    []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, PropertyStringNames(tc.entries))
		})
	}
}

func TestPropertyStringNamesNeverLeaksValues(t *testing.T) {
	got := PropertyStringNames([]string{"name=Authorization,value=Bearer super-secret"})
	for _, name := range got {
		require.NotContains(t, name, "super-secret")
		require.NotContains(t, name, "Bearer")
	}
}

// The notification, mapping, and ACME-plugin routes sit behind privileges
// PVEAuditor does not carry. A read-only scan has to degrade to an empty list
// rather than failing the whole run.
func TestPermissionDeniedEndpointsDegradeToEmpty(t *testing.T) {
	f := newFakePVE(t)
	paths := []string{
		"/cluster/notifications/targets",
		"/cluster/notifications/matchers",
		"/cluster/notifications/endpoints/smtp",
		"/cluster/notifications/endpoints/sendmail",
		"/cluster/notifications/endpoints/gotify",
		"/cluster/notifications/endpoints/webhook",
		"/cluster/metrics/server",
		"/cluster/acme/account",
		"/cluster/acme/plugins",
		"/cluster/mapping/pci",
		"/cluster/mapping/usb",
		"/cluster/sdn/controllers",
		"/cluster/sdn/ipams",
		"/cluster/sdn/dns",
	}
	for _, p := range paths {
		f.errorRoute(p, http.StatusForbidden, "Permission check failed")
	}
	conn := f.conn()

	targets, err := conn.GetNotificationTargets()
	require.NoError(t, err)
	require.Empty(t, targets)

	matchers, err := conn.GetNotificationMatchers()
	require.NoError(t, err)
	require.Empty(t, matchers)

	smtp, err := conn.GetSMTPEndpoints()
	require.NoError(t, err)
	require.Empty(t, smtp)

	webhooks, err := conn.GetWebhookEndpoints()
	require.NoError(t, err)
	require.Empty(t, webhooks)

	metrics, err := conn.GetMetricServers()
	require.NoError(t, err)
	require.Empty(t, metrics)

	plugins, err := conn.GetACMEPlugins()
	require.NoError(t, err)
	require.Empty(t, plugins)

	pci, err := conn.GetPCIMappings()
	require.NoError(t, err)
	require.Empty(t, pci)

	controllers, err := conn.GetSDNControllers()
	require.NoError(t, err)
	require.Empty(t, controllers)
}

// A 5xx is a real failure, not a permission boundary, and must not be
// swallowed the way a 403 is.
func TestServerErrorsStillSurface(t *testing.T) {
	f := newFakePVE(t)
	f.errorRoute("/cluster/notifications/targets", http.StatusInternalServerError, "boom")

	_, err := f.conn().GetNotificationTargets()
	require.Error(t, err)
}

func TestGetWebhookEndpoints(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/notifications/endpoints/webhook", []map[string]any{
		{
			"name": "alerts", "url": "http://hooks.example.com/pve",
			"method": "post", "origin": "user-created",
			"header": []string{"name=Content-Type,value=application/json"},
			"secret": []string{"name=token,value=redacted"},
		},
	})

	endpoints, err := f.conn().GetWebhookEndpoints()
	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	require.Equal(t, "http://hooks.example.com/pve", endpoints[0].URL)
	require.Equal(t, []string{"Content-Type"}, PropertyStringNames(endpoints[0].Header))
	require.Equal(t, []string{"token"}, PropertyStringNames(endpoints[0].Secret))
}

func TestGetSMTPEndpoints(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/notifications/endpoints/smtp", []map[string]any{
		{
			"name": "mail", "server": "smtp.example.com", "port": 587,
			"mode": "starttls", "from-address": "pve@example.com",
			"username": "pve", "mailto": []string{"ops@example.com"},
			"mailto-user": []string{"root@pam"}, "origin": "user-created",
		},
	})

	endpoints, err := f.conn().GetSMTPEndpoints()
	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	require.Equal(t, "starttls", endpoints[0].Mode)
	require.Equal(t, 587, endpoints[0].Port)
	require.Equal(t, []string{"ops@example.com"}, endpoints[0].Mailto)
	require.Equal(t, []string{"root@pam"}, endpoints[0].MailtoUser)
}

func TestGetMetricServers(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/metrics/server", []map[string]any{
		{"id": "influx", "type": "influxdb", "server": "10.0.0.9", "port": 8086, "disable": 0},
	})

	servers, err := f.conn().GetMetricServers()
	require.NoError(t, err)
	require.Len(t, servers, 1)
	require.Equal(t, "influxdb", servers[0].Type)
	require.Equal(t, 8086, servers[0].Port)
	require.False(t, servers[0].Disable.Bool())
}

func TestGetCorosyncConfig(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/config/join", map[string]any{
		"config_digest":  "abc123",
		"preferred_node": "pve1",
		"totem":          map[string]any{"cluster_name": "prod", "secauth": "on"},
		"nodelist": []map[string]any{
			{"name": "pve1", "nodeid": 1, "quorum_votes": 1, "ring0_addr": "10.0.0.1", "pve_addr": "10.0.0.1", "pve_fp": "AA:BB"},
			{"name": "pve2", "nodeid": 2, "quorum_votes": 1, "ring0_addr": "10.0.0.2", "ring1_addr": "10.1.0.2"},
		},
	})

	cfg, err := f.conn().GetCorosyncConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, "pve1", cfg.PreferredNode)
	require.Len(t, cfg.NodeList, 2)
	require.Empty(t, cfg.NodeList[0].Ring1Addr, "a single-link member reports no ring 1")
	require.Equal(t, "10.1.0.2", cfg.NodeList[1].Ring1Addr)
	require.Equal(t, "prod", cfg.Totem["cluster_name"])
}

func TestGetCorosyncConfig_StandaloneNode(t *testing.T) {
	f := newFakePVE(t)
	// A standalone node has no cluster configuration; PVE answers 404.
	f.errorRoute("/cluster/config/join", http.StatusNotFound, "no cluster")

	cfg, err := f.conn().GetCorosyncConfig()
	require.NoError(t, err, "a standalone node is not a failure")
	require.Nil(t, cfg)
}

func TestGetCorosyncConfig_FetchedOnce(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/config/join", map[string]any{"preferred_node": "pve1"})
	conn := f.conn()

	for range 4 {
		_, err := conn.GetCorosyncConfig()
		require.NoError(t, err)
	}

	var fetches int
	for _, path := range f.requests {
		if path == "/cluster/config/join" {
			fetches++
		}
	}
	require.Equal(t, 1, fetches, "four resource fields read this; it must be fetched once")
}

func TestGetPCIMappings(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/mapping/pci", []map[string]any{
		{
			"id": "gpu", "description": "Tesla T4",
			"map": []map[string]any{
				{"node": "pve1", "path": "0000:01:00.0", "id": "10de:1eb8", "iommugroup": 15},
			},
		},
	})

	mappings, err := f.conn().GetPCIMappings()
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, "gpu", mappings[0].ID)
	require.Len(t, mappings[0].Map, 1)
	require.Equal(t, "pve1", mappings[0].Map[0]["node"])
}

func TestGetSDNControllers(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/sdn/controllers", []map[string]any{
		{
			"controller": "evpnctl", "type": "evpn", "asn": 65000,
			"peers": "10.0.0.1,10.0.0.2", "ebgp": 1, "state": "new",
		},
	})

	controllers, err := f.conn().GetSDNControllers()
	require.NoError(t, err)
	require.Len(t, controllers, 1)
	require.Equal(t, 65000, controllers[0].ASN)
	require.True(t, controllers[0].EBGP.Bool())
	require.Equal(t, "new", controllers[0].State)
}
