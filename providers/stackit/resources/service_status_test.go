// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"reflect"
	"testing"

	serverbackup "github.com/stackitcloud/stackit-sdk-go/services/serverbackup/v2api"
	serverupdate "github.com/stackitcloud/stackit-sdk-go/services/serverupdate/v2api"
	vpn "github.com/stackitcloud/stackit-sdk-go/services/vpn/v1api"
)

// TestServerBackupPolicyArgs pins the policy mapping: the flags stay
// tri-state and the retention period is lifted out of the nested properties
// block, reading null rather than 0 when the block or the value is absent.
func TestServerBackupPolicyArgs(t *testing.T) {
	var full serverbackup.BackupPolicy
	if err := json.Unmarshal([]byte(`{
		"id": "pol-1", "name": "nightly", "description": "Nightly full backup",
		"enabled": true, "default": true, "rrule": "DTSTART;TZID=Europe/Berlin:20260101T020000 RRULE:FREQ=DAILY",
		"backupProperties": {"name": "nightly-{{server}}", "retentionPeriod": 14}
	}`), &full); err != nil {
		t.Fatalf("decoding policy: %v", err)
	}
	// The *Ptr constructors store the dereferenced value, or nil for null, so
	// the fields are compared as plain values here.
	args := serverBackupPolicyArgs(&full)
	if got := args["enabled"].Value; got != true {
		t.Fatalf("enabled = %v, want true", got)
	}
	if got := args["default"].Value; got != true {
		t.Fatalf("default = %v, want true", got)
	}
	if got := args["retentionPeriod"].Value; got != int64(14) {
		t.Fatalf("retentionPeriod = %v (%T), want 14", got, got)
	}
	if got := args["backupName"].Value; got != "nightly-{{server}}" {
		t.Fatalf("backupName = %v", got)
	}

	var bare serverbackup.BackupPolicy
	if err := json.Unmarshal([]byte(`{"id": "pol-2", "name": "manual"}`), &bare); err != nil {
		t.Fatalf("decoding bare policy: %v", err)
	}
	bareArgs := serverBackupPolicyArgs(&bare)
	if bareArgs["enabled"].Value != nil || bareArgs["default"].Value != nil {
		t.Fatalf("absent flags = %v/%v, want null", bareArgs["enabled"].Value, bareArgs["default"].Value)
	}
	if got := bareArgs["retentionPeriod"].Value; got != nil {
		t.Fatalf("retentionPeriod without properties = %v, want null", got)
	}
}

// TestServerUpdatePolicyArgs pins the update-policy mapping, in particular
// that an absent maintenance window reads null rather than a zero-hour window.
func TestServerUpdatePolicyArgs(t *testing.T) {
	var p serverupdate.UpdatePolicy
	if err := json.Unmarshal([]byte(`{"id": "up-1", "name": "weekly", "enabled": false, "default": true, "rrule": "RRULE:FREQ=WEEKLY", "maintenanceWindow": 4}`), &p); err != nil {
		t.Fatalf("decoding policy: %v", err)
	}
	args := serverUpdatePolicyArgs(&p)
	if got := args["enabled"].Value; got != false {
		t.Fatalf("enabled = %v, want false (a real false, not null)", got)
	}
	if got := args["maintenanceWindow"].Value; got != int64(4) {
		t.Fatalf("maintenanceWindow = %v (%T), want 4", got, got)
	}
	var bare serverupdate.UpdatePolicy
	if err := json.Unmarshal([]byte(`{"id": "up-2", "name": "none"}`), &bare); err != nil {
		t.Fatalf("decoding bare policy: %v", err)
	}
	if got := serverUpdatePolicyArgs(&bare)["maintenanceWindow"].Value; got != nil {
		t.Fatalf("absent maintenanceWindow = %v, want null", got)
	}
}

const gatewayStatusFixture = `{
	"id": "gw-1", "displayName": "office", "gatewayStatus": "READY",
	"tunnels": [
		{"name": "tunnel1", "publicIP": "203.0.113.10", "internalNextHopIP": "10.0.0.2", "instanceState": "READY",
		 "bgpStatus": {"peers": [{"localAs": 65001, "remoteAs": 65002, "remoteIP": "198.51.100.1", "state": "Established", "peerUptime": "3d02h", "pfxRcd": 12, "pfxSnt": 3}], "routes": []}},
		{"name": "tunnel2", "publicIP": "203.0.113.11", "internalNextHopIP": "10.0.0.3", "instanceState": "READY"}
	],
	"connections": [
		{"id": "conn-1", "displayName": "hq", "enabled": true, "tunnels": [
			{"name": "tunnel1", "established": true,
			 "phase1": {"dhGroup": "modp2048", "encryptionAlgorithm": "aes256", "integrityAlgorithm": "sha256", "state": "ESTABLISHED"},
			 "phase2": {"dhGroup": "modp2048", "encryptionAlgorithm": "aes128gcm16", "integrityAlgorithm": "none", "encap": "UDP", "protocol": "ESP", "state": "INSTALLED", "bytesIn": "10", "bytesOut": "20", "packetsIn": "1", "packetsOut": "2"}},
			{"name": "tunnel2", "established": false, "phase1": {"state": "CONNECTING"}}
		]}
	]
}`

// TestGatewayPublicIPs pins the public-address projection: one entry per
// distinct tunnel endpoint, sorted, and nil for an unreadable status.
func TestGatewayPublicIPs(t *testing.T) {
	var st vpn.GatewayStatusResponse
	if err := json.Unmarshal([]byte(gatewayStatusFixture), &st); err != nil {
		t.Fatalf("decoding status: %v", err)
	}
	if got := gatewayPublicIPs(&st); !reflect.DeepEqual(got, []string{"203.0.113.10", "203.0.113.11"}) {
		t.Fatalf("publicIps = %v", got)
	}
	if got := gatewayPublicIPs(&vpn.GatewayStatusResponse{}); len(got) != 0 {
		t.Fatalf("empty status = %v, want empty", got)
	}
	if got := gatewayPublicIPs(nil); got != nil {
		t.Fatalf("nil status = %v, want nil", got)
	}
}

// TestFindTunnelStatus pins the lookup the negotiated-parameter accessors
// depend on: the right connection and slot, the offered-versus-negotiated
// distinction (the fixture offers aes256 but the data channel negotiated
// aes128gcm16), and nil for an unknown connection or slot.
func TestFindTunnelStatus(t *testing.T) {
	var st vpn.GatewayStatusResponse
	if err := json.Unmarshal([]byte(gatewayStatusFixture), &st); err != nil {
		t.Fatalf("decoding status: %v", err)
	}
	t1 := findTunnelStatus(&st, "conn-1", "tunnel1")
	if t1 == nil || !t1.GetEstablished() {
		t.Fatalf("tunnel1 = %+v, want established", t1)
	}
	if p2, ok := t1.GetPhase2Ok(); !ok || p2.GetEncryptionAlgorithm() != "aes128gcm16" || p2.GetEncap() != "UDP" {
		t.Fatalf("tunnel1 phase2 = %+v, want the negotiated aes128gcm16 over UDP", p2)
	}
	t2 := findTunnelStatus(&st, "conn-1", "tunnel2")
	if t2 == nil || t2.GetEstablished() {
		t.Fatalf("tunnel2 = %+v, want not established", t2)
	}
	if p2, ok := t2.GetPhase2Ok(); ok && p2 != nil {
		t.Fatalf("tunnel2 phase2 = %+v, want absent while connecting", p2)
	}
	if got := findTunnelStatus(&st, "conn-9", "tunnel1"); got != nil {
		t.Fatalf("unknown connection = %+v, want nil", got)
	}
	if got := findTunnelStatus(&st, "conn-1", "tunnel3"); got != nil {
		t.Fatalf("unknown slot = %+v, want nil", got)
	}
	if got := findTunnelStatus(nil, "conn-1", "tunnel1"); got != nil {
		t.Fatalf("nil status = %+v, want nil", got)
	}
}

// TestMembershipInherited pins the one derived field on a membership: a
// binding is inherited unless it sits on the scanned project itself.
func TestMembershipInherited(t *testing.T) {
	const project = "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		resourceType, resourceID string
		want                     bool
	}{
		{"project", project, false},
		{"project", "22222222-2222-2222-2222-222222222222", true},
		{"folder", "team-folder", true},
		{"organization", "acme-org", true},
	}
	for _, c := range cases {
		if got := membershipInherited(c.resourceType, c.resourceID, project); got != c.want {
			t.Fatalf("membershipInherited(%s, %s) = %v, want %v", c.resourceType, c.resourceID, got, c.want)
		}
	}
}
