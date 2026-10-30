// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// liveRows loads rows captured from a real MikroTik device, in exactly the
// shape the RouterOS API hands to an args builder.
func liveRows(t *testing.T, fixture string) []map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "live", fixture))
	require.NoError(t, err)
	var rows []map[string]string
	require.NoError(t, json.Unmarshal(raw, &rows))
	return rows
}

// plainSchemaFields returns the fields a resource declares in the .lr that the
// args builder is responsible for populating.
//
// It reads the schema rather than the generated struct because the struct
// cannot tell the two kinds apart: a computed field (`certificate() ...`) and
// a plain one both become a plugin.TValue. Computed fields are resolved by an
// accessor on demand and must not be in the args map; plain ones must.
func plainSchemaFields(t *testing.T, resource string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("mikrotik.lr"))
	require.NoError(t, err)

	header := regexp.MustCompile(`(?m)^(?:private\s+)?` + regexp.QuoteMeta(resource) + `[\s@].*\{$`)
	loc := header.FindStringIndex(string(raw))
	require.NotNil(t, loc, "%s is not declared in mikrotik.lr", resource)

	fields := []string{}
	for line := range strings.SplitSeq(string(raw)[loc[1]:], "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "}" {
			break
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		m := regexp.MustCompile(`^(\w+)(\(\))?\s`).FindStringSubmatch(trimmed)
		if m == nil || m[2] != "" { // m[2] != "" means a computed accessor
			continue
		}
		fields = append(fields, m[1])
	}
	return fields
}

// TestLiveRowsCoverEverySchemaField drives each args builder with rows captured
// from a real device and asserts it populates every field the schema declares.
//
// Codegen accepts a field declared in the .lr with no population path: the
// generated getter hands back the zero TValue, whose State is 0 — unset, not
// null — which crosses the plugin boundary as a primitive with no type
// information and reads client-side as a null that points at nothing. Nothing
// fails to build and no other test goes red, so a field added to the schema
// but not to the builder ships silently empty.
func TestLiveRowsCoverEverySchemaField(t *testing.T) {
	for _, tc := range []struct {
		fixture  string
		resource string
		build    func(map[string]string) map[string]*llx.RawData
	}{
		{"interface.json", "mikrotik.interface", interfaceArgs},
		{"interface-bridge.json", "mikrotik.interface.bridge", bridgeArgs},
		{"interface-vlan.json", "mikrotik.interface.vlan", vlanArgs},
		{"ip-pool.json", "mikrotik.ip.pool", poolArgs},
		{"ip-ssh.json", "mikrotik.ssh", sshArgs},
		{"radius.json", "mikrotik.radius.client", radiusClientArgs},
		{"ip-ipsec-proposal.json", "mikrotik.ip.ipsec.proposal", ipsecProposalArgs},
		{"ip-ipsec-identity.json", "mikrotik.ip.ipsec.identity", ipsecIdentityArgs},
		{"interface-l2tp-server-server.json", "mikrotik.interface.l2tpServer", l2tpServerArgs},
		{"interface-sstp-server-server.json", "mikrotik.interface.sstpServer", sstpServerArgs},
		{"system-script.json", "mikrotik.system.script", scriptArgs},
		{"system-logging.json", "mikrotik.system.logging.rule", loggingRuleArgs},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			rows := liveRows(t, tc.fixture)
			if len(rows) == 0 {
				t.Skipf("%s captured no rows on the reference device", tc.fixture)
			}
			args := tc.build(rows[0])
			for _, field := range plainSchemaFields(t, tc.resource) {
				if _, ok := args[field]; !ok {
					t.Errorf("%s is declared in the schema but the builder never populates it", field)
				}
			}
		})
	}
}

// TestLiveRowsDoNotPanic runs every captured menu through its builder. These
// are real rows from a real device, so a builder that indexes past the end of
// a split or asserts a type it did not check fails here rather than in a scan,
// where a panic in a provider goroutine takes down everything, not one query.
func TestLiveRowsDoNotPanic(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		build   func(map[string]string) map[string]*llx.RawData
	}{
		{"interface.json", interfaceArgs},
		{"interface-bridge.json", bridgeArgs},
		{"interface-vlan.json", vlanArgs},
		{"ip-pool.json", poolArgs},
		{"ip-ssh.json", sshArgs},
		{"radius.json", radiusClientArgs},
		{"ip-ipsec-proposal.json", ipsecProposalArgs},
		{"ip-ipsec-identity.json", ipsecIdentityArgs},
		{"interface-l2tp-server-server.json", l2tpServerArgs},
		{"interface-sstp-server-server.json", sstpServerArgs},
		{"system-script.json", scriptArgs},
		{"system-logging.json", loggingRuleArgs},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			for _, row := range liveRows(t, tc.fixture) {
				require.NotPanics(t, func() { tc.build(row) })
			}
		})
	}
}

// TestLiveFirewallRowsAcrossTables runs the real firewall rows through the
// shared builder for every table, which is what keeps the tables from drifting
// apart again.
func TestLiveFirewallRowsAcrossTables(t *testing.T) {
	for fixture, prefix := range map[string]string{
		"ip-firewall-filter.json": "mikrotik.ip.firewall.filter/",
		"ip-firewall-nat.json":    "mikrotik.ip.firewall.nat/",
		"ip-firewall-mangle.json": "mikrotik.ip.firewall.mangle/",
		"ip-firewall-raw.json":    "mikrotik.ip.firewall.raw/",
	} {
		t.Run(fixture, func(t *testing.T) {
			rows := liveRows(t, fixture)
			require.NotEmpty(t, rows, "the reference device configured this table")
			for _, row := range rows {
				args := firewallRuleArgs(prefix, row)
				require.Equal(t, prefix+row[".id"], args["__id"].Value,
					"every real row carries a .id, so the fallback key must not be reached")
			}
		})
	}
}
