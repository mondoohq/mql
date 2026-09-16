// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"testing"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// These tests pin the cache-key format for every sub-resource that
// builds its key from parent context. They guard against two
// regressions: (1) accidentally returning to the previous pattern
// where `parentVmid` / `parentNode` were assigned *after* CreateResource
// (so the cache key was built from a zero value), and (2) silent
// drift in the key format that would invalidate every cached value
// in a live runtime mid-session.
//
// The keys are formatted as plain strings here rather than going
// through `id()` because the new pattern doesn't call id() at all —
// the __id is passed directly to CreateResource. So these tests pin
// the string each call site builds.

func vmNetworkKey(vmid int64, slot string) string {
	return fmt.Sprintf("proxmox.vm.network/%d/%s", vmid, slot)
}

func vmDiskKey(vmid int64, slot string) string {
	return fmt.Sprintf("proxmox.vm.virtualDisk/%d/%s", vmid, slot)
}

func vmSnapshotKey(vmid int64, name string) string {
	return fmt.Sprintf("proxmox.vm.snapshot/vm/%d/%s", vmid, name)
}

func vmUpdateKey(vmid int64, pkg string) string {
	return fmt.Sprintf("proxmox.vm.update/%d/%s", vmid, pkg)
}

func vmSerialPortKey(vmid int64, slot string) string {
	return fmt.Sprintf("proxmox.vm.serialPort/%d/%s", vmid, slot)
}

func containerNetworkKey(vmid int64, slot string) string {
	return fmt.Sprintf("proxmox.container.network/%d/%s", vmid, slot)
}

func containerMountPointKey(vmid int64, slot string) string {
	return fmt.Sprintf("proxmox.container.mountPoint/%d/%s", vmid, slot)
}

func containerSnapshotKey(vmid int64, name string) string {
	return fmt.Sprintf("proxmox.vm.snapshot/ct/%d/%s", vmid, name)
}

func nodeNetworkKey(node, iface string) string {
	return "proxmox.network/" + node + "/" + iface
}

func nodeUpdateKey(node, pkg string) string {
	return "proxmox.node.update/" + node + "/" + pkg
}

func nodeDnsKey(node string) string             { return "proxmox.dns/" + node }
func nodeServiceKey(node, name string) string   { return "proxmox.service/" + node + "/" + name }
func nodeCertificateKey(node, fp string) string { return "proxmox.certificate/" + node + "/" + fp }
func nodeSubscriptionKey(node, sid string) string {
	return "proxmox.subscription/" + node + "/" + sid
}
func nodeRepositoryKey(node, id string) string { return "proxmox.repository/" + node + "/" + id }
func nodeDiskKey(node, dev string) string      { return "proxmox.node.disk/" + node + "/" + dev }
func nodeDiskSmartKey(node, dev string) string {
	return "proxmox.node.disk.smart/" + node + "/" + dev
}
func zfsPoolKey(node, name string) string { return "proxmox.zfs.pool/" + node + "/" + name }
func lvmVolumeGroupKey(node, name string) string {
	return "proxmox.lvm.volumeGroup/" + node + "/" + name
}
func lvmThinPoolKey(node, vg, lv string) string {
	return "proxmox.lvm.thinPool/" + node + "/" + vg + "/" + lv
}

// Firewall resources are scoped by `scope` (cluster, node/<name>,
// vm/<id>, ct/<id>) and need their own __id; the previous review of
// this PR caught that the id() methods were removed without the
// CreateResource sites being updated.
func firewallOptionsKey(scope string) string {
	return "proxmox.firewall.options/" + scope
}

func firewallIpsetKey(scope, name string) string {
	return "proxmox.firewall.ipset/" + scope + "/" + name
}

func firewallIpsetEntryKey(entriesScope, cidr string) string {
	return "proxmox.firewall.ipset.entry/" + entriesScope + "/" + cidr
}

func firewallAliasKey(scope, name string) string {
	return "proxmox.firewall.alias/" + scope + "/" + name
}

// firewall.rule has no natural scalar id, so its __id is scope + the rule
// tuple. Scope MUST be part of the key: it's an Internal-struct field set
// after CreateResource, so it can't come from id() (which would run with an
// empty scope) — the __id is built explicitly at the call site instead.
func firewallRuleKey(scope string, pos int, typ, action, source, dest string) string {
	return fmt.Sprintf("proxmox.firewall.rule/%s/%d/%s/%s/%s/%s", scope, pos, typ, action, source, dest)
}

// TestVMSnapshotAndContainerSnapshotKeysDoNotCollide guards the bug
// motivating this refactor: VM and container snapshots share the
// proxmox.vm.snapshot resource type, so without a scope prefix a VM
// 100 snapshot "before" and a container 100 snapshot "before" would
// cache-key-collide and only the second-fetched entry would survive.
func TestVMSnapshotAndContainerSnapshotKeysDoNotCollide(t *testing.T) {
	const guestID int64 = 100
	const name = "before"
	vm := vmSnapshotKey(guestID, name)
	ct := containerSnapshotKey(guestID, name)
	if vm == ct {
		t.Fatalf("VM and container snapshot keys collide: %q", vm)
	}
}

// TestCacheKeysIncludeParentContext rejects any future change that
// strips the parent identifier out of a sub-resource cache key.
func TestCacheKeysIncludeParentContext(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{"vm.network", vmNetworkKey(100, "net0"), "100"},
		{"vm.disk", vmDiskKey(100, "scsi0"), "100"},
		{"vm.snapshot", vmSnapshotKey(100, "before"), "100"},
		{"vm.update", vmUpdateKey(100, "openssl"), "100"},
		{"vm.serialPort", vmSerialPortKey(100, "serial0"), "100"},
		{"container.network", containerNetworkKey(200, "net0"), "200"},
		{"container.mountPoint", containerMountPointKey(200, "rootfs"), "200"},
		{"container.snapshot", containerSnapshotKey(200, "before"), "200"},
		{"node.network", nodeNetworkKey("pve1", "vmbr0"), "pve1"},
		{"node.update", nodeUpdateKey("pve1", "openssl"), "pve1"},
		{"node.dns", nodeDnsKey("pve1"), "pve1"},
		{"node.service", nodeServiceKey("pve1", "pveproxy"), "pve1"},
		{"node.certificate", nodeCertificateKey("pve1", "AB:CD:EF"), "pve1"},
		{"node.subscription", nodeSubscriptionKey("pve1", "ABCDE-12345"), "pve1"},
		{"node.repository", nodeRepositoryKey("pve1", "/etc/apt/sources.list:0"), "pve1"},
		{"node.disk", nodeDiskKey("pve1", "/dev/sda"), "pve1"},
		{"node.disk.smart", nodeDiskSmartKey("pve1", "/dev/sda"), "pve1"},
		{"zfs.pool", zfsPoolKey("pve1", "rpool"), "pve1"},
		{"lvm.volumeGroup", lvmVolumeGroupKey("pve1", "vg0"), "pve1"},
		{"lvm.thinPool", lvmThinPoolKey("pve1", "vg0", "data"), "pve1"},
		{"firewall.options (cluster)", firewallOptionsKey("cluster"), "cluster"},
		{"firewall.options (node)", firewallOptionsKey("node/pve1"), "pve1"},
		{"firewall.options (vm)", firewallOptionsKey("vm/100"), "vm/100"},
		{"firewall.options (ct)", firewallOptionsKey("ct/200"), "ct/200"},
		{"firewall.ipset (cluster)", firewallIpsetKey("cluster", "blocklist"), "cluster"},
		{"firewall.ipset (vm)", firewallIpsetKey("vm/100", "allow"), "vm/100"},
		{"firewall.ipset.entry", firewallIpsetEntryKey("vm/100/allow", "10.0.0.0/24"), "vm/100/allow"},
		{"firewall.alias (cluster)", firewallAliasKey("cluster", "office"), "cluster"},
		{"firewall.alias (ct)", firewallAliasKey("ct/200", "internal"), "ct/200"},
		{"firewall.rule (vm)", firewallRuleKey("vm/100", 0, "in", "ACCEPT", "", ""), "vm/100"},
		{"firewall.rule (ct)", firewallRuleKey("ct/200", 0, "in", "ACCEPT", "", ""), "ct/200"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !contains(tt.key, tt.want) {
				t.Errorf("key %q should contain parent identifier %q", tt.key, tt.want)
			}
		})
	}
}

// TestCacheKeysDistinctAcrossParents pins the multi-tenancy property
// of the new layout: same sub-resource slot on different parents
// MUST produce different cache keys.
func TestCacheKeysDistinctAcrossParents(t *testing.T) {
	pairs := []struct {
		name string
		a    string
		b    string
	}{
		{"vm.network across VMs", vmNetworkKey(100, "net0"), vmNetworkKey(101, "net0")},
		{"vm.disk across VMs", vmDiskKey(100, "scsi0"), vmDiskKey(101, "scsi0")},
		{"vm.serialPort across VMs", vmSerialPortKey(100, "serial0"), vmSerialPortKey(101, "serial0")},
		{"container.network across CTs", containerNetworkKey(200, "net0"), containerNetworkKey(201, "net0")},
		{"container.mountPoint across CTs", containerMountPointKey(200, "rootfs"), containerMountPointKey(201, "rootfs")},
		{"node.disk across nodes", nodeDiskKey("pve1", "/dev/sda"), nodeDiskKey("pve2", "/dev/sda")},
		{"zfs.pool across nodes", zfsPoolKey("pve1", "rpool"), zfsPoolKey("pve2", "rpool")},
		{"node.repository across nodes", nodeRepositoryKey("pve1", "f:0"), nodeRepositoryKey("pve2", "f:0")},
		{"lvm.thinPool across nodes", lvmThinPoolKey("pve1", "vg0", "data"), lvmThinPoolKey("pve2", "vg0", "data")},
		{"firewall.options across scopes", firewallOptionsKey("cluster"), firewallOptionsKey("vm/100")},
		{"firewall.options across guest scopes", firewallOptionsKey("vm/100"), firewallOptionsKey("ct/100")},
		{"firewall.ipset across scopes", firewallIpsetKey("cluster", "blocklist"), firewallIpsetKey("vm/100", "blocklist")},
		{"firewall.ipset.entry across parent ipsets", firewallIpsetEntryKey("vm/100/allow", "10.0.0.0/24"), firewallIpsetEntryKey("vm/101/allow", "10.0.0.0/24")},
		{"firewall.alias across scopes", firewallAliasKey("cluster", "office"), firewallAliasKey("vm/100", "office")},
		// The C1 regression: two rules with an identical pos/type/action/
		// source/dest tuple on different guests must NOT collide. With an empty
		// scope segment (the bug) both were "proxmox.firewall.rule//0/in/ACCEPT//"
		// and the second aliased the first.
		{"firewall.rule identical tuple across VMs",
			firewallRuleKey("vm/100", 0, "in", "ACCEPT", "", ""),
			firewallRuleKey("vm/101", 0, "in", "ACCEPT", "", "")},
		{"firewall.rule identical tuple vm vs ct",
			firewallRuleKey("vm/100", 0, "in", "ACCEPT", "", ""),
			firewallRuleKey("ct/100", 0, "in", "ACCEPT", "", "")},
	}
	for _, tt := range pairs {
		t.Run(tt.name, func(t *testing.T) {
			if tt.a == tt.b {
				t.Errorf("expected different keys; both are %q", tt.a)
			}
		})
	}
}

// TestCacheKeyHelpersMatchProductionFormat is a source-grep guard:
// when a future change rewrites a creator's __id format, this test
// reads the source to confirm the helper above still encodes it.
// Without this, a creator-side typo (e.g. "proxmox.vm.snap/...")
// would diverge silently from these tests.
func TestCacheKeyHelpersMatchProductionFormat(t *testing.T) {
	vmGo := mustReadFile(t, "vm.go")
	for _, expected := range []string{
		`"proxmox.vm.network/%d/%s"`,
		`"proxmox.vm.virtualDisk/%d/%s"`,
		`"proxmox.vm.snapshot/vm/%d/%s"`,
		`"proxmox.vm.update/%d/%s"`,
		`"proxmox.vm.serialPort/%d/%s"`,
	} {
		if !containsSubstring(vmGo, expected) {
			t.Errorf("vm.go is missing the __id format %s", expected)
		}
	}
	ctGo := mustReadFile(t, "container.go")
	for _, expected := range []string{
		`"proxmox.container.network/%d/%s"`,
		`"proxmox.container.mountPoint/%d/%s"`,
		`"proxmox.vm.snapshot/ct/%d/%s"`,
	} {
		if !containsSubstring(ctGo, expected) {
			t.Errorf("container.go is missing the __id format %s", expected)
		}
	}
	fwGo := mustReadFile(t, "firewall.go")
	for _, expected := range []string{
		`"proxmox.firewall.options/" + scope`,
		`"proxmox.firewall.ipset/" + scope`,
		`"proxmox.firewall.ipset.entry/" + r.entriesScope`,
		`"proxmox.firewall.alias/" + scope`,
	} {
		if !containsSubstring(fwGo, expected) {
			t.Errorf("firewall.go is missing the __id format %s", expected)
		}
	}
	// firewall.rule builds its __id at the CreateResource site in helpers.go.
	helpersGo := mustReadFile(t, "helpers.go")
	if !containsSubstring(helpersGo, `"proxmox.firewall.rule/%s/%d/%s/%s/%s/%s"`) {
		t.Error("helpers.go is missing the firewall.rule __id format")
	}
}
