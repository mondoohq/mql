// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/llx"
)

func getStr(m map[string]*llx.RawData, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.Value.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(m map[string]*llx.RawData, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.Value.(bool); ok {
			return b
		}
	}
	return false
}

func getInt(m map[string]*llx.RawData, key string) int64 {
	if v, ok := m[key]; ok {
		if i, ok := v.Value.(int64); ok {
			return i
		}
	}
	return 0
}

func TestParseVMNetworkConfig_Virtio(t *testing.T) {
	net := parseVMNetworkConfig("net0", "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=100")

	if v := getStr(net, "model"); v != "virtio" {
		t.Errorf("expected model 'virtio', got %q", v)
	}
	if v := getStr(net, "macAddress"); v != "BC:24:11:AA:BB:CC" {
		t.Errorf("expected MAC 'BC:24:11:AA:BB:CC', got %q", v)
	}
	if v := getStr(net, "bridge"); v != "vmbr0" {
		t.Errorf("expected bridge 'vmbr0', got %q", v)
	}
	if !getBool(net, "firewall") {
		t.Error("expected firewall=true")
	}
	if v := getInt(net, "tag"); v != 100 {
		t.Errorf("expected tag 100, got %d", v)
	}
}

func TestParseVMNetworkConfig_E1000(t *testing.T) {
	net := parseVMNetworkConfig("net1", "e1000=AA:BB:CC:DD:EE:FF,bridge=vmbr1")

	if v := getStr(net, "model"); v != "e1000" {
		t.Errorf("expected model 'e1000', got %q", v)
	}
	if v := getStr(net, "bridge"); v != "vmbr1" {
		t.Errorf("expected bridge 'vmbr1', got %q", v)
	}
	if getBool(net, "firewall") {
		t.Error("expected firewall=false")
	}
}

func TestParseVMDiskConfig_Full(t *testing.T) {
	disk := parseVMDiskConfig("scsi0", "local-lvm:vm-100-disk-0,size=32G,cache=writeback,iothread=1,backup=0")

	if v := getStr(disk, "storage"); v != "local-lvm" {
		t.Errorf("expected storage 'local-lvm', got %q", v)
	}
	if v := getInt(disk, "size"); v != 32*1024*1024*1024 {
		t.Errorf("expected size 32GiB, got %d", v)
	}
	if v := getStr(disk, "cache"); v != "writeback" {
		t.Errorf("expected cache 'writeback', got %q", v)
	}
	if !getBool(disk, "iothread") {
		t.Error("expected iothread=true")
	}
	if getBool(disk, "backup") {
		t.Error("expected backup=false")
	}
}

func TestParseVMDiskConfig_Minimal(t *testing.T) {
	disk := parseVMDiskConfig("virtio0", "ceph-pool:vm-200-disk-0,size=100G")

	if v := getStr(disk, "storage"); v != "ceph-pool" {
		t.Errorf("expected storage 'ceph-pool', got %q", v)
	}
	if v := getInt(disk, "size"); v != 100*1024*1024*1024 {
		t.Errorf("expected size 100GiB, got %d", v)
	}
	if !getBool(disk, "backup") {
		t.Error("expected backup=true (default)")
	}
}

func TestParseSizeToBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"32G", 32 * 1024 * 1024 * 1024},
		{"512M", 512 * 1024 * 1024},
		{"1T", 1024 * 1024 * 1024 * 1024},
		{"4096K", 4096 * 1024},
		{"10", 10},
	}
	for _, tt := range tests {
		result := parseSizeToBytes(tt.input)
		if result != tt.expected {
			t.Errorf("parseSizeToBytes(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestParseContainerNetworkConfig_Full(t *testing.T) {
	net := parseContainerNetworkConfig("net0",
		"name=eth0,bridge=vmbr0,firewall=1,gw=192.168.1.1,hwaddr=AA:BB:CC:DD:EE:FF,ip=192.168.1.50/24,ip6=auto,tag=42,type=veth")

	if v := getStr(net, "name"); v != "eth0" {
		t.Errorf("expected name 'eth0', got %q", v)
	}
	if v := getStr(net, "macAddress"); v != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected MAC 'AA:BB:CC:DD:EE:FF', got %q", v)
	}
	if v := getStr(net, "bridge"); v != "vmbr0" {
		t.Errorf("expected bridge 'vmbr0', got %q", v)
	}
	if !getBool(net, "firewall") {
		t.Error("expected firewall=true")
	}
	if v := getInt(net, "tag"); v != 42 {
		t.Errorf("expected tag 42, got %d", v)
	}
	if v := getStr(net, "ip"); v != "192.168.1.50/24" {
		t.Errorf("expected ip '192.168.1.50/24', got %q", v)
	}
	if v := getStr(net, "gw"); v != "192.168.1.1" {
		t.Errorf("expected gw '192.168.1.1', got %q", v)
	}
	if v := getStr(net, "ip6"); v != "auto" {
		t.Errorf("expected ip6 'auto', got %q", v)
	}
}

func TestParseContainerNetworkConfig_DHCPMinimal(t *testing.T) {
	net := parseContainerNetworkConfig("net1", "name=eth0,bridge=vmbr0,ip=dhcp")

	if v := getStr(net, "name"); v != "eth0" {
		t.Errorf("expected name 'eth0', got %q", v)
	}
	if v := getStr(net, "ip"); v != "dhcp" {
		t.Errorf("expected ip 'dhcp', got %q", v)
	}
	if getBool(net, "firewall") {
		t.Error("expected firewall=false")
	}
	if v := getInt(net, "tag"); v != 0 {
		t.Errorf("expected tag 0 (untagged), got %d", v)
	}
}

func TestParseContainerMountPoint_Rootfs(t *testing.T) {
	mp := parseContainerMountPoint("rootfs", "local-lvm:vm-100-disk-0,size=8G")

	if v := getStr(mp, "storage"); v != "local-lvm" {
		t.Errorf("expected storage 'local-lvm', got %q", v)
	}
	if v := getInt(mp, "size"); v != 8*1024*1024*1024 {
		t.Errorf("expected size 8GiB, got %d", v)
	}
	if v := getStr(mp, "mountPath"); v != "/" {
		t.Errorf("expected mountPath '/' for rootfs, got %q", v)
	}
	if !getBool(mp, "backup") {
		t.Error("expected backup=true (default)")
	}
	if getBool(mp, "readonly") {
		t.Error("expected readonly=false (default)")
	}
}

func TestParseContainerMountPoint_ExtraMount(t *testing.T) {
	mp := parseContainerMountPoint("mp0", "local-zfs:subvol-200-disk-1,size=50G,mp=/var/lib/data,backup=0,ro=1,replicate=0,acl=1")

	if v := getStr(mp, "storage"); v != "local-zfs" {
		t.Errorf("expected storage 'local-zfs', got %q", v)
	}
	if v := getStr(mp, "mountPath"); v != "/var/lib/data" {
		t.Errorf("expected mountPath '/var/lib/data', got %q", v)
	}
	if getBool(mp, "backup") {
		t.Error("expected backup=false")
	}
	if !getBool(mp, "readonly") {
		t.Error("expected readonly=true")
	}
	if getBool(mp, "replicate") {
		t.Error("expected replicate=false")
	}
	if !getBool(mp, "aclEnabled") {
		t.Error("expected aclEnabled=true")
	}
}

// An additional mount point with no explicit backup= must default to
// backup=false: PVE excludes mp0..mp254 from vzdump unless backup=1 is set.
// rootfs is the only mount point backed up by default.
func TestParseContainerMountPoint_ExtraMountDefaultsNoBackup(t *testing.T) {
	mp := parseContainerMountPoint("mp0", "local-lvm:subvol-200-disk-1,size=8G,mp=/data")
	if getBool(mp, "backup") {
		t.Error("expected backup=false for an additional mount point with no explicit backup flag")
	}

	// Explicit backup=1 still opts the extra mount into backups.
	mp = parseContainerMountPoint("mp1", "local-lvm:subvol-200-disk-2,size=8G,mp=/data2,backup=1")
	if !getBool(mp, "backup") {
		t.Error("expected backup=true when backup=1 is set explicitly")
	}

	// rootfs stays backed up by default...
	mp = parseContainerMountPoint("rootfs", "local-lvm:subvol-200-disk-0,size=8G")
	if !getBool(mp, "backup") {
		t.Error("expected backup=true by default for rootfs")
	}
	// ...but honors an explicit backup=0.
	mp = parseContainerMountPoint("rootfs", "local-lvm:subvol-200-disk-0,size=8G,backup=0")
	if getBool(mp, "backup") {
		t.Error("expected backup=false when rootfs sets backup=0 explicitly")
	}
}

func TestLooksLikeMAC(t *testing.T) {
	if !looksLikeMAC("AA:BB:CC:DD:EE:FF") {
		t.Error("expected true for valid MAC")
	}
	if looksLikeMAC("not-a-mac") {
		t.Error("expected false for non-MAC")
	}
	if looksLikeMAC("") {
		t.Error("expected false for empty string")
	}
}

func TestIsNetSlotKey(t *testing.T) {
	cases := map[string]bool{
		// Valid slots — Proxmox accepts net0..net31 on VMs, fewer on
		// containers, but the validator just checks the digit suffix.
		"net0":  true,
		"net1":  true,
		"net12": true,
		"net31": true,
		// Critical regression cases: the listing endpoint exposes
		// traffic counters with names that start with "net" but aren't
		// configured interfaces.
		"netin":  false,
		"netout": false,
		// Other near-matches that should not be treated as net slots.
		"net":       false, // missing slot number
		"netname":   false,
		"network":   false,
		"":          false,
		"snet0":     false, // doesn't start with "net"
		"netfoo":    false,
		"net0extra": false,
	}
	for key, want := range cases {
		t.Run(key, func(t *testing.T) {
			if got := isNetSlotKey(key); got != want {
				t.Errorf("isNetSlotKey(%q) = %v, want %v", key, got, want)
			}
		})
	}
}
