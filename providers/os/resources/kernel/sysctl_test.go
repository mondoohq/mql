// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestSysctlDebian(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	c, err := mock.RunCommand("/sbin/sysctl -a")
	require.NoError(t, err)

	entries, err := ParseSysctl(c.Stdout, "=")
	require.NoError(t, err)

	assert.Equal(t, 32, len(entries))
	assert.Equal(t, "10000", entries["net.ipv4.conf.all.igmpv2_unsolicited_report_interval"])
}

func TestSysctlMacos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	c, err := mock.RunCommand("sysctl -a")
	require.NoError(t, err)

	entries, err := ParseSysctl(c.Stdout, ":")
	require.NoError(t, err)

	assert.Equal(t, 17, len(entries))
	assert.Equal(t, "1024", entries["net.inet6.ip6.neighborgcthresh"])
}

func TestSysctlFreebsd14(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd14.toml"))
	require.NoError(t, err)

	c, err := mock.RunCommand("sysctl -a")
	require.NoError(t, err)

	entries, err := ParseSysctl(c.Stdout, ":")
	require.NoError(t, err)

	assert.Equal(t, 20, len(entries))
	assert.Equal(t, "1", entries["security.bsd.unprivileged_mlock"])
}

func TestSysctlFreebsd15(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd15.toml"))
	require.NoError(t, err)

	c, err := mock.RunCommand("sysctl -a")
	require.NoError(t, err)

	entries, err := ParseSysctl(c.Stdout, ":")
	require.NoError(t, err)

	assert.Equal(t, 20, len(entries))
	assert.Equal(t, "15.0-BETA4", entries["kern.osrelease"])
	// the value holds colons of its own
	assert.Equal(t, "{ sec = 1762105103, usec = 779441 } Sun Nov  2 18:38:23 2025", entries["kern.boottime"])
}

func TestSysctlOpenBSD(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/openbsd77.toml"))
	require.NoError(t, err)

	c, err := mock.RunCommand("sysctl -a")
	require.NoError(t, err)

	entries, err := ParseSysctl(c.Stdout, "=")
	require.NoError(t, err)

	assert.Equal(t, 30, len(entries))
	assert.Equal(t, "OpenBSD", entries["kern.ostype"])
	// the value holds equals signs of its own
	assert.Equal(t, "tick = 10000, hz = 100, profhz = 1000, stathz = 100", entries["kern.clockrate"])
}

// FreeBSD 14.5 `sysctl -ae`: multi-line values continue on the lines after
// their name, and those lines must neither become keys of their own nor be
// lost from the value.
func TestSysctlFreebsd145MultilineValues(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd145.toml"))
	require.NoError(t, err)

	c, err := mock.RunCommand("sysctl -ae")
	require.NoError(t, err)

	entries, err := ParseSysctl(c.Stdout, "=")
	require.NoError(t, err)

	assert.Equal(t, 46, len(entries))
	assert.Equal(t, "ec2a1b2c-3d4e-5f60-7182-93a4b5c6d7e8", entries["kern.hostuuid"])
	assert.Equal(t, "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz", entries["hw.model"])
	assert.Equal(t, "/boot/kernel/kernel", entries["kern.bootfile"])
	// kern.version ends in a newline, so a blank line follows it
	assert.Equal(t, "FreeBSD 14.5-RELEASE releng/14.5-n274872-4099b5c82880 GENERIC", entries["kern.version"])
	assert.Equal(t, "181505", entries["kern.maxvnodes"])

	// continuation lines of kern.msgbuf and vm.phys_segs stay in their values
	assert.True(t, strings.HasPrefix(entries["kern.msgbuf"], "---<<BOOT>>---\nCopyright (c) 1992-2023 The FreeBSD Project.\n"))
	assert.Contains(t, entries["kern.msgbuf"], "\n  Features=0x1f83fbff<FPU,")
	assert.True(t, strings.HasSuffix(entries["kern.msgbuf"], "ena0: Cannot get hash function"))
	assert.True(t, strings.HasPrefix(entries["vm.phys_segs"], "SEGMENT 0:\n\nstart:     0x1000\n"))
	assert.Equal(t, "0: -1", entries["vm.phys_locality"])
	for key := range entries {
		assert.Truef(t, strings.HasPrefix(key, "kern.") || strings.HasPrefix(key, "vm.") ||
			strings.HasPrefix(key, "hw.") || strings.HasPrefix(key, "kstat."), "unexpected key %q", key)
	}

	// OpenZFS kstat names contain a space
	assert.Equal(t, "0", entries["kstat.zfs.zroot.misc.dmu_tx_assign.2199023255552 ns"])
}

// Values may contain the separator; only the first one splits.
func TestSysctlFirstSeparator(t *testing.T) {
	t.Run("macOS", func(t *testing.T) {
		// macOS 27 `sysctl -a`
		out := `kern.ostype: Darwin
kern.version: Darwin Kernel Version 27.0.0: Tue Aug 11 21:05:48 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_T6041
kern.boottime: { sec = 1790030978, usec = 706302 } Mon Sep 21 15:49:38 2026
user.cs_path: /usr/bin:/bin:/usr/sbin:/sbin
`
		entries, err := ParseSysctl(strings.NewReader(out), ":")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			"kern.ostype":   "Darwin",
			"kern.version":  "Darwin Kernel Version 27.0.0: Tue Aug 11 21:05:48 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_T6041",
			"kern.boottime": "{ sec = 1790030978, usec = 706302 } Mon Sep 21 15:49:38 2026",
			"user.cs_path":  "/usr/bin:/bin:/usr/sbin:/sbin",
		}, entries)
	})

	t.Run("Linux", func(t *testing.T) {
		out := "kernel.printk = 4\t4\t1\t7\n" +
			"net.ipv4.conf.eth0/100.forwarding = 1\n" +
			"kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P a=b\n"
		entries, err := ParseSysctl(strings.NewReader(out), "=")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			"kernel.printk":                     "4\t4\t1\t7",
			"net.ipv4.conf.eth0/100.forwarding": "1",
			"kernel.core_pattern":               "|/usr/lib/systemd/systemd-coredump %P a=b",
		}, entries)
	})
}

// Lines ahead of the first parameter belong to no value and are dropped.
func TestSysctlLeadingGarbage(t *testing.T) {
	entries, err := ParseSysctl(strings.NewReader("sysctl: unknown oid\nkern.ostype=FreeBSD\n"), "=")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"kern.ostype": "FreeBSD"}, entries)
}

func TestIsSysctlName(t *testing.T) {
	for _, name := range []string{
		"kern.hostname",
		"security.jail.param.allow.mount.",
		"net.ipv4.conf.eth0/100.forwarding",
		"dev.hn.0.%desc",
		"kstat.zfs.zroot.misc.dmu_tx_assign.1024 ns",
		"net.ipv6.conf.wg-home.forwarding",
	} {
		assert.Truef(t, isSysctlName(name), "%q", name)
	}
	for _, name := range []string{
		"",
		"0xffffffff82635000",
		"<118>\texpat",
		"  Features",
		"Features2",
		"Hypervisor: Origin",
		"0",
	} {
		assert.Falsef(t, isSysctlName(name), "%q", name)
	}
}

func TestBsdSysctlCommand(t *testing.T) {
	cmd, sep := bsdSysctlCommand("freebsd")
	assert.Equal(t, "sysctl -ae", cmd)
	assert.Equal(t, "=", sep)

	// NetBSD prints `name = value`
	cmd, sep = bsdSysctlCommand("netbsd")
	assert.Equal(t, "/sbin/sysctl -a", cmd)
	assert.Equal(t, "=", sep)

	cmd, sep = bsdSysctlCommand("openbsd")
	assert.Equal(t, "sysctl -a", cmd)
	assert.Equal(t, "=", sep)

	cmd, sep = bsdSysctlCommand("dragonflybsd")
	assert.Equal(t, "sysctl -a", cmd)
	assert.Equal(t, ":", sep)
}

func TestManagerFreebsdParameters(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/freebsd145.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mock)
	require.NoError(t, err)
	params, err := mm.Parameters()
	require.NoError(t, err)
	assert.Equal(t, 46, len(params))
	assert.Equal(t, "/boot/kernel/kernel", params["kern.bootfile"])
}
