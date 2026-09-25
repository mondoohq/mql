// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/logindefs"
)

func TestParseUIDRange(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    uidRange
	}{
		{name: "debian stock", content: "UID_MIN\t\t\t 1000\nUID_MAX\t\t\t60000\n#SYS_UID_MIN\t\t  101\n", want: uidRange{1000, 60000}},
		{name: "custom values", content: "UID_MIN 5000\nUID_MAX 2000000\n", want: uidRange{5000, 2000000}},
		{name: "hex like strtoul base 0", content: "UID_MIN 0x1F4\n", want: uidRange{500, 60000}},
		{name: "octal like strtoul base 0", content: "UID_MIN 0764\n", want: uidRange{500, 60000}},
		{name: "trailing comment", content: "UID_MIN 2000 # site policy\n", want: uidRange{2000, 60000}},
		{name: "absent", content: "PASS_MAX_DAYS 90\n", want: uidRange{1000, 60000}},
		{name: "commented out", content: "# UID_MIN 500\n#UID_MAX 500\n", want: uidRange{1000, 60000}},
		{name: "garbage", content: "UID_MIN lots\nUID_MAX many\n", want: uidRange{1000, 60000}},
		{name: "negative", content: "UID_MIN -5\n", want: uidRange{1000, 60000}},
		{name: "empty file", content: "", want: uidRange{1000, 60000}},
		{name: "SYS_UID_MAX does not stand in for UID_MIN", content: "SYS_UID_MAX 499\n", want: uidRange{1000, 60000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUIDRange(logindefs.Parse(strings.NewReader(tc.content)))
			assert.Equal(t, tc.want, got)
		})
	}
	assert.Equal(t, uidRange{1000, 60000}, parseUIDRange(nil), "no login.defs")
}

func TestIsLinuxSystemUID(t *testing.T) {
	std := uidRange{min: 1000, max: 60000}
	system := map[int64]string{
		0:     "root",
		1:     "daemon",
		999:   "last below UID_MIN",
		64055: "Debian static allocation (libvirt-qemu)",
		64757: "Debian static allocation (wsdd)",
		61184: "systemd DynamicUser",
		65534: "nobody",
		60514: "above the homed range",
	}
	for uid, why := range system {
		assert.True(t, isLinuxSystemUID(uid, std), "%d %s", uid, why)
	}
	regular := map[int64]string{
		1000:    "UID_MIN itself",
		1001:    "",
		60000:   "UID_MAX itself",
		60001:   "systemd-homed first",
		60513:   "systemd-homed last",
		65536:   "container range",
		1000000: "directory-service range",
	}
	for uid, why := range regular {
		assert.False(t, isLinuxSystemUID(uid, std), "%d %s", uid, why)
	}

	assert.True(t, isLinuxSystemUID(4999, uidRange{5000, 60000}), "a raised UID_MIN widens the low range")
	assert.False(t, isLinuxSystemUID(600, uidRange{500, 60000}), "a lowered UID_MIN narrows it")
	assert.False(t, isLinuxSystemUID(64055, uidRange{1000, 65000}), "a raised UID_MAX makes 64055 a regular uid")
	assert.True(t, isLinuxSystemUID(65534, uidRange{1000, 65000}), "nobody stays above a raised UID_MAX")
}

func TestIsDarwinSystemUID(t *testing.T) {
	assert.True(t, isDarwinSystemUID(0), "root")
	assert.True(t, isDarwinSystemUID(-2), "nobody")
	assert.True(t, isDarwinSystemUID(499))
	assert.False(t, isDarwinSystemUID(500))
	assert.False(t, isDarwinSystemUID(501), "first user")
}

func TestIsLoginShell(t *testing.T) {
	notLogin := []string{
		"/sbin/nologin",
		"/usr/sbin/nologin",
		"/usr/bin/nologin",
		"/bin/false",
		"/usr/bin/false",
		"/bin/true",
		"/usr/bin/true",
		"//usr/sbin//nologin",
	}
	for _, s := range notLogin {
		assert.False(t, isLoginShell(s), s)
	}

	login := []string{
		"",
		"/bin/sh",
		"/bin/bash",
		"/usr/bin/zsh",
		"/bin/ash",
		"/bin/sync",
		"/sbin/shutdown",
		"/usr/bin/passwd",
		"/home/alice/nologin",
		"/tmp/false",
		"nologin",
		"/usr/local/bin/nologin",
		"/usr/sbin/nologin-wrapper",
	}
	for _, s := range login {
		assert.True(t, isLoginShell(s), s)
	}
}

func TestSystemAccountRuleFor(t *testing.T) {
	assert.Equal(t, systemAccountRuleLinux, systemAccountRuleFor(&inventory.Platform{Family: []string{"debian", "linux", "unix", "os"}}))
	assert.Equal(t, systemAccountRuleDarwin, systemAccountRuleFor(&inventory.Platform{Family: []string{"darwin", "bsd", "unix", "os"}}))
	assert.Equal(t, systemAccountRuleUnknown, systemAccountRuleFor(&inventory.Platform{Family: []string{"windows", "os"}}))
	assert.Equal(t, systemAccountRuleUnknown, systemAccountRuleFor(&inventory.Platform{Family: []string{"bsd", "unix", "os"}}), "freebsd")
	assert.Equal(t, systemAccountRuleUnknown, systemAccountRuleFor(&inventory.Platform{Family: []string{"unix", "os"}}), "solaris")
	assert.Equal(t, systemAccountRuleUnknown, systemAccountRuleFor(nil))
}

func TestLoginShellApplies(t *testing.T) {
	assert.True(t, loginShellApplies(&inventory.Platform{Family: []string{"redhat", "linux", "unix", "os"}}))
	assert.True(t, loginShellApplies(&inventory.Platform{Family: []string{"darwin", "bsd", "unix", "os"}}))
	assert.False(t, loginShellApplies(&inventory.Platform{Family: []string{"windows", "os"}}))
	assert.False(t, loginShellApplies(nil))
}
