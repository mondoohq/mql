// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/kernel"
)

func TestIsConfDFileName(t *testing.T) {
	assert.True(t, isConfDFileName("blacklist.conf"))
	assert.True(t, isConfDFileName("zz-linked.conf"))
	assert.False(t, isConfDFileName("ignored.txt"))
	assert.False(t, isConfDFileName(".hidden.conf"))
	assert.False(t, isConfDFileName("blacklist.conf.dpkg-old"))
	assert.False(t, isConfDFileName("legacy.alias"))
	assert.False(t, isConfDFileName("README.sysctl"))
}

// sysctl.d on Ubuntu 24.04 plus test files. `sysctl --system` (procps-ng
// 4.0.4) applied them in exactly this order: the /etc copy of 50-shadow.conf
// hides the /usr/lib one, and /lib/sysctl.d (merged into /usr/lib) adds
// nothing.
func TestSelectConfDFiles_Sysctl(t *testing.T) {
	listings := [][]string{
		// /etc/sysctl.d
		{"10-bufferbloat.conf", "10-kernel-hardening.conf", "50-shadow.conf", "README.sysctl", "zz-after.conf"},
		// /run/sysctl.d
		nil,
		// /usr/local/lib/sysctl.d
		nil,
		// /usr/lib/sysctl.d
		{"10-a.conf", "50-shadow.conf", "99-protect-links.conf"},
		// /lib/sysctl.d
		{"10-a.conf", "50-shadow.conf", "99-protect-links.conf"},
	}

	assert.Equal(t, []string{
		"/usr/lib/sysctl.d/10-a.conf",
		"/etc/sysctl.d/10-bufferbloat.conf",
		"/etc/sysctl.d/10-kernel-hardening.conf",
		"/etc/sysctl.d/50-shadow.conf",
		"/usr/lib/sysctl.d/99-protect-links.conf",
		"/etc/sysctl.d/zz-after.conf",
	}, selectConfDFiles(kernel.SysctlDirs, listings))
}
