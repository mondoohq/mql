// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestLoginDefsDropInMode(t *testing.T) {
	suse := &inventory.Platform{Name: "sles", Family: []string{"suse", "linux", "unix", "os"}}
	leap := &inventory.Platform{Name: "opensuse-leap", Family: []string{"suse", "linux", "unix", "os"}}
	ubuntu := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	rhel := &inventory.Platform{Name: "redhat", Family: []string{"redhat", "linux", "unix", "os"}}

	assert.Equal(t, loginDefsVendorAndEtcDropIns, loginDefsDropInMode(suse, "/etc/login.defs", false))
	assert.Equal(t, loginDefsVendorAndEtcDropIns, loginDefsDropInMode(leap, "/usr/etc/login.defs", false), "Leap 16 ships login.defs in /usr/etc")
	assert.Equal(t, loginDefsNoDropIns, loginDefsDropInMode(ubuntu, "/etc/login.defs", false), "Debian's useradd reads login.defs alone")
	assert.Equal(t, loginDefsNoDropIns, loginDefsDropInMode(rhel, "/etc/login.defs", false), "RHEL 7 to 9 useradd has no libeconf")
	// RHEL 10, CentOS Stream 10, AlmaLinux 10 and Fedora 44: useradd links
	// libeconf and applies /etc/login.defs.d, but not /usr/etc/login.defs.d
	// even when /usr/etc/login.defs exists
	assert.Equal(t, loginDefsEtcDropIns, loginDefsDropInMode(rhel, "/etc/login.defs", true))
	assert.Equal(t, loginDefsVendorAndEtcDropIns, loginDefsDropInMode(suse, "/etc/login.defs", true))
	assert.Equal(t, loginDefsNoDropIns, loginDefsDropInMode(suse, "/srv/chroot/etc/login.defs", false), "a file passed by path is read alone")
	assert.Equal(t, loginDefsNoDropIns, loginDefsDropInMode(rhel, "/srv/chroot/etc/login.defs", true), "a file passed by path is read alone")
	assert.Equal(t, loginDefsNoDropIns, loginDefsDropInMode(nil, "/etc/login.defs", false))
}
