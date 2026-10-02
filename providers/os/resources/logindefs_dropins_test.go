// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestReadsLoginDefsDropIns(t *testing.T) {
	suse := &inventory.Platform{Name: "sles", Family: []string{"suse", "linux", "unix", "os"}}
	leap := &inventory.Platform{Name: "opensuse-leap", Family: []string{"suse", "linux", "unix", "os"}}
	ubuntu := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	rhel := &inventory.Platform{Name: "redhat", Family: []string{"redhat", "linux", "unix", "os"}}

	assert.True(t, readsLoginDefsDropIns(suse, "/etc/login.defs"))
	assert.True(t, readsLoginDefsDropIns(leap, "/usr/etc/login.defs"), "Leap 16 ships login.defs in /usr/etc")
	assert.False(t, readsLoginDefsDropIns(ubuntu, "/etc/login.defs"), "Debian's useradd reads login.defs alone")
	assert.False(t, readsLoginDefsDropIns(rhel, "/etc/login.defs"))
	assert.False(t, readsLoginDefsDropIns(suse, "/srv/chroot/etc/login.defs"), "a file passed by path is read alone")
	assert.False(t, readsLoginDefsDropIns(nil, "/etc/login.defs"))
}
