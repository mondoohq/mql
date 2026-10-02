// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func inetdTestConn(t *testing.T, family []string, withInetutils bool) shared.Connection {
	t.Helper()
	files := map[string]*mock.MockFileData{
		"/etc/inetd.conf":  {Path: "/etc/inetd.conf", Content: "#discard stream tcp nowait root internal\n"},
		"/etc/inetd.d/g04": {Path: "/etc/inetd.d/g04", Content: "tftp dgram udp6 wait nobody /usr/sbin/in.tftpd in.tftpd -s /srv/tftp\n"},
	}
	if withInetutils {
		files[debianInetutilsInetd] = &mock.MockFileData{Path: debianInetutilsInetd, Content: "ELF"}
	}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: family[0], Family: family},
	}, mock.WithData(&mock.TomlData{Files: files}))
	require.NoError(t, err)
	return conn
}

// openbsd-inetd, Debian's and Ubuntu's default inetd, reads only
// /etc/inetd.conf: a tftp line in /etc/inetd.d/g04 is not a service it runs.
// GNU inetutils' inetd reads the directory too.
func TestInetdReadsDropIns(t *testing.T) {
	debian := []string{"debian", "linux", "unix", "os"}
	assert.False(t, inetdReadsDropIns(inetdTestConn(t, debian, false)), "debian with openbsd-inetd")
	assert.True(t, inetdReadsDropIns(inetdTestConn(t, debian, true)), "debian with inetutils-inetd")
	// other platforms keep reading the directory
	assert.True(t, inetdReadsDropIns(inetdTestConn(t, []string{"arch", "linux", "unix", "os"}, false)))
}
