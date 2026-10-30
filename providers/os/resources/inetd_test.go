// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
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

// /etc/xinetd.conf and /etc/xinetd.d as openSUSE Leap 15.6 ships them, with
// echo and daytime enabled and a stray echo.rpmnew that enables chargen.
// xinetd runs echo and daytime only.
func TestInetdConfigXinetd(t *testing.T) {
	data := &mock.TomlData{Files: map[string]*mock.MockFileData{
		"/etc/xinetd.d": {Path: "/etc/xinetd.d", StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
	}}
	add := func(path, src string) {
		content, err := os.ReadFile(src)
		require.NoError(t, err)
		data.Files[path] = &mock.MockFileData{Path: path, Content: string(content), StatData: mock.FileInfo{Mode: 0o644}}
	}
	add("/etc/xinetd.conf", "inetd/testdata/leap-15.6-xinetd/xinetd.conf")
	srcs, err := filepath.Glob("inetd/testdata/leap-15.6-xinetd/xinetd.d/*")
	require.NoError(t, err)
	for _, src := range srcs {
		add("/etc/xinetd.d/"+filepath.Base(src), src)
	}
	data.Files["/etc/xinetd.d/chargen.rpmnew"] = &mock.MockFileData{
		Path:     "/etc/xinetd.d/chargen.rpmnew",
		Content:  "service chargen\n{\n\ttype = INTERNAL\n\tsocket_type = stream\n\tprotocol = tcp\n\twait = no\n\tdisable = no\n}\n",
		StatData: mock.FileInfo{Mode: 0o644},
	}

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "opensuse-leap", Family: []string{"suse", "linux", "unix", "os"}},
	}, mock.WithData(data))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	res, err := NewResource(rt, "inetd.config", map[string]*llx.RawData{"path": llx.StringData("/etc/xinetd.conf")})
	require.NoError(t, err)
	cfg := res.(*mqlInetdConfig)

	files := cfg.GetFiles()
	require.NoError(t, files.Error)
	paths := []string{}
	for _, f := range files.Data {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	assert.Len(t, paths, 13)
	assert.NotContains(t, paths, "/etc/xinetd.d/chargen.rpmnew")

	names := cfg.GetServiceNames()
	require.NoError(t, names.Error)
	assert.ElementsMatch(t, []any{"daytime", "echo"}, names.Data)
}
