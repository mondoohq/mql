// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func newPfTestResource(t *testing.T, platform string, files map[string]string, commands map[string]*mock.Command) *mqlPf {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{}
	for path, content := range files {
		mockFiles[path] = &mock.MockFileData{Path: path, Content: content}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{Name: platform}},
		mock.WithData(&mock.TomlData{Files: mockFiles, Commands: commands}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err := NewResource(rt, "pf", nil)
	require.NoError(t, err)
	return res.(*mqlPf)
}

func readPfFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("pfctl/testdata/" + name)
	require.NoError(t, err)
	return string(data)
}

func TestPfEnabledAndRules(t *testing.T) {
	pf := newPfTestResource(t, "freebsd",
		map[string]string{
			"/sbin/pfctl":   "",
			"/etc/services": "ssh              22/tcp     # SSH Remote Login Protocol\n",
		},
		map[string]*mock.Command{
			"/sbin/pfctl -s info":  {Stdout: readPfFixture(t, "freebsd14_info_enabled.txt")},
			"/sbin/pfctl -s rules": {Stdout: readPfFixture(t, "freebsd14_rules.txt")},
		})

	enabled := pf.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.True(t, enabled.Data)

	rules := pf.GetRules()
	require.NoError(t, rules.Error)
	require.Len(t, rules.Data, 17)
	ssh := rules.Data[3].(*mqlPfRule)
	assert.Equal(t, "22", ssh.ToPort.Data)
	assert.True(t, ssh.Quick.Data)
	// the two web alt rules differ only in protocol and must not collapse
	assert.NotEqual(t, rules.Data[14].(*mqlPfRule).MqlID(), rules.Data[15].(*mqlPfRule).MqlID())
	assert.Equal(t, "udp", rules.Data[15].(*mqlPfRule).Protocol.Data)
}

func TestPfRefused(t *testing.T) {
	// a regular user on FreeBSD 14.5, Solaris 11.4, and macOS
	pf := newPfTestResource(t, "macos",
		map[string]string{"/sbin/pfctl": ""},
		map[string]*mock.Command{
			"/sbin/pfctl -s info":  {Stderr: "pfctl: /dev/pf: Permission denied\n", ExitStatus: 1},
			"/sbin/pfctl -s rules": {Stderr: "pfctl: /dev/pf: Permission denied\n", ExitStatus: 1},
		})

	enabled := pf.GetEnabled()
	require.Error(t, enabled.Error)
	assert.True(t, errors.Is(enabled.Error, llx.ErrForbidden))

	rules := pf.GetRules()
	require.Error(t, rules.Error)
	assert.True(t, errors.Is(rules.Error, llx.ErrForbidden))
}

func TestPfNotLoaded(t *testing.T) {
	// FreeBSD 14.5 before pf.ko is loaded
	pf := newPfTestResource(t, "freebsd",
		map[string]string{"/sbin/pfctl": ""},
		map[string]*mock.Command{
			"/sbin/pfctl -s info":  {Stderr: "pfctl: /dev/pf: No such file or directory\n", ExitStatus: 1},
			"/sbin/pfctl -s rules": {Stderr: "pfctl: /dev/pf: No such file or directory\n", ExitStatus: 1},
		})

	enabled := pf.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.False(t, enabled.Data)

	rules := pf.GetRules()
	require.NoError(t, rules.Error)
	assert.Empty(t, rules.Data)
}

func TestPfNotInstalled(t *testing.T) {
	pf := newPfTestResource(t, "ubuntu", map[string]string{}, nil)

	enabled := pf.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.False(t, enabled.Data)

	tables := pf.GetTables()
	require.NoError(t, tables.Error)
	assert.Empty(t, tables.Data)
}

func TestPfOtherFailureIsAnError(t *testing.T) {
	pf := newPfTestResource(t, "freebsd",
		map[string]string{"/sbin/pfctl": ""},
		map[string]*mock.Command{
			"/sbin/pfctl -s info": {Stderr: "pfctl: an unclassified failure\n", ExitStatus: 1},
		})
	enabled := pf.GetEnabled()
	require.Error(t, enabled.Error)
	assert.False(t, errors.Is(enabled.Error, llx.ErrForbidden))
}

func TestPfTables(t *testing.T) {
	pf := newPfTestResource(t, "freebsd",
		map[string]string{"/sbin/pfctl": ""},
		map[string]*mock.Command{
			"/sbin/pfctl -s Tables":             {Stdout: readPfFixture(t, "freebsd14_tables.txt")},
			"/sbin/pfctl -t bruteforce -T show": {Stdout: readPfFixture(t, "freebsd14_table_show.txt")},
		})
	tables := pf.GetTables()
	require.NoError(t, tables.Error)
	require.Len(t, tables.Data, 2)
	bf := tables.Data[0].(*mqlPfTable)
	assert.Equal(t, "bruteforce", bf.Name.Data)
	addrs := bf.GetAddresses()
	require.NoError(t, addrs.Error)
	assert.Equal(t, []any{"192.0.2.10", "198.51.100.0/24"}, addrs.Data)
}

func TestPfConfigPath(t *testing.T) {
	// the Solaris 11.4 image on OCI points the firewall service at
	// pf_ssh_only.conf instead of the default pf.conf
	pf := newPfTestResource(t, "solaris", map[string]string{"/usr/sbin/pfctl": ""},
		map[string]*mock.Command{
			"/usr/bin/svcprop -p firewall/rules svc:/network/firewall:default": {Stdout: "/etc/firewall/pf_ssh_only.conf\n"},
		})
	path, err := pf.configPath()
	require.NoError(t, err)
	assert.Equal(t, "/etc/firewall/pf_ssh_only.conf", path)

	pf = newPfTestResource(t, "solaris", map[string]string{}, map[string]*mock.Command{
		"/usr/bin/svcprop -p firewall/rules svc:/network/firewall:default": {Stderr: "svcprop: Couldn't find property", ExitStatus: 1},
	})
	path, err = pf.configPath()
	require.NoError(t, err)
	assert.Equal(t, "/etc/firewall/pf.conf", path)

	pf = newPfTestResource(t, "freebsd", map[string]string{}, map[string]*mock.Command{
		"/usr/sbin/sysrc -n pf_rules": {Stdout: "/usr/local/etc/pf.conf\n"},
	})
	path, err = pf.configPath()
	require.NoError(t, err)
	assert.Equal(t, "/usr/local/etc/pf.conf", path)

	pf = newPfTestResource(t, "macos", map[string]string{}, nil)
	path, err = pf.configPath()
	require.NoError(t, err)
	assert.Equal(t, "/etc/pf.conf", path)
}

func TestSingleAbsolutePath(t *testing.T) {
	assert.Equal(t, "/etc/pf.conf", singleAbsolutePath("/etc/pf.conf\n"))
	assert.Equal(t, "", singleAbsolutePath(""))
	assert.Equal(t, "", singleAbsolutePath("pf.conf"))
	assert.Equal(t, "", singleAbsolutePath("/etc/a.conf\n/etc/b.conf"))
}
