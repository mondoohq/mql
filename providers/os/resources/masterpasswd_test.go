// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// fixtureFile reads one file out of a mock toml fixture.
func fixtureFile(t *testing.T, fixture, path string) string {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(fixture))
	require.NoError(t, err)
	f, err := conn.FileSystem().Open(path)
	require.NoError(t, err)
	defer f.Close()
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(data)
}

// bsdRuntime builds a mock runtime for the given platform with
// master.passwd and login.conf taken from the parser fixtures.
func bsdRuntime(t *testing.T, platform, masterPasswdFixture, loginConfFixture string) *plugin.Runtime {
	t.Helper()
	files := map[string]*mock.MockFileData{}
	if masterPasswdFixture != "" {
		files["/etc/master.passwd"] = &mock.MockFileData{
			Path:    "/etc/master.passwd",
			Content: fixtureFile(t, "./masterpasswd/testdata/"+masterPasswdFixture, "/etc/master.passwd"),
		}
	}
	if loginConfFixture != "" {
		files["/etc/login.conf"] = &mock.MockFileData{
			Path:    "/etc/login.conf",
			Content: fixtureFile(t, "./loginconf/testdata/"+loginConfFixture, "/etc/login.conf"),
		}
	}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: platform, Family: []string{"bsd", "unix"}},
	}, mock.WithData(&mock.TomlData{Files: files}))
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func masterpasswdEntries(t *testing.T, rt *plugin.Runtime) (*mqlMasterpasswd, map[string]*mqlMasterpasswdEntry) {
	t.Helper()
	raw, err := CreateResource(rt, "masterpasswd", map[string]*llx.RawData{})
	require.NoError(t, err)
	mp := raw.(*mqlMasterpasswd)
	list := mp.GetList()
	require.NoError(t, list.Error)
	res := map[string]*mqlMasterpasswdEntry{}
	for _, x := range list.Data {
		e := x.(*mqlMasterpasswdEntry)
		res[e.Name.Data] = e
	}
	return mp, res
}

func entryLoginClass(t *testing.T, e *mqlMasterpasswdEntry) any {
	t.Helper()
	c := e.GetLoginClass()
	require.NoError(t, c.Error)
	if c.Data == nil {
		return nil
	}
	return c.Data.Name.Data
}

func TestMasterpasswdEdgeCases(t *testing.T) {
	rt := bsdRuntime(t, "freebsd", "edgecases.toml", "freebsd14.toml")
	mp, entries := masterpasswdEntries(t, rt)

	assert.Len(t, entries, 4)
	assert.NotContains(t, entries, "mallory")
	invalid := mp.GetInvalidLines()
	require.NoError(t, invalid.Error)
	assert.Equal(t, int64(2), invalid.Data)

	bob := entries["bob"]
	assert.True(t, bob.Locked.Data)
	assert.False(t, bob.HasPassword.Data)
	assert.Equal(t, "staff", bob.Class.Data)

	alice := entries["alice"]
	assert.True(t, alice.HasPassword.Data)
	require.NotNil(t, alice.Change.Data)
	assert.Equal(t, int64(1767225600), alice.Change.Data.Unix())

	carol := entries["carol"]
	assert.False(t, carol.HasPassword.Data)
	assert.True(t, carol.Change.IsNull(), "0 is never, which reads as null")
	assert.True(t, carol.Expire.IsNull())

	// Entries keep distinct ids even when they come from one file.
	assert.NotEqual(t, alice.MqlID(), bob.MqlID())
}

func TestMasterpasswdLoginClassFreeBSD(t *testing.T) {
	rt := bsdRuntime(t, "freebsd", "edgecases.toml", "freebsd14.toml")
	_, entries := masterpasswdEntries(t, rt)

	assert.Equal(t, "root", entryLoginClass(t, entries["root"]), "empty class on uid 0 is root on FreeBSD")
	assert.Equal(t, "default", entryLoginClass(t, entries["alice"]), "empty class is default")
	assert.Equal(t, "staff", entryLoginClass(t, entries["bob"]))
	assert.Equal(t, "default", entryLoginClass(t, entries["carol"]), "an unknown class falls back to default on FreeBSD")

	staff := entries["bob"].GetLoginClass().Data
	eff := staff.GetEffective()
	require.NoError(t, eff.Error)
	assert.Equal(t, "022", eff.Data.(map[string]any)["umask"])
	assert.Equal(t, "sha512", eff.Data.(map[string]any)["passwd_format"])
}

func TestMasterpasswdLoginClassOpenBSD(t *testing.T) {
	rt := bsdRuntime(t, "openbsd", "edgecases.toml", "openbsd7.toml")
	_, entries := masterpasswdEntries(t, rt)

	assert.Equal(t, "default", entryLoginClass(t, entries["root"]), "OpenBSD has no root class rule")
	assert.Equal(t, "staff", entryLoginClass(t, entries["bob"]))
	assert.Nil(t, entryLoginClass(t, entries["carol"]), "OpenBSD refuses an unknown class")
	assert.True(t, entries["carol"].LoginClass.IsNull())
}

func TestMasterpasswdLoginClassNoDefault(t *testing.T) {
	// NetBSD ships login.conf with every class commented out.
	rt := bsdRuntime(t, "netbsd", "netbsd10.toml", "netbsd10.toml")
	_, entries := masterpasswdEntries(t, rt)
	assert.Nil(t, entryLoginClass(t, entries["root"]))
}

func TestMasterpasswdMissingFile(t *testing.T) {
	rt := bsdRuntime(t, "freebsd", "", "")
	raw, err := CreateResource(rt, "masterpasswd", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := raw.(*mqlMasterpasswd).GetList()
	require.Error(t, list.Error)
	assert.True(t, errors.Is(list.Error, llx.ErrNotFound), list.Error.Error())
}

// permissionDeniedFs refuses to open one path, like a 0600 root file read by
// another user.
type permissionDeniedFs struct {
	afero.Fs
	path string
}

func (p *permissionDeniedFs) Open(name string) (afero.File, error) {
	if name == p.path {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return p.Fs.Open(name)
}

func (p *permissionDeniedFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if name == p.path {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return p.Fs.OpenFile(name, flag, perm)
}

func TestMasterpasswdUnreadable(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeMemFSFile(t, mem, "/etc/master.passwd", []byte("root:*:0:0::0:0::/root:/bin/sh\n"))
	rt := memFSRuntime(t, &permissionDeniedFs{Fs: mem, path: "/etc/master.passwd"})

	raw, err := CreateResource(rt, "masterpasswd", map[string]*llx.RawData{})
	require.NoError(t, err)
	mp := raw.(*mqlMasterpasswd)
	list := mp.GetList()
	require.Error(t, list.Error, "an unreadable file must not read as an empty list")
	assert.True(t, errors.Is(list.Error, llx.ErrForbidden), list.Error.Error())
	assert.Contains(t, list.Error.Error(), "--sudo")
	assert.Error(t, mp.GetInvalidLines().Error)
}

func TestMasterpasswdPath(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeMemFSFile(t, mem, "/tmp/mp", []byte("x:*:5:5:staff:0:0::/:/bin/sh\n"))
	rt := memFSRuntime(t, mem)

	args, _, err := initMasterpasswd(rt, map[string]*llx.RawData{"path": llx.StringData("/tmp/mp")})
	require.NoError(t, err)
	raw, err := CreateResource(rt, "masterpasswd", args)
	require.NoError(t, err)
	mp := raw.(*mqlMasterpasswd)
	assert.Equal(t, "/tmp/mp", mp.MqlID())
	list := mp.GetList()
	require.NoError(t, list.Error)
	require.Len(t, list.Data, 1)
	assert.Equal(t, int64(5), list.Data[0].(*mqlMasterpasswdEntry).Uid.Data)
}
