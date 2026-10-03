// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/users"
)

func TestParseEtcPasswdSkipsMalformedUidGid(t *testing.T) {
	// A line with a non-numeric uid/gid must be skipped, not surfaced as a
	// phantom uid 0 (root) account.
	const passwd = `root:x:0:0:root:/root:/bin/bash
broken:x:notanumber:1:broken uid:/home/broken:/bin/sh
brokengid:x:1001:notanumber:broken gid:/home/brokengid:/bin/sh
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`

	m, err := users.ParseEtcPasswd(strings.NewReader(passwd))
	require.NoError(t, err)
	require.Equal(t, 2, len(m), "malformed uid/gid lines should be skipped")

	assert.Equal(t, "root", m[0].Name)
	assert.Equal(t, int64(0), m[0].Uid)
	assert.Equal(t, "alice", m[1].Name)
	assert.Equal(t, int64(1000), m[1].Uid)
	assert.Equal(t, int64(1000), m[1].Gid)
}

func TestParseLinuxEtcPasswd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/debian.toml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := mock.FileSystem().Open("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)
	defer f.Close()

	m, err := users.ParseEtcPasswd(f)
	assert.Nil(t, err)
	assert.Equal(t, 13, len(m), "detected the right amount of services")

	assert.Equal(t, "root", m[0].Name, "detected user name")
	assert.Equal(t, int64(0), m[0].Uid, "detected uid")
	assert.Equal(t, int64(0), m[0].Gid, "detected gid")
	assert.Equal(t, "root", m[0].Description, "user description")
	assert.Equal(t, "/root", m[0].Home, "detected user home")
	assert.Equal(t, "/bin/bash", m[0].Shell, "detected user shell")
}

func TestParseFreebsdLinuxEtcPasswd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd12.toml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := mock.FileSystem().Open("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)
	defer f.Close()

	m, err := users.ParseEtcPasswd(f)
	assert.Nil(t, err)
	assert.Equal(t, 28, len(m), "detected the right amount of services")

	assert.Equal(t, "root", m[0].Name, "detected user name")
	assert.Equal(t, int64(0), m[0].Uid, "detected uid")
	assert.Equal(t, int64(0), m[0].Gid, "detected gid")
	assert.Equal(t, "Charlie &", m[0].Description, "user description")
	assert.Equal(t, "/root", m[0].Home, "detected user home")
	assert.Equal(t, "/bin/csh", m[0].Shell, "detected user shell")
}

func TestParseLinuxGetentPasswd(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"os", "unix", "linux", "redhat"},
		},
	}, mock.WithPath("./testdata/oraclelinux_getent_passwd.toml"))
	require.NoError(t, err)
	m, err := users.ResolveManager(conn)
	require.Nil(t, err)

	list, err := m.List()
	require.Nil(t, err)
	assert.Equal(t, 20, len(list), "detected the right amount of users")

	assert.Equal(t, "root", list[0].Name, "detected user name")
	assert.Equal(t, int64(0), list[0].Uid, "detected uid")
	assert.Equal(t, int64(0), list[0].Gid, "detected gid")
	assert.Equal(t, "root", list[0].Description, "user description")
	assert.Equal(t, "/root", list[0].Home, "detected user home")
	assert.Equal(t, "/bin/bash", list[0].Shell, "detected user shell")
}

// glibc reads /etc/passwd with no line limit, so a user after a very long
// line (a 70 KB GECOS field) still exists. Stopping at the long line hides
// every later account, including a second uid 0.
func TestParseEtcPasswdKeepsUsersAfterLongLine(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"longgecos:x:1001:1001:" + strings.Repeat("g", 70*1024) + ":/home/longgecos:/bin/bash\n" +
		"toor:x:0:0:hidden root:/root:/bin/sh\n"

	m, err := users.ParseEtcPasswd(strings.NewReader(passwd))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, "longgecos", m[1].Name)
	assert.Len(t, m[1].Description, 70*1024)
	assert.Equal(t, "toor", m[2].Name)
	assert.Equal(t, int64(0), m[2].Uid)
}

// A read error must fail the parse rather than return the users read so far
// as if they were the whole file.
func TestParseEtcPasswdReturnsReadError(t *testing.T) {
	r := io.MultiReader(strings.NewReader("root:x:0:0:root:/root:/bin/bash\n"), iotest.ErrReader(errors.New("read failed")))
	_, err := users.ParseEtcPasswd(r)
	require.Error(t, err)
}
