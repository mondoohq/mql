// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseLinuxEtcGroups(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/debian.toml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := mock.FileSystem().Open("/etc/group")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)
	defer f.Close()

	m, err := ParseEtcGroup(f)
	assert.Nil(t, err)
	assert.Equal(t, 23, len(m), "detected the right amount of services")

	assert.Equal(t, "root", m[0].Name, "detected user name")
	assert.Equal(t, "0", m[0].ID, "detected id")
	assert.Equal(t, int64(0), m[0].Gid, "detected gid")
	assert.Equal(t, "", m[22].Sid, "detected sid")
	assert.Equal(t, []string{}, m[0].Members, "user description")

	assert.Equal(t, "vagrant", m[22].Name, "detected user name")
	assert.Equal(t, "1000", m[22].ID, "detected id")
	assert.Equal(t, int64(1000), m[22].Gid, "detected gid")
	assert.Equal(t, "", m[22].Sid, "detected sid")
	assert.Equal(t, []string{"vagrant"}, m[22].Members, "user description")
}

func TestParseFreebsd12EtcGroups(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd12.toml"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := mock.FileSystem().Open("/etc/group")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)
	defer f.Close()

	m, err := ParseEtcGroup(f)
	assert.Nil(t, err)
	assert.Equal(t, 36, len(m), "detected the right amount of services")

	assert.Equal(t, "wheel", m[0].Name, "detected user name")
	assert.Equal(t, "0", m[0].ID, "detected id")
	assert.Equal(t, int64(0), m[0].Gid, "detected gid")
	assert.Equal(t, "", m[0].Sid, "detected sid")
	assert.Equal(t, []string{"root", "vagrant"}, m[0].Members, "user description")

	assert.Equal(t, "vagrant", m[35].Name, "detected user name")
	assert.Equal(t, "1001", m[35].ID, "detected id")
	assert.Equal(t, int64(1001), m[35].Gid, "detected gid")
	assert.Equal(t, "", m[35].Sid, "detected sid")
	assert.Equal(t, []string{}, m[35].Members, "user description")
}

func TestUnixGroupManager(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)
	gm := &UnixGroupManager{
		conn: mock,
	}

	groups, err := gm.List()
	require.NoError(t, err)

	var vagrantGroup *Group
	for _, g := range groups {
		if g.Name == "vagrant" {
			vagrantGroup = g
			break
		}
	}

	require.NotNil(t, vagrantGroup)
	assert.Equal(t, "vagrant", vagrantGroup.Name)
	assert.Equal(t, int64(1000), vagrantGroup.Gid)
	assert.Equal(t, "1000", vagrantGroup.ID)
	assert.Equal(t, []string{"vagrant"}, vagrantGroup.Members)
}

// getent group emits the same colon separated format as /etc/group, which is
// why the existing parser handles it unchanged. This pins that, because the
// NSS fallback depends on it.
func TestParseEtcGroupHandlesGetentOutput(t *testing.T) {
	// verbatim shape of `getent group` on a host whose groups come from an NSS
	// module rather than /etc/group
	out := `root:x:0:
daemon:x:1:
sudo:x:27:core
docker:x:233:core
nobody:x:65534:
portage:x:250:core
`
	groups, err := ParseEtcGroup(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, groups, 6)

	byName := map[string]*Group{}
	for _, g := range groups {
		byName[g.Name] = g
	}

	// the entries that only NSS knows about must parse identically
	assert.Contains(t, byName, "nobody", "an NSS-only group must parse")
	assert.Equal(t, int64(65534), byName["nobody"].Gid)

	require.Contains(t, byName, "portage")
	assert.Equal(t, int64(250), byName["portage"].Gid)
	assert.Equal(t, []string{"core"}, byName["portage"].Members)

	assert.Equal(t, int64(0), byName["root"].Gid)
	assert.Empty(t, byName["root"].Members)
}

// A group line with no members must not invent one.
func TestParseEtcGroupEmptyMembers(t *testing.T) {
	groups, err := ParseEtcGroup(strings.NewReader("wheel:x:10:\n"))
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Empty(t, groups[0].Members)
}
