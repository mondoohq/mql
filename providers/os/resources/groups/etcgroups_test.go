// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"

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

// glibc reads /etc/group with no line limit. A group with thousands of
// members is one line well over 64 KiB, and the groups after it must still be
// reported.
func TestParseEtcGroupKeepsGroupsAfterLongLine(t *testing.T) {
	members := make([]string, 7000)
	for i := range members {
		members[i] = fmt.Sprintf("mqlhuge%05d", i)
	}
	group := "root:x:0:\n" +
		"mqlg_huge:x:5000:" + strings.Join(members, ",") + "\n" +
		"mqlg_after:x:5001:alice\n"
	require.Greater(t, len(group), 64*1024)

	m, err := ParseEtcGroup(strings.NewReader(group))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, "mqlg_huge", m[1].Name)
	assert.Len(t, m[1].Members, 7000)
	assert.Equal(t, "mqlg_after", m[2].Name)
	assert.Equal(t, int64(5001), m[2].Gid)
}

// glibc ignores a group line whose gid is not a number (getent group <name>
// finds nothing). Reporting it with gid 0 invents a second root group.
func TestParseEtcGroupSkipsNonNumericGid(t *testing.T) {
	group := "root:x:0:\nmqlg_badgid:x:abc:alice\nwheel:x:10:alice\n"

	m, err := ParseEtcGroup(strings.NewReader(group))
	require.NoError(t, err)
	require.Len(t, m, 2)
	assert.Equal(t, "root", m[0].Name)
	assert.Equal(t, "wheel", m[1].Name)
}

// A read error must fail the parse rather than return a partial list.
func TestParseEtcGroupReturnsReadError(t *testing.T) {
	r := io.MultiReader(strings.NewReader("root:x:0:\n"), iotest.ErrReader(errors.New("read failed")))
	_, err := ParseEtcGroup(r)
	require.Error(t, err)
}
