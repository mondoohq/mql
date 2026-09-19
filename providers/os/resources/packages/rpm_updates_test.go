// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestRpmUpdateParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/updates_rpm.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("python")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := ParseRpmUpdates(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(m), "detected the right amount of package updates")

	update := m["python-libs"]
	assert.Equal(t, "python-libs", update.Name, "pkg name detected")
	assert.Equal(t, "", update.Version, "pkg version detected")
	assert.Equal(t, "0:2.7.5-69.el7_5", update.Available, "pkg available version detected")

	update = m["binutils"]
	assert.Equal(t, "binutils", update.Name, "pkg name detected")
	assert.Equal(t, "", update.Version, "pkg version detected")
	assert.Equal(t, "0:2.27-28.base.el7_5.1", update.Available, "pkg available version detected")
}

func TestZypperUpdateParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/updates_zypper.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("zypper -n --xmlout list-updates")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := ParseZypperUpdates(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 22, len(m), "detected the right amount of package updates")

	update := m["aaa_base"]
	assert.Equal(t, "aaa_base", update.Name, "pkg name detected")
	assert.Equal(t, "13.2+git20140911.61c1681-28.3.1", update.Version, "pkg version detected")

	update = m["bash"]
	assert.Equal(t, "bash", update.Name, "pkg name detected")
	assert.Equal(t, "4.3-83.3.1", update.Version, "pkg version detected")
}

// TestParseRpmCheckUpdate reads `dnf check-update` captured from live EC2
// hosts on 2026-09-18. Before this parser existed the rpm reader ran a Python
// 2 / yum-cli snippet that no longer runs on either host, so both reported no
// updates at all.
func TestParseRpmCheckUpdate(t *testing.T) {
	t.Run("rhel9, including the Obsoleting Packages section", func(t *testing.T) {
		f, err := os.Open("./testdata/dnf-rhel9.txt")
		require.NoError(t, err)
		defer f.Close()

		m, err := ParseRpmCheckUpdate(f)
		require.NoError(t, err)
		require.NotEmpty(t, m)

		// epoch stays on the available version, as it is printed
		nm, ok := m["NetworkManager"]
		require.True(t, ok)
		assert.Equal(t, "1:1.54.3-5.el9_8", nm.Available)
		assert.Equal(t, "x86_64", nm.Arch)
		assert.Equal(t, "rhel-9-baseos-rhui-rpms", nm.Repo)

		acl, ok := m["acl"]
		require.True(t, ok)
		assert.Equal(t, "2.4.0-1.el9_8", acl.Available)

		// grub2-tools appears ONLY as the indented @System side of an
		// obsoletes pair, carrying the older installed version. Reading it
		// would advertise a downgrade as an available update.
		if g, ok := m["grub2-tools"]; ok {
			assert.NotEqual(t, "1:2.06-105.el9_6.2", g.Available,
				"picked up the obsoleted @System line")
			assert.NotEqual(t, "@System", g.Repo)
		}
		for name, u := range m {
			assert.NotEqual(t, "@System", u.Repo, "package %s", name)
			assert.NotEmpty(t, u.Arch, "package %s has no arch", name)
		}
	})

	t.Run("alma9", func(t *testing.T) {
		f, err := os.Open("./testdata/dnf-alma9.txt")
		require.NoError(t, err)
		defer f.Close()
		m, err := ParseRpmCheckUpdate(f)
		require.NoError(t, err)

		k, ok := m["kernel"]
		require.True(t, ok)
		assert.Equal(t, "5.14.0-687.48.1.el9_8", k.Available)
		assert.Equal(t, "x86_64", k.Arch)
		assert.Equal(t, "baseos", k.Repo)
	})

	t.Run("no updates yields an empty map, not an error", func(t *testing.T) {
		m, err := ParseRpmCheckUpdate(strings.NewReader(""))
		require.NoError(t, err)
		assert.Empty(t, m)
	})

	t.Run("headers and indented lines are ignored", func(t *testing.T) {
		m, err := ParseRpmCheckUpdate(strings.NewReader(
			"Last metadata expiration check: 0:00:01 ago.\n\n" +
				"Obsoleting Packages\n" +
				"    grub2-tools.x86_64   1:2.06-105.el9_6.2   @System\n"))
		require.NoError(t, err)
		assert.Empty(t, m)
	})
}
