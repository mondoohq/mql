// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readRegistriesFixture(t *testing.T, name string) registriesConf {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "containers-registries", name))
	require.NoError(t, err)
	c, err := parseRegistriesConf(string(b))
	require.NoError(t, err)
	return c
}

// Fedora's containers-common 0.69.2 ships its settings as vendor drop-ins
// under /usr/share/containers/registries.conf.d, with a registries.conf that
// holds only comments.
func TestRegistriesConfFedora(t *testing.T) {
	conf := registriesConf{}
	for _, name := range []string{"fedora/registries.conf", "fedora/00-vendor.conf", "fedora/000-shortnames.conf"} {
		mergeRegistriesConf(&conf, readRegistriesFixture(t, name))
	}
	require.NotNil(t, conf.UnqualifiedSearchRegistries)
	assert.Equal(t, []string{"registry.fedoraproject.org", "registry.access.redhat.com", "docker.io"}, *conf.UnqualifiedSearchRegistries)
	assert.Equal(t, "enforcing", conf.ShortNameMode)
	assert.Equal(t, "registry.fedoraproject.org/fedora", conf.Aliases["fedora"])
	assert.Greater(t, len(conf.Aliases), 100)
	assert.Empty(t, conf.Registries)
}

// A later file replaces the settings it sets, replaces the registry with the
// same prefix, adds new ones, and removes an alias set to "".
func TestMergeRegistriesConf(t *testing.T) {
	conf := registriesConf{}
	mergeRegistriesConf(&conf, readRegistriesFixture(t, "fedora/00-vendor.conf"))
	mergeRegistriesConf(&conf, readRegistriesFixture(t, "fedora/000-shortnames.conf"))
	mergeRegistriesConf(&conf, readRegistriesFixture(t, "mirrors.conf"))

	assert.Equal(t, "disabled", conf.ShortNameMode)
	require.NotNil(t, conf.UnqualifiedSearchRegistries, "a file that does not set it keeps the earlier list")
	assert.Len(t, *conf.UnqualifiedSearchRegistries, 3)
	_, ok := conf.Aliases["fedora"]
	assert.False(t, ok, "an empty alias removes it")
	assert.Equal(t, "quay.io/example/busybox", conf.Aliases["busybox"])

	require.Len(t, conf.Registries, 3)
	// by prefix
	assert.Equal(t, "*.untrusted.example", conf.Registries[0].Prefix)
	assert.True(t, conf.Registries[0].Blocked)
	assert.Equal(t, "", conf.Registries[0].Location)

	docker := conf.Registries[1]
	assert.Equal(t, "docker.io", docker.Prefix)
	require.Len(t, docker.Mirrors, 2)
	assert.Equal(t, "mirror.example.com/dockerhub/", docker.Mirrors[0].Location)
	assert.Equal(t, "digest-only", docker.Mirrors[0].PullFromMirror)
	assert.True(t, docker.Mirrors[1].Insecure)

	local := conf.Registries[2]
	assert.Equal(t, "registry.example.local:5000", local.Prefix, "the prefix defaults to the location")
	assert.True(t, local.Insecure)

	// a later drop-in replaces the docker.io entry as a whole
	mergeRegistriesConf(&conf, registriesConf{Registries: []registryConf{{Prefix: "docker.io", Location: "docker.io", Blocked: true}}})
	require.Len(t, conf.Registries, 3)
	assert.True(t, conf.Registries[1].Blocked)
	assert.Empty(t, conf.Registries[1].Mirrors)

	// an empty list set later clears the search registries
	empty := []string{}
	mergeRegistriesConf(&conf, registriesConf{UnqualifiedSearchRegistries: &empty})
	assert.Empty(t, *conf.UnqualifiedSearchRegistries)
}

// The version 1 format, as in containers-registries.conf(5)
func TestParseRegistriesConfV1(t *testing.T) {
	conf := readRegistriesFixture(t, "v1.conf")
	require.NotNil(t, conf.UnqualifiedSearchRegistries)
	assert.Equal(t, []string{"registry1.com", "registry2.com"}, *conf.UnqualifiedSearchRegistries)

	merged := registriesConf{}
	mergeRegistriesConf(&merged, conf)
	require.Len(t, merged.Registries, 2)
	assert.Equal(t, "registry.untrusted.com", merged.Registries[0].Prefix)
	assert.True(t, merged.Registries[0].Blocked)
	assert.False(t, merged.Registries[0].Insecure)
	assert.Equal(t, "registry3.com", merged.Registries[1].Prefix)
	assert.True(t, merged.Registries[1].Insecure, "listed as insecure")
	assert.True(t, merged.Registries[1].Blocked, "and as blocked")
}

func TestParseRegistriesConfErrors(t *testing.T) {
	_, err := parseRegistriesConf("unqualified-search-registries = [\"docker.io\"]\n[registries.search]\nregistries = [\"quay.io\"]\n")
	assert.Error(t, err, "version 1 and 2 settings in one file")
	_, err = parseRegistriesConf("[[registry]\nlocation = ")
	assert.Error(t, err)

	conf, err := parseRegistriesConf("")
	require.NoError(t, err)
	assert.Nil(t, conf.UnqualifiedSearchRegistries, "an empty file sets nothing")
}

func TestIsRegistriesConfDFileName(t *testing.T) {
	assert.True(t, isRegistriesConfDFileName("crio.conf"))
	assert.True(t, isRegistriesConfDFileName(".hidden.conf"), "the containers tools read hidden drop-ins")
	assert.False(t, isRegistriesConfDFileName("crio.conf.rpmsave"))

	// in byte order: "." sorts before digits, and "-" before "0"
	assert.Equal(t, []string{
		"/etc/containers/registries.conf.d/.local.conf",
		"/usr/share/containers/registries.conf.d/00-vendor.conf",
		"/usr/share/containers/registries.conf.d/000-shortnames.conf",
		"/etc/containers/registries.conf.d/crio.conf",
	}, selectConfDFilesWith(containersRegistriesDropInDirs, [][]string{
		nil,
		{"crio.conf", ".local.conf", "00-vendor.conf.bak"},
		nil,
		{"00-vendor.conf", "000-shortnames.conf", "crio.conf"},
	}, isRegistriesConfDFileName), "an /etc drop-in hides the vendor file of the same name")
}

// The drop-in the CRI-O package installs on Ubuntu sets only the search list
func TestRegistriesConfCrio(t *testing.T) {
	conf := readRegistriesFixture(t, "crio.conf")
	require.NotNil(t, conf.UnqualifiedSearchRegistries)
	assert.Equal(t, []string{"docker.io"}, *conf.UnqualifiedSearchRegistries)
	assert.Equal(t, "", conf.ShortNameMode)
	assert.Empty(t, conf.Registries)
}
