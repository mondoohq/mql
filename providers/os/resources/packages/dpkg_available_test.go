// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func parseFile(t *testing.T, path string, parse func(f *os.File) (map[string]PackageUpdate, error)) map[string]PackageUpdate {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	m, err := parse(f)
	require.NoError(t, err)
	return m
}

func aptList(f *os.File) (map[string]PackageUpdate, error)   { return ParseAptListUpgradable(f) }
func aptDryRun(f *os.File) (map[string]PackageUpdate, error) { return ParseDpkgUpdates(f) }

// byNameArch indexes updates the way packages.list joins them.
func byNameArch(m map[string]PackageUpdate) map[string]PackageUpdate {
	res := map[string]PackageUpdate{}
	for _, u := range m {
		res[u.Name+"/"+u.Arch] = u
	}
	return res
}

// `apt list --upgradable` captured on Ubuntu 24.04 with a held package
// (g03-hold), a package kept back for a new dependency (g03-keptback), the
// pending kernel meta packages, and g03-ma installed for amd64 and i386. A
// simulated `apt-get upgrade` on the same host named none of the held, kept
// back or kernel updates.
func TestParseAptListUpgradableUbuntu2404(t *testing.T) {
	m := byNameArch(parseFile(t, "./testdata/apt-list-upgradable-ubuntu2404.txt", aptList))
	assert.Len(t, m, 28, "apt printed 28 upgradable lines")

	for key, want := range map[string]PackageUpdate{
		"g03-hold/all":     {Name: "g03-hold", Arch: "all", Version: "1.0-1", Available: "1.1-1"},
		"g03-keptback/all": {Name: "g03-keptback", Arch: "all", Version: "1.0-1", Available: "1.1-1"},
		"linux-image-aws/amd64": {Name: "linux-image-aws", Arch: "amd64",
			Version: "7.0.0-1013.13~24.04.1", Available: "7.0.0-1014.14~24.04.1"},
		// both architectures of a multi-arch package stay apart
		"g03-ma/amd64": {Name: "g03-ma", Arch: "amd64", Version: "1.0-1", Available: "1.1-1"},
		"g03-ma/i386":  {Name: "g03-ma", Arch: "i386", Version: "1.0-1", Available: "1.1-1"},
		// epoch and tilde versions
		"g03-epoch/all":       {Name: "g03-epoch", Arch: "all", Version: "2:1.0-1", Available: "2:1.1-1"},
		"g03-tilde/all":       {Name: "g03-tilde", Arch: "all", Version: "1.0~rc1-1", Available: "1.0-1"},
		"libaudit-common/all": {Name: "libaudit-common", Arch: "all", Version: "1:3.1.2-2.1build1.1", Available: "1:3.1.2-2.1ubuntu0.1"},
	} {
		assert.Equal(t, want, m[key], key)
	}

	_, listing := m["Listing.../"]
	assert.False(t, listing, "the header is not a package")
}

func TestParseAptListUpgradableLineShapes(t *testing.T) {
	in := strings.Join([]string{
		"Listing... Done",
		// a qualified name is reduced to the name dpkg lists
		"g03-ma:i386/unknown 1.1-1 i386 [upgradable from: 1.0-1]",
		// apt list --installed shape, not an upgrade
		"bash/noble,now 5.2.21-2ubuntu4 amd64 [installed]",
		"",
	}, "\n")
	m, err := ParseAptListUpgradable(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, m, 1)
	assert.Equal(t, PackageUpdate{Name: "g03-ma", Arch: "i386", Version: "1.0-1", Available: "1.1-1"}, m["g03-ma/i386"])
}

// A foreign-architecture update is printed as `Inst g03-ma:i386 [...]`. The
// name used to keep the qualifier, so packages.list looked up "g03-ma/i386"
// against "g03-ma:i386/i386" and the i386 package reported no update.
func TestParseDpkgUpdatesForeignArch(t *testing.T) {
	m := byNameArch(parseFile(t, "./testdata/apt-upgrade-dry-run-ubuntu1604.txt", aptDryRun))
	assert.Equal(t, PackageUpdate{Name: "g03-ma", Arch: "i386", Version: "1.0-1", Available: "1.1-1"}, m["g03-ma/i386"])
	assert.Equal(t, PackageUpdate{Name: "g03-ma", Arch: "amd64", Version: "1.0-1", Available: "1.1-1"}, m["g03-ma/amd64"])
}

// apt 1.2 (Ubuntu 16.04) prints a multi-arch package once per name: with
// g03-ma installed for amd64 and i386 its apt list shows only the i386 line.
// The simulated upgrade still names the amd64 one, while only apt list names
// the held, kept-back and kernel updates. The merge needs both.
func TestMergeDebUpdatesUbuntu1604(t *testing.T) {
	list := parseFile(t, "./testdata/apt-list-upgradable-ubuntu1604.txt", aptList)
	dry := parseFile(t, "./testdata/apt-upgrade-dry-run-ubuntu1604.txt", aptDryRun)

	_, inList := list["g03-ma/amd64"]
	require.False(t, inList, "apt 1.2 collapses the multi-arch package")

	m := byNameArch(mergeDebUpdates(list, dry))
	for _, key := range []string{"g03-ma/amd64", "g03-ma/i386", "g03-hold/all", "g03-keptback/all", "linux-image-aws/amd64", "kmod/amd64"} {
		assert.Contains(t, m, key)
	}
	// 16 lines from apt list plus g03-ma/amd64 from the simulated upgrade
	assert.Len(t, m, 17)
}

// aptHostConn answers the commands DebPkgManager.Available runs.
type aptHostConn struct {
	shared.Connection
	listOut  string
	listExit int
	dryOut   string
}

func (c *aptHostConn) RunCommand(command string) (*shared.Command, error) {
	out := func(s string, exit int) (*shared.Command, error) {
		return &shared.Command{Command: command, Stdout: bytes.NewBufferString(s), Stderr: &bytes.Buffer{}, ExitStatus: exit}, nil
	}
	switch {
	case command == aptListUpgradableCmd:
		return out(c.listOut, c.listExit)
	case strings.Contains(command, "upgrade --dry-run"):
		return out(c.dryOut, 0)
	}
	return out("", 0)
}

func TestDebAvailableUsesAptList(t *testing.T) {
	base, err := mock.New(0, &inventory.Asset{})
	require.NoError(t, err)

	listOut, err := os.ReadFile("./testdata/apt-list-upgradable-ubuntu1604.txt")
	require.NoError(t, err)
	dryOut, err := os.ReadFile("./testdata/apt-upgrade-dry-run-ubuntu1604.txt")
	require.NoError(t, err)

	pm := &DebPkgManager{conn: &aptHostConn{Connection: base, listOut: string(listOut), dryOut: string(dryOut)}}
	m, err := pm.Available()
	require.NoError(t, err)
	got := byNameArch(m)
	assert.Equal(t, "4.4.0.1193.197", got["linux-image-aws/amd64"].Available, "kept-back kernel update")
	assert.Equal(t, "1.1-1", got["g03-hold/all"].Available, "held package")
	assert.Equal(t, "1.1-1", got["g03-ma/amd64"].Available)

	// apt list failing still leaves the simulated upgrade's answer
	pm = &DebPkgManager{conn: &aptHostConn{Connection: base, listExit: 100, dryOut: string(dryOut)}}
	m, err = pm.Available()
	require.NoError(t, err)
	got = byNameArch(m)
	assert.Len(t, got, 12)
	assert.NotContains(t, got, "g03-hold/all")
}
