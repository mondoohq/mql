// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func checkUpdateCmd(stdout, stderr string, exit int) *shared.Command {
	return &shared.Command{
		Command:    rpmCheckUpdateCommand,
		Stdout:     bytes.NewBufferString(stdout),
		Stderr:     bytes.NewBufferString(stderr),
		ExitStatus: exit,
	}
}

func TestParseRpmCheckUpdateResult(t *testing.T) {
	t.Run("exit 100 lists the updates", func(t *testing.T) {
		m, err := parseRpmCheckUpdateResult(checkUpdateCmd(
			"\ng03-epoch.x86_64     3:2.0-1     g03repo\n", "", 100))
		require.NoError(t, err)
		assert.Equal(t, "3:2.0-1", m["g03-epoch.x86_64"].Available)
	})

	t.Run("exit 0 is no updates", func(t *testing.T) {
		m, err := parseRpmCheckUpdateResult(checkUpdateCmd("", "", 0))
		require.NoError(t, err)
		assert.Empty(t, m)
	})

	// RHEL 9 as root with repo_gpgcheck=1 and an unsigned repository: dnf
	// prints nothing on stdout and exits 1. This read as "no updates".
	t.Run("a failed check is an error, not an empty list", func(t *testing.T) {
		stderr := "Error: Failed to download metadata for repo 'g03repo': GPG verification is enabled, but GPG signature is not available. This may be an error or the repository does not support GPG verification: Curl error (37): Couldn't read a file:// file for file:///srv/g03repo/repodata/repomd.xml.asc [Couldn't open file /srv/g03repo/repodata/repomd.xml.asc]\n"
		m, err := parseRpmCheckUpdateResult(checkUpdateCmd("", stderr, 1))
		require.Error(t, err)
		assert.Nil(t, m)
		assert.ErrorIs(t, err, ErrUpdateCheckFailed)
		assert.Contains(t, err.Error(), "status 1")
		assert.Contains(t, err.Error(), "Failed to download metadata for repo 'g03repo'")
	})

	t.Run("a long stderr is cut", func(t *testing.T) {
		_, err := parseRpmCheckUpdateResult(checkUpdateCmd("", strings.Repeat("x", 4096), 1))
		require.Error(t, err)
		assert.Less(t, len(err.Error()), 700)
	})

	t.Run("no stderr", func(t *testing.T) {
		_, err := parseRpmCheckUpdateResult(&shared.Command{Stdout: &bytes.Buffer{}, ExitStatus: 127})
		require.EqualError(t, err, "could not check for package updates: check-update exited with status 127")
	})
}

// The g03 test packages, as rpm -qa prints them with queryFormat(). The
// values are from `rpm -qa --qf` on RHEL 9 (rpm.tsv in the sweep evidence).
func TestParseRpmPackagesUnitSeparator(t *testing.T) {
	pf := &inventory.Platform{Name: "redhat", Version: "9", Arch: "x86_64", Labels: map[string]string{"distro-id": "rhel"}}
	us := rpmFieldSep
	lines := []string{
		"g03-weird 0:1.0-1 x86_64" + us + "G03 Vendor <https://vendor.example>" + us + "weird __ summary __ with separators" + us + "MIT and BSD" + us + "1790924429" + us + "(none)",
		"g03-novendor 0:1.0-1 x86_64" + us + "(none)" + us + "G03 no vendor tilde" + us + "MIT" + us + "1790924429" + us + "(none)",
		// a vendor with no spaces next to the arch, and no modularity field
		"g03-multi 0:1.0-1 i686" + us + "G03" + us + "G03 multilib i686" + us + "MIT" + us + "1790924429",
	}
	pkgs := ParseRpmPackages(pf, strings.NewReader(strings.Join(lines, "\n")+"\n"))
	require.Len(t, pkgs, 3)

	weird := pkgs[0]
	assert.Equal(t, "g03-weird", weird.Name)
	assert.Equal(t, "x86_64", weird.Arch)
	assert.Equal(t, "G03 Vendor", weird.Vendor)
	assert.Equal(t, "weird __ summary __ with separators", weird.Description)
	assert.Equal(t, "MIT and BSD", weird.License)
	assert.Equal(t, int64(1790924429), weird.InstallDate.Unix())

	novendor := pkgs[1]
	assert.Equal(t, "", novendor.Vendor, "(none) is rpm's sentinel for a missing Vendor tag")
	assert.Equal(t, "MIT", novendor.License)

	multi := pkgs[2]
	assert.Equal(t, "i686", multi.Arch)
	assert.Equal(t, "G03", multi.Vendor)
	assert.Equal(t, "G03 multilib i686", multi.Description)
}

// The "__" format remains readable: reboot/rhel.go and captured test data
// still use it.
func TestParseRpmPackagesLegacySeparator(t *testing.T) {
	pf := &inventory.Platform{Name: "redhat", Version: "9", Arch: "x86_64"}
	pkgs := ParseRpmPackages(pf, strings.NewReader("kernel 0:5.14.0-1.el9 x86_64__Red Hat, Inc.__The Linux kernel__GPLv2__1790924429\n"))
	require.Len(t, pkgs, 1)
	assert.Equal(t, "Red Hat, Inc.", pkgs[0].Vendor)
	assert.Equal(t, "The Linux kernel", pkgs[0].Description)
	assert.Equal(t, "GPLv2", pkgs[0].License)
}
