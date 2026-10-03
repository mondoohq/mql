// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func TestSbinCommandCandidates(t *testing.T) {
	assert.Equal(t, []string{
		"vgs --reportformat json -o vg_name",
		"/usr/sbin/vgs --reportformat json -o vg_name",
		"/sbin/vgs --reportformat json -o vg_name",
	}, sbinCommandCandidates("vgs --reportformat json -o vg_name"))

	assert.Equal(t, []string{"zfs", "/usr/sbin/zfs", "/sbin/zfs"}, sbinCommandCandidates("zfs"))

	// the environment words in front of the tool stay in front of it
	assert.Equal(t, []string{
		"env LC_ALL=C vgs -o vg_name",
		"env LC_ALL=C /usr/sbin/vgs -o vg_name",
		"env LC_ALL=C /sbin/vgs -o vg_name",
	}, sbinCommandCandidates("env LC_ALL=C vgs -o vg_name"))
	assert.Equal(t, []string{"LC_ALL=C mdadm", "LC_ALL=C /usr/sbin/mdadm", "LC_ALL=C /sbin/mdadm"}, sbinCommandCandidates("LC_ALL=C mdadm"))
	// an empty value is still an assignment
	assert.Equal(t, []string{"env LANG= vgs", "env LANG= /usr/sbin/vgs", "env LANG= /sbin/vgs"}, sbinCommandCandidates("env LANG= vgs"))

	// a tool named by its path is run as is
	assert.Equal(t, []string{"/usr/local/sbin/zpool list"}, sbinCommandCandidates("/usr/local/sbin/zpool list"))
}

func TestIsCommandNotFound(t *testing.T) {
	assert.True(t, isCommandNotFound(127, ""))
	assert.False(t, isCommandNotFound(0, ""))
	assert.False(t, isCommandNotFound(5, ""))
	// sudo with a secure_path that lacks sbin, and doas, exit 1
	assert.True(t, isCommandNotFound(1, "sudo: vgs: command not found\n"))
	assert.True(t, isCommandNotFound(1, "doas: mdadm: command not found\n"))
	// the tool ran and failed
	assert.False(t, isCommandNotFound(1, "mdadm: must be super-user to perform this action\n"))
	assert.False(t, isCommandNotFound(1, "Device /dev/sdb1 is not a valid LUKS device.\n"))
}

// lvm prints numbers in the caller's locale, "0,02" under de_DE.UTF-8, and
// translates "Permission denied" ("Keine Berechtigung"), so its reports run in
// the C locale.
func TestLvmCommandLineRunsInTheCLocale(t *testing.T) {
	assert.Equal(t, "env LC_ALL=C vgs --reportformat json -o vg_name", lvmCommandLine("vgs --reportformat json -o vg_name"))
}

func TestMdadmFailure(t *testing.T) {
	t.Run("not installed", func(t *testing.T) {
		withStructuredErrors(t, true)
		absent, err := mdadmFailure(127, "sh: 1: mdadm: not found\n")
		assert.True(t, absent)
		assert.NoError(t, err)
	})
	t.Run("refused, structured errors", func(t *testing.T) {
		withStructuredErrors(t, true)
		_, err := mdadmFailure(1, "mdadm: must be super-user to perform this action\n")
		assert.ErrorIs(t, err, llx.ErrForbidden)
	})
	t.Run("refused, v13", func(t *testing.T) {
		withStructuredErrors(t, false)
		absent, err := mdadmFailure(1, "mdadm: must be super-user to perform this action\n")
		assert.True(t, absent)
		assert.NoError(t, err)
	})
	t.Run("other failure", func(t *testing.T) {
		withStructuredErrors(t, false)
		_, err := mdadmFailure(1, "mdadm: cannot open /dev/md0: No such device\n")
		assert.Error(t, err)
	})
}

func TestLuksDumpFailure(t *testing.T) {
	// cryptsetup 2.6 run by a regular user, exit 4
	refused := "Device /dev/nvme2n1p1 does not exist or access denied.\n"
	t.Run("refused, structured errors", func(t *testing.T) {
		withStructuredErrors(t, true)
		skip, err := luksDumpFailure("/dev/nvme2n1p1", 4, refused)
		assert.False(t, skip)
		assert.ErrorIs(t, err, llx.ErrForbidden)
	})
	t.Run("refused, v13", func(t *testing.T) {
		withStructuredErrors(t, false)
		skip, err := luksDumpFailure("/dev/nvme2n1p1", 4, refused)
		assert.True(t, skip)
		assert.NoError(t, err)
	})
	// lsblk found a LUKS device; without cryptsetup it cannot be described,
	// which is not the same as there being none
	t.Run("cryptsetup not installed", func(t *testing.T) {
		withStructuredErrors(t, false)
		_, err := luksDumpFailure("/dev/nvme2n1p1", 127, "sh: 1: cryptsetup: not found\n")
		assert.Error(t, err)
	})
	t.Run("other failure", func(t *testing.T) {
		withStructuredErrors(t, false)
		_, err := luksDumpFailure("/dev/nvme2n1p1", 1, "Device /dev/nvme2n1p1 is not a valid LUKS device.\n")
		assert.Error(t, err)
	})
}
