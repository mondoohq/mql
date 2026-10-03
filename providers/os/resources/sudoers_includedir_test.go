// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestSudoersIncludedirRefusal(t *testing.T) {
	// SLES 16 as a non-root user: /usr/etc/sudoers is 0444, the includedirs 0750
	fsys := newUnlistableFs(t, []string{
		"/usr/etc/sudoers",
		"/etc/sudoers.d/90-cloud-init-users",
		"/usr/etc/sudoers.d/mqlvendor",
	}, "/etc/sudoers.d")

	t.Run("unlistable includedir is forbidden", func(t *testing.T) {
		withStructuredErrors(t, true)
		err := sudoersIncludedirRefusal(fsys, "/etc/sudoers.d")
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrForbidden), "%v", err)
		assert.Contains(t, err.Error(), "/etc/sudoers.d")
	})

	t.Run("readable and missing includedirs are not errors", func(t *testing.T) {
		withStructuredErrors(t, true)
		assert.NoError(t, sudoersIncludedirRefusal(fsys, "/usr/etc/sudoers.d"))
		assert.NoError(t, sudoersIncludedirRefusal(fsys, "/etc/sudoers.missing.d"))
	})

	t.Run("v13 keeps skipping the directory", func(t *testing.T) {
		withStructuredErrors(t, false)
		assert.NoError(t, sudoersIncludedirRefusal(fsys, "/etc/sudoers.d"))
	})
}

func TestSudoersIncludedirFiles(t *testing.T) {
	// /etc/sudoers.d on RHEL 9 after the sweep's fixtures; `visudo -c` parsed
	// README, mqltest, mqlnew and mqllink and none of the others
	listing := []string{
		"/etc/sudoers.d/README",
		"/etc/sudoers.d/mqltest",
		"/etc/sudoers.d/mql.ignored",
		"/etc/sudoers.d/mqlbackup~",
		"/etc/sudoers.d/mqlnew",
		"/etc/sudoers.d/mqllink",
		"/etc/sudoers.d/mqlsub/inner",
	}
	assert.Equal(t,
		[]string{"/etc/sudoers.d/README", "/etc/sudoers.d/mqltest", "/etc/sudoers.d/mqlnew", "/etc/sudoers.d/mqllink"},
		sudoersIncludedirFiles("/etc/sudoers.d", listing))
	assert.Empty(t, sudoersIncludedirFiles("/etc/sudoers.d", nil))
}
