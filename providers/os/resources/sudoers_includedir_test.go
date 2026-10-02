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
