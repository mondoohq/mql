// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// sudoersIncludedirRefusal returns a forbidden error when dir exists but
// cannot be listed, and nil otherwise. files.find skips a directory it may
// not read, even the one it starts from, so without this check an unreadable
// @includedir reads as an empty one. SLES 16 and openSUSE Leap 16 ship
// /etc/sudoers.d and /usr/etc/sudoers.d as 0750 next to a world-readable
// /usr/etc/sudoers, so a non-root scan saw only the main file and missed the
// NOPASSWD grants in the drop-ins. v13 skipped the directory, and keeps doing
// so without StructuredErrors.
func sudoersIncludedirRefusal(fs afero.Fs, dir string) error {
	if fs == nil {
		return nil
	}
	_, err := globDir(fs, dir, "*", false)
	if err == nil || !errors.Is(err, llx.ErrForbidden) || !plugin.StructuredErrors() {
		return nil
	}
	return err
}
