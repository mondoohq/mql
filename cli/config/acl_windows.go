// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

// systemOnlyFileSDDL is the access list of a credentials file under
// ProgramData: SYSTEM and Administrators get full control, nobody else gets
// anything, and the "P" flag stops entries inherited from the folder from
// applying. Without it the file inherits ProgramData's defaults, which let
// every local user read it.
const systemOnlyFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// programDataDir returns the ProgramData folder. A variable so tests can
// point it at a temporary directory.
var programDataDir = func() string {
	if dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && dir != "" {
		return dir
	}
	if dir := os.Getenv("ProgramData"); dir != "" {
		return dir
	}
	return `C:\ProgramData`
}

// isUnderProgramData reports whether path is inside a folder below ProgramData,
// such as C:\ProgramData\Mondoo\mondoo.yml. The comparison ignores case, as
// Windows paths do.
func isUnderProgramData(path string) bool {
	root := filepath.Clean(programDataDir())
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(strings.ToLower(root), strings.ToLower(filepath.Clean(abs)))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	// a file directly in ProgramData is not ours to lock down
	return strings.Contains(rel, string(filepath.Separator))
}

// restrictAccess limits a credentials file under ProgramData to SYSTEM and
// Administrators. It is applied on every write, so a file written by an older
// version with ProgramData's inherited access list is repaired the next time
// it is written. Files elsewhere, such as a config in the user's profile, keep
// the access list they inherit, which is limited to that user by default.
func restrictAccess(path string) error {
	if !isUnderProgramData(path) {
		return nil
	}
	return restrictToSystemAndAdmins(path)
}

// restrictToSystemAndAdmins replaces the access list of path with
// systemOnlyFileSDDL and makes Administrators its owner, so a file someone else
// created beforehand does not stay under their control.
//
// Changing the owner needs an elevated process. Without one, the owner is left
// as is and the account that writes the file is added to the access list, so
// the write that follows still succeeds.
func restrictToSystemAndAdmins(path string) error {
	sd, err := windows.SecurityDescriptorFromString(systemOnlyFileSDDL)
	if err != nil {
		return errors.Wrap(err, "failed to build access list")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return errors.Wrap(err, "failed to build access list")
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return errors.Wrap(err, "failed to look up the Administrators group")
	}

	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info|windows.OWNER_SECURITY_INFORMATION, admins, nil, dacl, nil)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_INVALID_OWNER) && !errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
		return errors.Wrap(err, "failed to restrict access to "+path)
	}

	log.Debug().Err(err).Str("path", path).Msg("not elevated, keeping the file owner and granting access to the current user")
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errors.Wrap(err, "failed to look up the current user")
	}
	sd, err = windows.SecurityDescriptorFromString(systemOnlyFileSDDL + "(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return errors.Wrap(err, "failed to build access list")
	}
	if dacl, _, err = sd.DACL(); err != nil {
		return errors.Wrap(err, "failed to build access list")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		return errors.Wrap(err, "failed to restrict access to "+path)
	}
	return nil
}
