// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"syscall"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// errPlatformUnknown is returned for an OS runtime when the asset's platform
// was not detected: a package named "" with the purl "pkg:platform/" would
// identify no operating system.
var errPlatformUnknown = errors.New("cannot report the operating system as the runtime: the asset's platform is not known")

// configPresent reports whether configPath exists on the target as a directory,
// or as a regular file when isFile is set. Only an absent path is an absent
// config; a stat that failed otherwise is returned (see configStatError).
func configPresent(runtime *plugin.Runtime, configPath string, isFile bool) (bool, error) {
	if configPath == "" {
		return false, nil
	}
	info, err := connectionAfs(runtime).Stat(configPath)
	if err != nil {
		return false, configStatError(err)
	}
	if isFile {
		return info.Mode().IsRegular(), nil
	}
	return info.IsDir(), nil
}

// configStatError turns the error of a stat on a tool's config path into the
// error the package lookup returns: nil when the path is absent (or sits
// under a file), so the tool reads as not installed. A refused stat is a
// refusal (ADR 046), returned only with structured errors on, since v13 read
// it as absent. Anything else, such as a transport that stalled, is returned
// as is: "not installed" would be a confident answer nobody measured.
func configStatError(err error) error {
	if err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil
	}
	if errors.Is(err, fs.ErrPermission) {
		if !plugin.StructuredErrors() {
			return nil
		}
		return llx.Forbidden(err)
	}
	return err
}
