// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

const (
	// According to https://learn.microsoft.com/en-gb/windows/win32/sysinfo/structure-of-the-registry
	// we have the following registry keys
	Software = "SOFTWARE"
	System   = "SYSTEM"
	Security = "SECURITY"
	Default  = "DEFAULT"
	Sam      = "SAM"

	// The paths use forward slashes: they are handed to the connection's
	// filesystem (afero), where a POSIX scanner treats a backslash as part of a
	// file name. Windows accepts both separators.
	SoftwareRegPath = "Windows/System32/config/SOFTWARE"
	SystemRegPath   = "Windows/System32/config/SYSTEM"
	SecurityRegPath = "Windows/System32/config/SECURITY"
	DefaultRegPath  = "Windows/System32/config/DEFAULT"
	SamRegPath      = "Windows/System32/config/SAM"
)

var KnownRegistryFiles = map[string]string{
	Software: SoftwareRegPath,
	System:   SystemRegPath,
	Security: SecurityRegPath,
	Default:  DefaultRegPath,
	Sam:      SamRegPath,
}
