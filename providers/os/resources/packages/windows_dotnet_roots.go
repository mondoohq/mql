// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Where a .NET install that is NOT under the default Program Files roots is
// recorded. fillDotNetInstallPaths only drops a leftover runtime entry when the
// version folder is missing from all of these as well as from the defaults, so
// a relocated install is never mistaken for a leftover.
//
//   - HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\<arch>\InstallLocation is
//     the globally registered install location the .NET host itself consults
//     when it looks for a runtime. The 32-bit view of the same key
//     (HKLM\SOFTWARE\WOW6432Node\dotnet\...) is read too.
//     https://learn.microsoft.com/dotnet/core/runtime-discovery/troubleshoot-app-launch
//   - DOTNET_ROOT, DOTNET_ROOT(x86), DOTNET_ROOT_X86, DOTNET_ROOT_X64 and
//     DOTNET_ROOT_ARM64 are the environment variables that redirect it. The
//     machine-wide ones live under
//     HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment.
//     https://learn.microsoft.com/dotnet/core/tools/dotnet-environment-variables
//
// Per-user environment variables are not read: an installer-registered runtime
// is machine-wide, and a user's own DOTNET_ROOT points at that user's private
// (zip) installs, which have no Add/Remove Programs entry.

var dotNetInstalledVersionsArchs = []string{"x64", "x86", "arm64", "arm"}

const dotNetMachineEnvKey = `CurrentControlSet\Control\Session Manager\Environment`

// dotNetRegistry reads registry values from the machine hives. found is false
// with a nil error for a key that does not exist; an error means the key could
// not be read, which is NOT the same as absent.
type dotNetRegistry interface {
	keyItems(hive, path string) (items []registry.RegistryKeyItem, found bool, err error)
}

var (
	dotNetDriveRoot = regexp.MustCompile(`^[A-Za-z]:\\`)
	dotNetRootEnv   = regexp.MustCompile(`(?i)^DOTNET_ROOT(?:\(x86\)|_X86|_X64|_ARM64)?$`)
)

// relocatedDotNetRoots returns the dotnet roots recorded in the registry as
// drive-absolute Windows paths. mounted says the filesystem is a mounted system
// volume: roots on the system drive are then returned relative to the mount, and
// roots on any other drive make the result incomplete, since the volume is not
// part of this connection.
//
// complete is false when anything could not be read or resolved.
func relocatedDotNetRoots(reg dotNetRegistry, mounted bool) (roots []string, complete bool) {
	complete = true
	seen := map[string]struct{}{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		value = strings.ReplaceAll(strings.Trim(value, `"`), "/", `\`)
		value = strings.TrimRight(value, `\`)
		if strings.Contains(value, "%") || !dotNetDriveRoot.MatchString(value+`\`) || len(value) < 4 {
			// A reference we cannot expand, a UNC path or a relative path.
			complete = false
			return
		}
		if mounted {
			rel, ok := mountedSystemDrivePath(value + `\`)
			if !ok {
				complete = false
				return
			}
			value = strings.TrimRight(rel, "/")
		}
		key := strings.ToLower(value)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		roots = append(roots, value)
	}

	read := func(hive, path string) []registry.RegistryKeyItem {
		items, found, err := reg.keyItems(hive, path)
		if err != nil {
			log.Debug().Err(err).Str("key", path).Msg("could not read .NET root from the registry")
			complete = false
			return nil
		}
		if !found {
			return nil
		}
		return items
	}

	for _, view := range []string{`SOFTWARE`, `SOFTWARE\WOW6432Node`} {
		for _, arch := range dotNetInstalledVersionsArchs {
			path := view + `\dotnet\Setup\InstalledVersions\` + arch
			hive, sub, _ := strings.Cut(path, `\`)
			for _, item := range read(hive, sub) {
				if strings.EqualFold(item.Key, "InstallLocation") {
					if item.Value.Err != nil {
						complete = false
						continue
					}
					add(item.Value.String)
				}
			}
		}
	}

	for _, item := range read(registry.System, dotNetMachineEnvKey) {
		if dotNetRootEnv.MatchString(item.Key) {
			if item.Value.Err != nil {
				complete = false
				continue
			}
			add(item.Value.String)
		}
	}
	return roots, complete
}

// registryKeyNotFound reports whether a registry read failed because the key is not there.
func registryKeyNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// nativeDotNetRegistry reads the live registry of the local Windows host.
type nativeDotNetRegistry struct{}

func (nativeDotNetRegistry) keyItems(hive, path string) ([]registry.RegistryKeyItem, bool, error) {
	items, err := registry.GetNativeRegistryKeyItems(`HKLM\` + hive + `\` + path)
	if registryKeyNotFound(err) {
		return nil, false, nil
	}
	return items, err == nil, err
}

// hiveDotNetRegistry reads the SOFTWARE and SYSTEM hives loaded from a mounted
// system volume.
type hiveDotNetRegistry struct {
	rh interface {
		GetNativeRegistryKeyItems(registryId string, path string) ([]registry.RegistryKeyItem, error)
	}
}

func (h hiveDotNetRegistry) keyItems(hive, path string) ([]registry.RegistryKeyItem, bool, error) {
	if hive == registry.System {
		path = h.controlSetPath(path)
	}
	items, err := h.rh.GetNativeRegistryKeyItems(hive, path)
	if registryKeyNotFound(err) {
		return nil, false, nil
	}
	return items, err == nil, err
}

// controlSetPath maps CurrentControlSet, a link that exists only in a live
// registry, onto the control set the offline SYSTEM hive marks as current.
func (h hiveDotNetRegistry) controlSetPath(path string) string {
	const prefix = `CurrentControlSet\`
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return path
	}
	n := int64(1)
	if items, err := h.rh.GetNativeRegistryKeyItems(registry.System, "Select"); err == nil {
		for _, it := range items {
			if strings.EqualFold(it.Key, "Current") && it.Value.Number > 0 {
				n = it.Value.Number
			}
		}
	}
	return fmt.Sprintf(`ControlSet%03d\%s`, n, rest)
}

// remoteDotNetRegistry reads the registry of a remote Windows host through
// PowerShell. A failing command cannot tell a missing key from a refused one,
// so a canary key that exists on every Windows install is read first: only when
// that works does a failing read mean "no such key".
type remoteDotNetRegistry struct {
	w        *WinPkgManager
	canary   bool
	canaryOK bool
}

func (r *remoteDotNetRegistry) keyItems(hive, path string) ([]registry.RegistryKeyItem, bool, error) {
	if !r.canary {
		r.canary = true
		_, found, err := r.read(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
		r.canaryOK = err == nil && found
	}
	if !r.canaryOK {
		return nil, false, fmt.Errorf("registry is not readable over this connection")
	}
	return r.read(`HKEY_LOCAL_MACHINE\` + hive + `\` + path)
}

func (r *remoteDotNetRegistry) read(path string) ([]registry.RegistryKeyItem, bool, error) {
	cmd, err := r.w.conn.RunCommand(powershell.Encode(registry.GetRegistryKeyItemScript(path)))
	if err != nil {
		return nil, false, err
	}
	if cmd.ExitStatus != 0 {
		return nil, false, nil
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, true, nil
	}
	items, err := registry.ParsePowershellRegistryKeyItems(strings.NewReader(string(data)))
	return items, err == nil, err
}

// dotNetRootLookup returns the lookup of relocated dotnet roots for this
// connection, or nil when it has no way to read the registry (fail open).
func (w *WinPkgManager) dotNetRootLookup() dotNetRootLookup {
	switch {
	case w.conn.Type() == shared.Type_Local && runtime.GOOS == "windows":
		return func() ([]string, bool) { return relocatedDotNetRoots(nativeDotNetRegistry{}, false) }

	case w.conn.Type() == shared.Type_FileSystem || w.conn.Type() == shared.Type_Device:
		return func() ([]string, bool) {
			rh := registry.NewRegistryHandler()
			defer func() {
				if err := rh.UnloadSubkeys(); err != nil {
					log.Debug().Err(err).Msg("could not unload registry subkeys")
				}
			}()
			for id, file := range map[string]string{registry.Software: registry.SoftwareRegPath, registry.System: registry.SystemRegPath} {
				fi, err := w.conn.FileInfo(file)
				if err != nil {
					log.Debug().Err(err).Str("hive", id).Msg("could not find registry hive for .NET roots")
					return nil, false
				}
				if err := rh.LoadSubkey(id, fi.Path); err != nil {
					log.Debug().Err(err).Str("hive", id).Msg("could not load registry hive for .NET roots")
					return nil, false
				}
			}
			return relocatedDotNetRoots(hiveDotNetRegistry{rh: rh}, true)
		}

	case w.conn.Capabilities().Has(shared.Capability_RunCommand):
		return func() ([]string, bool) { return relocatedDotNetRoots(&remoteDotNetRegistry{w: w}, false) }
	}
	return nil
}
