// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
)

// The Windows installer registers every home under
// HKLM\SOFTWARE\ORACLE\KEY_<HomeName> (value ORACLE_HOME) and the central
// inventory under HKLM\SOFTWARE\ORACLE (value inst_loc). 32-bit installs write
// to the WOW6432Node copy. Both feed the same inventory.xml format as on Unix.
var oracleWindowsRegistryRoots = []string{`ORACLE`, `WOW6432Node\ORACLE`}

// oracleWinRegistry is what the registry says about Oracle.
type oracleWinRegistry struct {
	// InstLoc is the central inventory directory, "" when not set.
	InstLoc string
	Homes   []string
}

// oracleRegistrySource is the subset of a registry hive the offline reader
// needs, relative to HKLM\SOFTWARE.
type oracleRegistrySource interface {
	Children(path string) ([]registry.RegistryKeyChild, error)
	Items(path string) ([]registry.RegistryKeyItem, error)
}

type softwareHive struct{ rh *registry.RegistryHandler }

func (s softwareHive) Children(p string) ([]registry.RegistryKeyChild, error) {
	return s.rh.GetNativeRegistryKeyChildren(registry.Software, p)
}

func (s softwareHive) Items(p string) ([]registry.RegistryKeyItem, error) {
	return s.rh.GetNativeRegistryKeyItems(registry.Software, p)
}

// readOracleRegistry reads the Oracle keys from a registry hive.
func readOracleRegistry(src oracleRegistrySource) oracleWinRegistry {
	var res oracleWinRegistry
	for _, root := range oracleWindowsRegistryRoots {
		if items, err := src.Items(root); err == nil {
			if v := itemString(items, "inst_loc"); v != "" && res.InstLoc == "" {
				res.InstLoc = v
			}
		}
		children, err := src.Children(root)
		if err != nil {
			continue
		}
		for _, ch := range children {
			items, err := src.Items(root + `\` + ch.Name)
			if err != nil {
				continue
			}
			if v := itemString(items, "ORACLE_HOME"); v != "" {
				res.Homes = append(res.Homes, v)
			}
		}
	}
	return res
}

// oracleRegistryScript prints the same two facts as JSON for a target that
// can run PowerShell (local Windows, WinRM, SSH). It touches nothing but the
// two Oracle keys.
const oracleRegistryScript = `
$ErrorActionPreference = 'SilentlyContinue'
$inst = ''
$homes = @()
foreach ($root in 'HKLM:\SOFTWARE\ORACLE', 'HKLM:\SOFTWARE\WOW6432Node\ORACLE') {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $v = [string](Get-ItemProperty -LiteralPath $root).inst_loc
    if ($v -and -not $inst) { $inst = $v }
    foreach ($k in Get-ChildItem -LiteralPath $root) {
        $h = [string]$k.GetValue('ORACLE_HOME')
        if ($h) { $homes += $h }
    }
}
[pscustomobject]@{ InstLoc = $inst; Homes = $homes } | ConvertTo-Json -Compress
`

// parseOracleRegistry reads oracleRegistryScript's output. Windows PowerShell
// 5.1 writes a one-element array as a single value, and an empty one as null.
func parseOracleRegistry(r io.Reader) (oracleWinRegistry, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return oracleWinRegistry{}, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return oracleWinRegistry{}, nil
	}
	var raw struct {
		InstLoc psOptionalString
		Homes   psList[string]
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return oracleWinRegistry{}, err
	}
	res := oracleWinRegistry{Homes: raw.Homes}
	if raw.InstLoc.v != nil {
		res.InstLoc = *raw.InstLoc.v
	}
	return res, nil
}

// newOracleWindowsHost returns the file reader of a Windows target. Offline
// images and devices address the system volume without its drive letter; a
// live connection takes native paths.
func newOracleWindowsHost(conn shared.Connection) *oracleHost {
	h := &oracleHost{fs: conn.FileSystem(), sep: `\`, toFs: nativeWindowsPath}
	if conn.Type() == shared.Type_FileSystem || conn.Type() == shared.Type_Device {
		h.toFs = mountedSystemDrivePath
	}
	return h
}

// discoverOracleWindowsHomes unions the homes of the registry with those of the
// central inventory it points at (or the default one). A target whose registry
// cannot be read yields nothing from the registry but still has the default
// inventory checked.
func discoverOracleWindowsHomes(h *oracleHost, reg oracleWinRegistry) []oracleHome {
	set := newOracleHomeSet(h)
	for _, home := range reg.Homes {
		set.add(home, false)
	}
	inv := h.clean(reg.InstLoc)
	if inv == "" {
		inv = oracleWindowsDefaultInventory
	}
	addInventoryHomes(h, set, inv)
	return set.homes
}

func readOracleWindowsRegistry(conn shared.Connection) oracleWinRegistry {
	switch {
	case conn.Type() == shared.Type_FileSystem || conn.Type() == shared.Type_Device:
		fi, err := conn.FileInfo(registry.SoftwareRegPath)
		if err != nil {
			log.Debug().Err(err).Msg("mql[packages]> oracle: could not find the SOFTWARE hive")
			return oracleWinRegistry{}
		}
		rh := registry.NewRegistryHandler()
		defer func() {
			if err := rh.UnloadSubkeys(); err != nil {
				log.Debug().Err(err).Msg("could not unload registry subkeys")
			}
		}()
		if err := rh.LoadSubkey(registry.Software, fi.Path); err != nil {
			log.Debug().Err(err).Msg("mql[packages]> oracle: could not load the SOFTWARE hive")
			return oracleWinRegistry{}
		}
		return readOracleRegistry(softwareHive{rh})
	case conn.Capabilities().Has(shared.Capability_RunCommand):
		cmd, err := runComponentScript(conn, "oracle-homes", oracleRegistryScript)
		if err != nil || cmd.ExitStatus != 0 {
			log.Debug().Err(err).Msg("mql[packages]> oracle: could not read the Oracle registry keys")
			return oracleWinRegistry{}
		}
		res, err := parseOracleRegistry(cmd.Stdout)
		if err != nil {
			log.Debug().Err(err).Msg("mql[packages]> oracle: could not parse the Oracle registry keys")
			return oracleWinRegistry{}
		}
		return res
	}
	return oracleWinRegistry{}
}
