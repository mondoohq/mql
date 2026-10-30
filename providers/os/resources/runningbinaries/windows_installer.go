// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"errors"
	"io"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Windows Installer records, for every component it installs, the path of
// the component's key file and the product that installed it:
// UserData\<sid>\Components\<component>, one value per product, named by
// the product's packed code. A product that records no InstallLocation,
// which leaves its files without an install directory to match, is found
// there by the files themselves. The product's name is in
// UserData\<sid>\Products\<product>\InstallProperties, as DisplayName, the
// name the package inventory reports.
const windowsInstallerKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData`

// windowsInstallerOwnersScript prints the product that installed the
// executable of each running process, for those Windows Installer installed.
// It lists the processes itself, as the signature script does, so that the
// paths need not travel on the command line.
const windowsInstallerOwnersScript = `[Console]::OutputEncoding = [Text.Encoding]::UTF8
$want = @{}
Get-Process | Where-Object { $_.Path } | ForEach-Object { $want[$_.Path.ToLowerInvariant()] = $true }
$ud = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('` + windowsInstallerKey + `')
$res = @(if ($ud) { foreach ($sid in $ud.GetSubKeyNames()) {
  $comps = $ud.OpenSubKey($sid + '\Components')
  if (-not $comps) { continue }
  foreach ($c in $comps.GetSubKeyNames()) {
    $k = $comps.OpenSubKey($c)
    if (-not $k) { continue }
    foreach ($n in $k.GetValueNames()) {
      $v = $k.GetValue($n)
      if ($v -is [string] -and $want.ContainsKey($v.ToLowerInvariant())) {
        $p = $ud.OpenSubKey($sid + '\Products\' + $n + '\InstallProperties')
        if ($p) { [pscustomobject]@{ Path = $v; Product = [string]$p.GetValue('DisplayName') }; $p.Close() }
      }
    }
    $k.Close()
  }
  $comps.Close()
} })
ConvertTo-Json -InputObject $res -Compress`

type windowsInstallerOwner struct {
	Path    string `json:"Path"`
	Product string `json:"Product"`
}

// WindowsInstallerOwners returns the name of the Windows Installer product
// that installed each of paths, keyed by WindowsPathKey. A path no product
// installed has no entry.
func WindowsInstallerOwners(conn shared.Connection, paths []string) (map[string]string, error) {
	if nativeWindows(conn) {
		if res, ok := nativeWindowsInstallerOwners(paths); ok {
			return res, nil
		}
	}
	cmd, err := runCommand(conn, powershell.Encode(windowsInstallerOwnersScript))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not read the Windows Installer components")
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	return parseWindowsInstallerOwners(data)
}

func parseWindowsInstallerOwners(data []byte) (map[string]string, error) {
	res := map[string]string{}
	if strings.TrimSpace(string(data)) == "" {
		return res, nil
	}
	entries, err := powershell.UnmarshalList[windowsInstallerOwner](data)
	if err != nil {
		return nil, llx.MalformedData(errors.New("could not read the Windows Installer components: " + err.Error()))
	}
	for _, e := range entries {
		addInstallerOwner(res, e.Path, e.Product)
	}
	return res, nil
}

// addInstallerOwner records product as the installer of path, unless
// another product, which shares the component, already is.
func addInstallerOwner(res map[string]string, path, product string) {
	product = strings.TrimSpace(product)
	if path == "" || product == "" {
		return
	}
	key := WindowsPathKey(path)
	if _, ok := res[key]; !ok {
		res[key] = product
	}
}
