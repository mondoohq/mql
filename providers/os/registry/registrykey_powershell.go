// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// isEmptyPowershellList reports whether the collection scripts produced no
// output. `ConvertTo-Json` writes nothing for an empty array, so a key that
// exists but holds no values (or no subkeys) comes back as an empty stream
// rather than as `[]`. Decoding that as JSON fails with "unexpected end of
// JSON input", which would surface as an unreadable key: exactly the case the
// callers need to read as "present, but nothing configured".
func isEmptyPowershellList(data []byte) bool {
	return len(bytes.TrimSpace(data)) == 0
}

func ParsePowershellRegistryKeyItems(r io.Reader) ([]RegistryKeyItem, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if isEmptyPowershellList(data) {
		return []RegistryKeyItem{}, nil
	}

	var items []RegistryKeyItem
	if err := json.Unmarshal(data, &items); err != nil {
		// json.Unmarshal fills in what it managed to decode before failing.
		// Dropping it keeps a caller that ignores the error from mistaking a
		// half-read key for a key with nothing configured.
		return nil, err
	}
	return items, nil
}

func ParsePowershellRegistryKeyChildren(r io.Reader) ([]RegistryKeyChild, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if isEmptyPowershellList(data) {
		return []RegistryKeyChild{}, nil
	}

	var children []RegistryKeyChild
	if err := json.Unmarshal(data, &children); err != nil {
		return nil, err
	}
	return children, nil
}

// getRegistryKeyItemScript reads every value of a registry key.
//
// Value types come from reg.exe rather than from RegistryKey.GetValueKind().
// PowerShell's Constrained Language Mode, which is what WDAC and AppLocker put
// a host into, refuses method invocation on non-core types, so GetValueKind()
// yields nothing there. reg.exe is an external program and language mode does
// not restrict those, so it reports the type on hardened and unhardened hosts
// alike. GetValueKind() is kept as a fallback for values reg.exe did not
// report; when neither produces a type the value is emitted without one and
// the Go decoder fails the read rather than reporting the value as empty.
//
// Value *data* still comes from Get-ItemProperty: reg.exe prints REG_EXPAND_SZ
// values unexpanded, so sourcing data from it would change what every existing
// query returns.
const getRegistryKeyItemScript = `
$path = %s
$reg = Get-Item ('Registry::' + $path)
if ($reg -eq $null) {
  Write-Error "Could not find registry key"
  exit 1
}
$regExe = $env:SystemRoot + '\System32\reg.exe'
$types = @{}
& $regExe query $path 2>$null | ForEach-Object {
  if ($_ -match '^\s{4}(.+?)\s{4}(REG_[A-Z_]+)(\s{4}|$)') {
    $types[$matches[1]] = $matches[2]
  }
}
$defaultType = $null
if ($reg.Property -contains '(default)') {
  # reg.exe names the default value in the console locale, so it is read
  # through its own query instead of being matched by name.
  & $regExe query $path /ve 2>$null | ForEach-Object {
    if ($_ -match '^\s{4}.+?\s{4}(REG_[A-Z_]+)(\s{4}|$)') { $defaultType = $matches[1] }
  }
}
$properties = @()
$reg.Property | ForEach-Object {
    $fetchKeyValue = $_
    $type = $types[$_]
    if ("(default)".Equals($_)) {
      $fetchKeyValue = ''
      $type = $defaultType
    }
    $data = $(Get-ItemProperty ('Registry::' + $path)).$_;
    if ($data -is [string[]]) {
      $data = $(Get-ItemProperty ('Registry::' + $path)) | Select-Object -ExpandProperty $_
    }
    $kind = $null
    if ($type -eq $null) {
      try { $kind = $reg.GetValueKind($fetchKeyValue) } catch { $kind = $null }
    }
    $entry = New-Object psobject -Property @{
      "key" = $_
      "value" = New-Object psobject -Property @{
        "data" = $data;
        "kind" = $kind;
        "type" = $type;
      }
    }
    $properties += $entry
}
ConvertTo-Json -Depth 3 -Compress $properties
`

func GetRegistryKeyItemScript(path string) string {
	return fmt.Sprintf(getRegistryKeyItemScript, powershell.SingleQuote(path))
}

// getRegistryKeyChildItemsScript represents a registry key item and its children
const getRegistryKeyChildItemsScript = `
$path = %s
$children = Get-ChildItem -Path ('Registry::' + $path) -ea SilentlyContinue

$properties = @()
$children | ForEach-Object {
  $entry = New-Object psobject -Property @{
    "name" = $_.PSChildName
    "path" = $_.Name
    "properties" = $_.Property
    "children" = $_.SubKeyCount
  }
  $properties += $entry
}
ConvertTo-Json -compress $properties
`

func GetRegistryKeyChildItemsScript(path string) string {
	return fmt.Sprintf(getRegistryKeyChildItemsScript, powershell.SingleQuote(path))
}
