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
// the Go decoder fails the read rather than reporting the value as empty. Such
// a value also carries the session's language mode, so the decoder can tell a
// refusal (Constrained Language Mode) from anything else.
//
// A key that cannot be opened fails Get-Item with -ErrorAction Stop, so stderr
// holds that one error record: its CategoryInfo (PermissionDenied,
// ObjectNotFound) is what the resource classifies. A Write-Error of its own
// would add a record that echoes the whole encoded script.
//
// Value data comes from Get-ItemProperty, except for REG_EXPAND_SZ:
// Get-ItemProperty expands environment variables, but the native path reads
// the value as stored, which is what is configured (%SystemRoot%\...), so the
// script reads it unexpanded too, with RegistryKey.GetValue and
// DoNotExpandEnvironmentNames. Where language mode refuses that method, it
// takes the data reg.exe printed, which is unexpanded as well.
//
// .NET returns no data at all for REG_LINK and the resource-list kinds
// (RegistryValueKind.Unknown), so for those the script also emits the hex
// reg.exe prints, and the decoder reads the value's bytes from it.
// REG_RESOURCE_REQUIREMENTS_LIST cannot be read this way: reg.exe does not know
// the type and prints it as REG_NONE, which carries no data on either path.
const getRegistryKeyItemScript = `
$path = %s
$reg = Get-Item ('Registry::' + $path) -ErrorAction Stop
$regExe = $env:SystemRoot + '\System32\reg.exe'
$types = @{}
$regData = @{}
& $regExe query $path 2>$null | ForEach-Object {
  if ($_ -match '^\s{4}(.+?)\s{4}(REG_[A-Z_]+)(?:\s{4}(.*))?$') {
    $types[$matches[1]] = $matches[2]
    $regData[$matches[1]] = $matches[3]
  }
}
$defaultType = $null
$defaultData = $null
if ($reg.Property -contains '(default)') {
  # reg.exe names the default value in the console locale, so it is read
  # through its own query instead of being matched by name.
  & $regExe query $path /ve 2>$null | ForEach-Object {
    if ($_ -match '^\s{4}.+?\s{4}(REG_[A-Z_]+)(?:\s{4}(.*))?$') {
      $defaultType = $matches[1]
      $defaultData = $matches[2]
    }
  }
}
$properties = @()
$reg.Property | ForEach-Object {
    $name = $_
    $fetchKeyValue = $name
    $type = $types[$name]
    $printed = $regData[$name]
    if ("(default)".Equals($name)) {
      $fetchKeyValue = ''
      $type = $defaultType
      $printed = $defaultData
    }
    $data = $(Get-ItemProperty ('Registry::' + $path)).$name;
    if ($data -is [string[]]) {
      $data = $(Get-ItemProperty ('Registry::' + $path)) | Select-Object -ExpandProperty $name
    }
    $kind = $null
    $languageMode = $null
    if ($type -eq $null) {
      try { $kind = $reg.GetValueKind($fetchKeyValue) } catch { $kind = $null }
      if ($kind -eq $null) { $languageMode = [string]$ExecutionContext.SessionState.LanguageMode }
    }
    if ($type -eq 'REG_EXPAND_SZ' -or "$kind" -eq 'ExpandString') {
      try {
        $data = $reg.GetValue($fetchKeyValue, $null, 'DoNotExpandEnvironmentNames')
      } catch {
        if ($printed -ne $null) { $data = $printed }
      }
    }
    $hex = $null
    if ($data -eq $null -and @('REG_LINK', 'REG_RESOURCE_LIST', 'REG_FULL_RESOURCE_DESCRIPTOR') -contains $type) {
      $hex = $printed
    }
    $entry = New-Object psobject -Property @{
      "key" = $name
      "value" = New-Object psobject -Property @{
        "data" = $data;
        "kind" = $kind;
        "type" = $type;
        "languageMode" = $languageMode;
        "hex" = $hex;
      }
    }
    $properties += $entry
}
ConvertTo-Json -Depth 3 -Compress $properties
`

func GetRegistryKeyItemScript(path string) string {
	return fmt.Sprintf(getRegistryKeyItemScript, powershell.SingleQuote(path))
}

// getRegistryKeyChildItemsScript lists the immediate child keys of a registry
// key. The key itself is opened first with -ErrorAction Stop, so a key that is
// refused or missing fails with its error record on stderr, which the resource
// classifies, instead of listing as a key with no children.
const getRegistryKeyChildItemsScript = `
$path = %s
$null = Get-Item ('Registry::' + $path) -ErrorAction Stop
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
