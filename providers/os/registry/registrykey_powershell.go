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
	err = json.Unmarshal(data, &items)
	return items, err
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
	err = json.Unmarshal(data, &children)
	return children, err
}

// RegistryKeyItem represents a registry key item and its properties
const getRegistryKeyItemScript = `
$path = %s
$reg = Get-Item ('Registry::' + $path)
if ($reg -eq $null) {
  Write-Error "Could not find registry key"
  exit 1
}
$properties = @()
$reg.Property | ForEach-Object {
    $fetchKeyValue = $_
    if ("(default)".Equals($_)) { $fetchKeyValue = '' }
	$data = $(Get-ItemProperty ('Registry::' + $path)).$_;
	$kind = $reg.GetValueKind($fetchKeyValue);
	if ($kind -eq 7) {
      $data = $(Get-ItemProperty ('Registry::' + $path)) | Select-Object -ExpandProperty $_
	}
    $entry = New-Object psobject -Property @{
      "key" = $_
      "value" = New-Object psobject -Property @{
        "data" = $data;
        "kind" = $kind;
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
