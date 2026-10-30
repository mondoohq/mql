// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWindowsPowershellCmdGeneration(t *testing.T) {
	depth1 := int64(1)
	depth5 := int64(5)
	depth0 := int64(0)
	depth2 := int64(2)

	tests := []struct {
		TestTitle   string
		From        string
		Xdev        bool
		FileType    string
		Regex       string
		Permission  int64
		Search      string
		Depth       *int64
		ExpectedCmd string
	}{
		{
			TestTitle: "basic file search",
			From:      "C:\\Users\\john\\.aws",
			FileType:  "file",
			ExpectedCmd: `$Path = @'
C:\Users\john\.aws
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items = $items | Where-Object { !$_.PSIsContainer }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "directory search with depth",
			From:      "C:\\Program Files",
			FileType:  "directory",
			Depth:     &depth1,
			ExpectedCmd: `$Path = @'
C:\Program Files
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
}
$items = $items | Where-Object { $_.PSIsContainer }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "search with TestTitle pattern",
			From:      "C:\\Windows",
			Search:    "*.log",
			ExpectedCmd: `$Path = @'
C:\Windows
'@

$SearchName = @'
*.log
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items = $items | Where-Object { $_.Name -like $SearchName }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "search with regex",
			From:      "C:\\Logs",
			Regex:     ".*\\.log$",
			ExpectedCmd: `$Path = @'
C:\Logs
'@

$RegexPattern = @'
.*\.log$
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items = $items | Where-Object { $_.FullName -match $RegexPattern }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle:  "search with read-only permission",
			From:       "C:\\Data",
			Permission: 0o555, // no write permissions
			ExpectedCmd: `$Path = @'
C:\Data
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items = $items | Where-Object { $_.IsReadOnly -eq $true }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle:  "search with writable permission",
			From:       "C:\\Data",
			Permission: 0o755, // has write permissions
			ExpectedCmd: `$Path = @'
C:\Data
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items = $items | Where-Object { $_.IsReadOnly -eq $false }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "symlink search",
			From:      "C:\\Links",
			FileType:  "symlink",
			ExpectedCmd: `$Path = @'
C:\Links
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items = $items | Where-Object { $_.LinkType -ne $null }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "depth 0 is the path alone",
			From:      "C:\\Temp",
			Depth:     &depth0,
			ExpectedCmd: `$Path = @'
C:\Temp
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "depth 2 walks the entries and theirs",
			From:      "C:\\mqltest",
			Depth:     &depth2,
			ExpectedCmd: `$Path = @'
C:\mqltest
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse -Depth 1)
}
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "combined filters - file type, search, and depth",
			From:      "C:\\Projects",
			FileType:  "file",
			Search:    "*.go",
			Depth:     &depth5,
			ExpectedCmd: `$Path = @'
C:\Projects
'@

$SearchName = @'
*.go
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse -Depth 4)
}
$items = $items | Where-Object { !$_.PSIsContainer -and $_.Name -like $SearchName }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle:  "all filters combined",
			From:       "C:\\Source",
			FileType:   "file",
			Search:     "*.txt",
			Regex:      ".*test.*",
			Permission: 0o644,
			Depth:      &depth1,
			ExpectedCmd: `$Path = @'
C:\Source
'@

$SearchName = @'
*.txt
'@

$RegexPattern = @'
.*test.*
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
}
$items = $items | Where-Object { !$_.PSIsContainer -and $_.Name -like $SearchName -and $_.FullName -match $RegexPattern -and $_.IsReadOnly -eq $false }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "path with special characters",
			From:      "C:\\Users\\john's folder\\data",
			ExpectedCmd: `$Path = @'
C:\Users\john's folder\data
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "regex with special characters",
			From:      "C:\\Data",
			Regex:     ".*[0-9]{4}-[0-9]{2}-[0-9]{2}.*",
			ExpectedCmd: `$Path = @'
C:\Data
'@

$RegexPattern = @'
.*[0-9]{4}-[0-9]{2}-[0-9]{2}.*
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items = $items | Where-Object { $_.FullName -match $RegexPattern }
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle:  "permission 0777 (should be ignored)",
			From:       "C:\\Data",
			Permission: 0o777,
			ExpectedCmd: `$Path = @'
C:\Data
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items | Select-Object -ExpandProperty FullName
`,
		},
		{
			TestTitle: "node modules search",
			From:      "C:\\Users",
			Search:    "package.json",
			Regex:     "^(?!.*node_modules).*$", // exclude node_modules
			ExpectedCmd: `$Path = @'
C:\Users
'@

$SearchName = @'
package.json
'@

$RegexPattern = @'
^(?!.*node_modules).*$
'@

$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue -Recurse)
}
$items = $items | Where-Object { $_.Name -like $SearchName -and $_.FullName -match $RegexPattern }
$items | Select-Object -ExpandProperty FullName
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.TestTitle, func(t *testing.T) {
			cmd := BuildPowershellCmd(tt.From, tt.Xdev, tt.FileType, tt.Regex, tt.Permission, tt.Search, tt.Depth)
			assert.Equal(t, tt.ExpectedCmd, cmd)
		})
	}
}
