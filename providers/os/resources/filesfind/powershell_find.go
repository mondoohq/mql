// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// powershellFindWalk walks from $Path with the .NET directory API.
// Get-ChildItem -Recurse lists every directory twice, sorts every listing and
// wraps each entry in a PowerShell object; here only matches are kept.
// Like find, depth 0 is $Path alone and depth 1 adds its entries. $Path is
// always searched; below it, junctions and symbolic links are reported but
// not entered, while other reparse points, such as OneDrive placeholders,
// are. A directory whose name matches an $Exclude glob is neither reported
// nor entered.
const powershellFindWalk = `$out = [Collections.Generic.List[string]]::new()
$todo = [Collections.Generic.Stack[object]]::new()
$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.BaseObject })
$lv = 0
while ($true) {
  foreach ($e in $items) {
    $dir = $e -is [IO.DirectoryInfo]
    if ($dir -and $lv -gt 0) {
      $skip = $false
      foreach ($x in $Exclude) { if ($e.Name -like $x) { $skip = $true; break } }
      if ($skip) { continue }
    }
    if (%s) { $out.Add($e.FullName) }
    if ($dir -and ($MaxDepth -lt 0 -or $lv -lt $MaxDepth) -and ($lv -eq 0 -or -not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @('Junction', 'SymbolicLink') -notcontains $e.LinkType)) { $todo.Push(@($e, $lv)) }
  }
  if ($todo.Count -eq 0) { break }
  $d, $lv = $todo.Pop()
  $lv++
  try { $items = @($d.EnumerateDirectories()) + @($d.EnumerateFiles($Pattern)) } catch { $items = @() }
}
$out.Sort([StringComparer]::OrdinalIgnoreCase)
$out
`

// BuildPowershellCmd builds the PowerShell script of a files.find search.
// xdev is not applied: the walk never enters a junction, which is how another
// volume is mounted into a directory.
func BuildPowershellCmd(from string, xdev bool, fileType string, regex string, permission int64, search string, depth *int64, exclude []string) string {
	var script strings.Builder

	// ensure we strip any \n and \r since those are not allowed for paths
	from = strings.ReplaceAll(from, "\n", " ")
	from = strings.ReplaceAll(from, "\r", " ")

	script.WriteString("$Path = " + powershell.SingleQuote(from) + "\n")

	var filters []string
	switch fileType {
	case "file", "regular":
		filters = append(filters, "-not $dir")
	case "directory", "dir":
		filters = append(filters, "$dir")
	case "symlink", "link":
		filters = append(filters, "$null -ne $e.LinkType")
		// socket, block, char and fifo don't exist on Windows
	}

	// The file system API matches the files' names, so the ones that don't
	// match are never listed. Its wildcards also match 8.3 short names and
	// know no [] ranges or ` escapes, so -like decides, and a name using
	// those lists every file.
	pattern := "'*'"
	if search != "" {
		script.WriteString("$SearchName = " + powershell.SingleQuote(search) + "\n")
		filters = append(filters, "$e.Name -like $SearchName")
		if !strings.ContainsAny(search, "[]`") {
			pattern = "$SearchName"
		}
	}
	script.WriteString("$Pattern = " + pattern + "\n")

	if regex != "" {
		script.WriteString("$RegexPattern = " + powershell.SingleQuote(regex) + "\n")
		filters = append(filters, "$e.FullName -match $RegexPattern")
	}

	if permission != 0 && permission != 0o777 {
		filters = append(filters, buildWindowsPermissionFilter(permission))
	}

	quoted := make([]string, len(exclude))
	for i := range exclude {
		quoted[i] = powershell.SingleQuote(exclude[i])
	}
	script.WriteString("$Exclude = @(" + strings.Join(quoted, ", ") + ")\n")

	maxDepth := int64(-1)
	if depth != nil {
		maxDepth = max(*depth, 0)
	}
	script.WriteString("$MaxDepth = " + strconv.FormatInt(maxDepth, 10) + "\n")

	filter := "$true"
	if len(filters) > 0 {
		filter = strings.Join(filters, " -and ")
	}
	script.WriteString(strings.Replace(powershellFindWalk, "%s", filter, 1))
	return script.String()
}

// buildWindowsPermissionFilter maps the owner write bit onto the read-only
// attribute. A directory has no IsReadOnly and never matches.
func buildWindowsPermissionFilter(unixPerms int64) string {
	if unixPerms&0o200 == 0 {
		return "$e.IsReadOnly -eq $true"
	}
	return "$e.IsReadOnly -eq $false"
}
