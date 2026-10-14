// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"strconv"
	"strings"
)

func BuildPowershellCmd(from string, xdev bool, fileType string, regex string, permission int64, search string, depth *int64) string {
	var script strings.Builder

	// ensure we strip any \n and \r since those are not allowed for paths
	from = strings.ReplaceAll(from, "\n", " ")
	from = strings.ReplaceAll(from, "\r", " ")

	// Use here-strings to safely embed all user input
	script.WriteString("$Path = @'\n")
	script.WriteString(from)
	script.WriteString("\n'@\n\n")

	if search != "" {
		script.WriteString("$SearchName = @'\n")
		script.WriteString(search)
		script.WriteString("\n'@\n\n")
	}

	if regex != "" {
		script.WriteString("$RegexPattern = @'\n")
		script.WriteString(regex)
		script.WriteString("\n'@\n\n")
	}

	// Like find, the search starts with the path itself and then walks what
	// is below it, depth levels deep: depth 0 is the path alone, depth 1 adds
	// its entries. Get-ChildItem counts differently: without -Recurse it lists
	// the entries, and -Depth N goes N levels below them, so depth N is
	// -Depth N-1. It also lists a file given as the path, which is why only a
	// directory is walked.
	script.WriteString("$items = @(Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue)\n")
	if depth == nil || *depth > 0 {
		script.WriteString("if ($items.Count -eq 1 -and $items[0].PSIsContainer) {\n")
		script.WriteString("  $items += @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue")
		if depth == nil {
			script.WriteString(" -Recurse")
		} else if *depth > 1 {
			script.WriteString(" -Recurse -Depth ")
			script.WriteString(strconv.FormatInt(*depth-1, 10))
		}
		script.WriteString(")\n}\n")
	}

	// Build filter conditions
	var filters []string

	// Type filter
	if fileType != "" {
		switch fileType {
		case "file", "regular":
			filters = append(filters, "!$_.PSIsContainer")
		case "directory", "dir":
			filters = append(filters, "$_.PSIsContainer")
		case "symlink", "link":
			filters = append(filters, "$_.LinkType -ne $null")
			// Note: socket, block, char, fifo don't exist in Windows
		}
	}

	// Name filter (exact match or wildcard pattern)
	if search != "" {
		filters = append(filters, "$_.Name -like $SearchName")
	}

	// Regex filter
	if regex != "" {
		filters = append(filters, "$_.FullName -match $RegexPattern")
	}

	// Permissions filter
	if permission != 0 && permission != 0o777 {
		permFilter := buildWindowsPermissionFilter(permission)
		filters = append(filters, permFilter)
	}

	// Apply filters if any exist
	if len(filters) > 0 {
		script.WriteString("$items = $items | Where-Object { ")
		script.WriteString(strings.Join(filters, " -and "))
		script.WriteString(" }\n")
	}

	// Output full paths
	script.WriteString("$items | Select-Object -ExpandProperty FullName\n")

	return script.String()
}

func buildWindowsPermissionFilter(unixPerms int64) string {
	// Map Unix permissions to Windows attributes (simplified)
	// Owner write bit (0o200)
	if unixPerms&0o200 == 0 {
		// No write permission = read-only
		return "$_.IsReadOnly -eq $true"
	} else {
		// Has write permission = not read-only
		return "$_.IsReadOnly -eq $false"
	}
}
