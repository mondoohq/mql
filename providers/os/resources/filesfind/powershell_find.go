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

	// Build the Get-ChildItem command
	script.WriteString("$items = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue")

	// Handle recursion and depth
	if depth != nil {
		if *depth > 0 {
			script.WriteString(" -Recurse -Depth ")
			script.WriteString(strconv.FormatInt(*depth, 10))
		}
		// If depth is 0, don't recurse (only current directory)
	} else {
		// No depth set, recurse without limit
		script.WriteString(" -Recurse")
	}

	script.WriteString("\n")

	// Build filter conditions
	var filters []string

	// Type filter
	if fileType != "" {
		switch fileType {
		case "file", "regular", "f":
			filters = append(filters, "!$_.PSIsContainer")
		case "directory", "dir", "d":
			filters = append(filters, "$_.PSIsContainer")
		case "symlink", "link", "l":
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
