// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package resources

// no local counterpart off Windows; callers fall back to PowerShell
func lookupAccountSids(names []string) (map[string]string, bool) {
	return nil, false
}
