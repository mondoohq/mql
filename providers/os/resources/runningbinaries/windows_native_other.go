// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package runningbinaries

// The native Windows reads exist only in Windows builds; elsewhere the
// PowerShell path answers.
func nativeListWindows() ([]Binary, bool) { return nil, false }

func nativeWindowsSignatures(paths []string) map[string]Signature { return nil }

func nativeWindowsInstallerOwners(paths []string) (map[string]string, bool) { return nil, false }
