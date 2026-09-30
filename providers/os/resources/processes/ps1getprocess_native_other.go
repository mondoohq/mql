// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package processes

// The native process reads exist only in Windows builds; elsewhere the
// PowerShell path answers.
func nativeProcessExists(pid int64) (bool, bool) { return false, false }
func nativeProcess(pid int64) (*OSProcess, bool) { return nil, false }
