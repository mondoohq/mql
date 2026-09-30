// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package networkinterface

// List detects network routes on Windows from a scanner that is not itself
// Windows: the native API is not available, so the target is asked through
// PowerShell and netstat.
func (w *windowsRouteDetector) List() ([]Route, error) {
	return w.listViaCommands()
}
