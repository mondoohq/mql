// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package selfupdate

// updateRegisteredVersion is a no-op off Windows. Every other platform's
// package manager owns its own metadata and is not expected to track a binary
// that updates itself: apt and yum report what they installed, and Homebrew
// and the tarball record nothing at all.
func updateRegisteredVersion(version string) error {
	return nil
}
