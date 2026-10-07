// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package config

import (
	"fmt"
	"os"
)

// restrictToOwner sets f's mode to 0600 and checks that the file system kept
// it: some file systems accept chmod without applying it.
func restrictToOwner(f *os.File) error {
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("the file system keeps mode %#o instead of 0600", perm)
	}
	return nil
}
