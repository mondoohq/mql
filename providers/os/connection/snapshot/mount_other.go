// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !linux

package snapshot

import "errors"

func Mount(attachedFS string, scanDir string, fsType string, opts []string) error {
	return errors.New("unsupported platform")
}

func Unmount(scanDir string) error {
	return errors.New("unsupported platform")
}
