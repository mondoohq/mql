// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build linux || darwin || netbsd || openbsd || freebsd
// +build linux darwin netbsd openbsd freebsd

package windows

// nativeGetHotpatchState is only reached when the scanner runs on Windows.
func nativeGetHotpatchState(arch string) *HotpatchState {
	return &HotpatchState{}
}
