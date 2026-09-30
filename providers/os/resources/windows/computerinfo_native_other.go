// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package windows

import "errors"

// NativeComputerInfo reads computer info natively, which only works on
// Windows; the caller then uses Get-ComputerInfo.
func NativeComputerInfo() (map[string]any, error) {
	return nil, errors.New("native computer info is only available on Windows")
}

// NativeComputerInfoKeys are the keys NativeComputerInfo sets on Windows.
var NativeComputerInfoKeys = []string{}
