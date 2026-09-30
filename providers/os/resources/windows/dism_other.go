// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package windows

import "errors"

var errDismNotSupported = errors.New("the DISM API is only available on Windows")

// NativeOptionalFeatures is only implemented on Windows; callers reach it only
// behind shared.WindowsNative, which is false elsewhere.
func NativeOptionalFeatures() ([]WindowsOptionalFeature, error) {
	return nil, errDismNotSupported
}

// NativeOptionalFeature is only implemented on Windows.
func NativeOptionalFeature(name string) (WindowsOptionalFeature, bool, error) {
	return WindowsOptionalFeature{}, false, errDismNotSupported
}
