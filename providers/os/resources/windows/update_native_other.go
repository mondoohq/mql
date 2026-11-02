// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package windows

import "errors"

// NativeWUAResults reads the Windows Update results natively, which only works
// on Windows; the caller then uses WINDOWS_QUERY_WUA_RESULTS.
func NativeWUAResults() (*WUAResults, error) {
	return nil, errors.New("native Windows Update results are only available on Windows")
}
