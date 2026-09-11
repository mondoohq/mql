// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package sysproxy

import (
	"errors"
	"net/url"
)

// detect reports no settings. Only Windows keeps a system-wide proxy that
// programs are expected to honor and exposes it through a stable API. macOS
// has one too, in System Settings; reading it would slot in here.
func detect() (*Settings, error) {
	return nil, nil
}

// evaluateScript is never reached without settings; it exists so the selector
// compiles identically on every platform.
func evaluateScript(*Settings, *url.URL) scriptResult {
	return scriptResult{err: errors.New("proxy setup scripts are not supported on this platform")}
}
