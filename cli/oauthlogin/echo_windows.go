// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package oauthlogin

import "golang.org/x/sys/windows"

// keyInput switches the console input handle fd to unechoed, key-by-key
// input; Ctrl-C keeps working. The returned func restores the previous mode.
func keyInput(fd int) (func(), error) {
	h := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return nil, err
	}
	keys := mode&^(windows.ENABLE_ECHO_INPUT|windows.ENABLE_LINE_INPUT) | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(h, keys); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, nil
}
