// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package oauthlogin

import "golang.org/x/sys/windows"

// disableEcho turns off echo on the console input handle fd, keeping line
// input, and returns a func that restores the previous mode.
func disableEcho(fd int) (func(), error) {
	h := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, nil
}
