// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package oauthlogin

import "golang.org/x/sys/unix"

// disableEcho turns off echo on the terminal fd, keeping line input and
// signals, and returns a func that restores the previous settings.
func disableEcho(fd int) (func(), error) {
	t, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	old := *t
	t.Lflag &^= unix.ECHO | unix.ECHONL
	t.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlWriteTermios, &old) }, nil
}
