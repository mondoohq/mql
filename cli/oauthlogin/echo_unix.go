// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package oauthlogin

import "golang.org/x/sys/unix"

// keyInput switches the terminal fd to unechoed, key-by-key input: a read
// returns as soon as a key is pressed, so Enter is seen whether the terminal
// sends "\r" or "\n". Signal keys such as Ctrl-C keep working. The change
// applies immediately without discarding pending input. The returned func
// restores the previous settings exactly.
func keyInput(fd int) (func(), error) {
	t, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	old := *t
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON
	t.Lflag |= unix.ISIG
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlWriteTermios, &old) }, nil
}
