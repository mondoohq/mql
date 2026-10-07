// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos || windows)

package oauthlogin

import "errors"

func keyInput(int) (func(), error) {
	return nil, errors.New("terminal input mode cannot be changed on this platform")
}
