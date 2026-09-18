// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows
// +build !windows

package config

import (
	"io/fs"
	"os"
	"syscall"
)

// preserveOwner gives path the owner and group of info.
//
// A config written by replacing the file takes the writing process's ownership,
// not the original's. mondoo.yml carries the service account's private key, so
// it is routinely mode 0600 owned by the account the agent runs as -- and an
// admin running the migration under sudo would hand that file to root and leave
// the agent unable to read its own config.
//
// Best effort: an unprivileged process cannot chown to another user, but in that
// case it is not changing the owner either, because it could only have written a
// file it already owned.
func preserveOwner(path string, info fs.FileInfo) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = os.Chown(path, int(stat.Uid), int(stat.Gid))
}
