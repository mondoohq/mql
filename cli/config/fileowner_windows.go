// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package config

import "io/fs"

// preserveOwner is a no-op on Windows, which has no uid/gid to carry over and
// where a file's ACL is inherited from the directory it is created in -- the
// same directory the original is in, so the replacement is already governed by
// the same rules.
func preserveOwner(path string, info fs.FileInfo) {}
