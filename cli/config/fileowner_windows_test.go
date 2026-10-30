// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package config

import (
	"io/fs"
	"testing"
)

func ownerOf(t *testing.T, info fs.FileInfo) (int, int) {
	t.Helper()
	return -1, -1
}
