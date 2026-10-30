// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package scp

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Connection.FileInfo probes for an Lstat method and, when it finds one, uses it
// as the primary call with no fallback. This filesystem cannot lstat, so it must
// not advertise the method: doing so made every stat fail with "lstat not
// implemented" on any SSH target without an sftp subsystem - Oracle Solaris
// 11.4 ships sshd with no Subsystem line at all - instead of falling through to
// Stat, which works.
func TestFsDoesNotAdvertiseLstat(t *testing.T) {
	type lstater interface {
		Lstat(string) (os.FileInfo, error)
	}

	var fs any = Fs{}
	_, ok := fs.(lstater)
	assert.False(t, ok, "scp Fs must not satisfy the lstat probe in Connection.FileInfo")

	var pfs any = &Fs{}
	_, ok = pfs.(lstater)
	assert.False(t, ok, "*scp.Fs must not satisfy the lstat probe either")
}
