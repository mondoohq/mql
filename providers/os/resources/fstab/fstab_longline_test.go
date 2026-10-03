// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fstab

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mount reads fstab with getmntent(3), which has no line limit. The entries
// after a long line (a long option list) must still be reported, or a
// nodev/nosuid check passes on a mount it never saw.
func TestParseKeepsEntriesAfterLongLine(t *testing.T) {
	content := "/dev/sda1 / ext4 defaults 0 1\n" +
		"server:/export /mnt/a nfs " + strings.Repeat("x", 70000) + " 0 0\n" +
		"/dev/sdb1 /tmp ext4 defaults 0 2\n"

	entries, err := Parse(strings.NewReader(content))
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, "/tmp", entries[2].Mountpoint)
}

func TestParseReturnsReadError(t *testing.T) {
	_, err := Parse(io.MultiReader(strings.NewReader("/dev/sda1 / ext4 defaults 0 1\n"), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
}
