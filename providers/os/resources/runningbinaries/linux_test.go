// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcExe(t *testing.T) {
	out := strings.Join([]string{
		"1\t/usr/lib/systemd/systemd",
		"812\t/usr/sbin/php-fpm8.3",
		"640\t/usr/sbin/php-fpm8.3",
		"901\t/opt/app/server (deleted)",
		"84\t/memfd:collector (deleted)",
		"garbage line",
		"x\t/usr/bin/not-a-pid",
	}, "\n")

	bins, err := parseProcExe(strings.NewReader(out), true)
	require.NoError(t, err)

	require.Len(t, bins, 3)
	// a file that is still at its path is read there
	assert.Equal(t, Binary{Path: "/usr/lib/systemd/systemd", Pids: []int64{1}}, bins[0])
	// one entry per file, pids sorted
	assert.Equal(t, Binary{Path: "/usr/sbin/php-fpm8.3", Pids: []int64{640, 812}}, bins[1])
	// a file replaced on disk is reported at its path, and its contents
	// read through /proc, which still holds the running one
	assert.Equal(t, Binary{Path: "/opt/app/server", ContentPath: "/proc/901/exe", Pids: []int64{901}}, bins[2])
}
