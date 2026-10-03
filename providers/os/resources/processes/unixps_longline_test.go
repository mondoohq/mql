// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

// ps prints the whole command line of every process. Any user can start a
// process whose arguments are longer than 64 KiB; the processes listed
// after it must still be reported.
func TestParseLinuxPsResultKeepsProcessesAfterLongCommand(t *testing.T) {
	out := "  PID %CPU %MEM    VSZ   RSS TT       STAT STIME     TIME   UID COMMAND\n" +
		"    1 0.0  0.1  12124  3232  ?        Ss   07:48   00:00:00     0 /sbin/init\n" +
		" 4100 0.0  0.0   5584  1024  ?        S    07:50   00:00:00  1000 sleep " + strings.Repeat("a", 70000) + "\n" +
		" 4101 0.0  0.0   5584  1024  ?        S    07:50   00:00:00  1000 /tmp/miner --pool example\n"

	m, err := processes.ParseLinuxPsResult(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, int64(4101), m[2].Pid)
	assert.Equal(t, "/tmp/miner --pool example", m[2].Command)
}

func TestParseUnixPsResultKeepsProcessesAfterLongCommand(t *testing.T) {
	out := "  PID  %CPU %MEM   VSZ  RSS TTY   STAT     TIME  UID COMMAND\n" +
		"    1   0.0  0.2 10056 1052 -     ILs   0:00.01    0 /sbin/init --\n" +
		"  900   0.0  0.2 10056 1052 -     S     0:00.01 1001 sleep " + strings.Repeat("a", 70000) + "\n" +
		"  901   0.0  0.2 10056 1052 -     S     0:00.01 1001 /tmp/miner\n"

	m, err := processes.ParseUnixPsResult(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, int64(901), m[2].Pid)
}

func TestParseAixPsResultKeepsProcessesAfterLongCommand(t *testing.T) {
	out := "     PID  %CPU  %MEM   VSZ     TT        TIME UID COMMAND\n" +
		"       1   0.0   0.0   792      -    00:00:00   0 /etc/init\n" +
		"    9000   0.0   0.0   792      -    00:00:00 201 sleep " + strings.Repeat("a", 70000) + "\n" +
		"    9001   0.0   0.0   792      -    00:00:00 201 /tmp/miner\n"

	m, err := processes.ParseAixPsResult(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, int64(9001), m[2].Pid)
}

// A ps output that cannot be read to the end must fail the list rather than
// report the processes read so far as all of them.
func TestParsePsResultReturnsReadError(t *testing.T) {
	head := "  PID %CPU %MEM    VSZ   RSS TT       STAT STIME     TIME   UID COMMAND\n" +
		"    1 0.0  0.1  12124  3232  ?        Ss   07:48   00:00:00     0 /sbin/init\n"
	_, err := processes.ParseLinuxPsResult(io.MultiReader(strings.NewReader(head), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
	_, err = processes.ParseUnixPsResult(io.MultiReader(strings.NewReader(head), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
	_, err = processes.ParseAixPsResult(io.MultiReader(strings.NewReader(head), iotest.ErrReader(errors.New("boom"))))
	assert.Error(t, err)
}
