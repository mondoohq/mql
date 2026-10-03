// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package procfs

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseProcessStatus(t *testing.T) {
	trans, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/process-pid1.toml"))
	require.NoError(t, err)

	f, err := trans.FileSystem().Open("/proc/1/status")
	require.NoError(t, err)
	defer f.Close()

	processStatus, err := ParseProcessStatus(f)
	require.NoError(t, err)

	assert.NotNil(t, processStatus, "process is not nil")
	assert.Equal(t, "bash", processStatus.Executable, "detected process name")
}

func TestParseProcessStatus_PidAndPPidDistinct(t *testing.T) {
	// Pid and PPid must be parsed into their own fields; previously the PPid
	// line was written into Pid, corrupting Pid and leaving PPid at 0.
	status := "Name:\tsshd\n" +
		"State:\tS (sleeping)\n" +
		"Tgid:\t4242\n" +
		"Ngid:\t0\n" +
		"Pid:\t4242\n" +
		"PPid:\t1\n"

	processStatus, err := ParseProcessStatus(bytes.NewBufferString(status))
	require.NoError(t, err)
	require.NotNil(t, processStatus)

	assert.Equal(t, int64(4242), processStatus.Pid, "Pid keeps the process id")
	assert.Equal(t, int64(1), processStatus.PPid, "PPid holds the parent process id")
}

func TestParseProcessCmdline(t *testing.T) {
	trans, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/process-pid1.toml"))
	require.NoError(t, err)

	f, err := trans.FileSystem().Open("/proc/1/cmdline")
	require.NoError(t, err)
	defer f.Close()

	cmd, err := ParseProcessCmdline(f)
	require.NoError(t, err)
	assert.Equal(t, "/bin/bash", cmd, "detected process name")
}

func TestParseProcessCmdline_Direct(t *testing.T) {
	testCases := []struct {
		name           string
		inputBytes     []byte
		expectedOutput string
	}{
		{
			name:           "single argument with trailing null",
			inputBytes:     []byte("/bin/bash\x00"), // \x00 is the null byte
			expectedOutput: "/bin/bash",
		},
		{
			name:           "multiple arguments with trailing null",
			inputBytes:     []byte("/usr/bin/my-app\x00--option\x00value\x00"),
			expectedOutput: "/usr/bin/my-app --option value",
		},
		{
			name:           "argument with spaces, then trailing null",
			inputBytes:     []byte("/usr/bin/app with spaces\x00-arg\x00"),
			expectedOutput: "/usr/bin/app with spaces -arg",
		},
		{
			name:           "empty cmdline (just a null terminator, e.g., kernel thread)",
			inputBytes:     []byte("\x00"),
			expectedOutput: "",
		},
		{
			name:           "double null (empty argument in middle) then trailing null",
			inputBytes:     []byte("arg1\x00\x00arg3\x00"),
			expectedOutput: "arg1 arg3",
		},
		{
			name:           "cmdline without trailing null (less common, but good to test)",
			inputBytes:     []byte("/bin/no-null"),
			expectedOutput: "/bin/no-null",
		},
		{
			name:           "empty input",
			inputBytes:     []byte{},
			expectedOutput: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.inputBytes)
			cmd, err := ParseProcessCmdline(reader)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, cmd)
		})
	}
}

func TestParseProcessArgv(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
		argv  []string
	}{
		{
			// /proc/<pid>/cmdline captured on RHEL 9 for
			// python3 -c '...' --cfg=/etc/x.conf operand1 -v 2 --name 'two words' --opt='a b'
			name:  "arguments with spaces stay whole",
			input: []byte("python3\x00-c\x00import time; time.sleep(100000)\x00--cfg=/etc/x.conf\x00operand1\x00-v\x002\x00--name\x00two words\x00--opt=a b\x00"),
			argv:  []string{"python3", "-c", "import time; time.sleep(100000)", "--cfg=/etc/x.conf", "operand1", "-v", "2", "--name", "two words", "--opt=a b"},
		},
		{
			// sshd rewrites its title into one NUL-terminated string (RHEL 9)
			name:  "process title rewritten into one string",
			input: []byte("sshd: /usr/sbin/sshd -D [listener] 0 of 200-300 startups\x00"),
			argv:  []string{"sshd: /usr/sbin/sshd -D [listener] 0 of 200-300 startups"},
		},
		{
			name:  "an empty argument in the middle is kept",
			input: []byte("app\x00--name\x00\x00--x\x00"),
			argv:  []string{"app", "--name", "", "--x"},
		},
		{
			name:  "padding after a rewritten title is dropped",
			input: []byte("postgres: checkpointer \x00\x00\x00"),
			argv:  []string{"postgres: checkpointer "},
		},
		{
			name:  "kernel thread",
			input: []byte{},
			argv:  nil,
		},
		{
			name:  "no trailing NUL",
			input: []byte("/bin/no-null"),
			argv:  []string{"/bin/no-null"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.argv, ParseProcessArgv(tc.input))
		})
	}
}
