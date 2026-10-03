// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Over SSH the process list comes from ps, which joins argv with spaces.
// flags reads the argv boundaries back from /proc/<pid>/cmdline (RHEL 9).
func TestArgvForCommand(t *testing.T) {
	cmdline := []byte("bash\x00-c\x00sleep 100000; : g04flags\x00--cfg=/etc/x.conf\x00operand1\x00-v\x002\x00--name\x00two words\x00--opt=a b\x00")
	psCommand := "bash -c sleep 100000; : g04flags --cfg=/etc/x.conf operand1 -v 2 --name two words --opt=a b"

	assert.Equal(t,
		[]string{"bash", "-c", "sleep 100000; : g04flags", "--cfg=/etc/x.conf", "operand1", "-v", "2", "--name", "two words", "--opt=a b"},
		argvForCommand(cmdline, psCommand))

	// the pid now belongs to another process than the one ps listed
	assert.Nil(t, argvForCommand(cmdline, "/usr/sbin/sshd -D"))
	// a kernel thread, or a process that exited
	assert.Nil(t, argvForCommand(nil, psCommand))
}
