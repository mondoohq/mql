// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The testdata/cmdline-*.bin files are /proc/<pid>/cmdline of the listening
// sshd (pid from /var/run/sshd.pid), copied byte for byte from EC2 hosts.
func readCmdline(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return data
}

func TestParseDaemonCommandLine_RHEL8CryptoPolicy(t *testing.T) {
	// RHEL 8.10, openssh-server-8.0p1: sshd.service runs
	// `sshd -D $OPTIONS $CRYPTO_POLICY` with the DEFAULT policy.
	res, ok := ParseDaemonCommandLine(readCmdline(t, "cmdline-rhel8.bin"))
	require.True(t, ok)
	assert.Equal(t, "", res.ConfigFile)
	require.Len(t, res.Options, 7)
	assert.Equal(t, "Ciphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc", res.Options[0])
	assert.Equal(t, "MACs=hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512", res.Options[1])
	assert.Equal(t, "CASignatureAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ssh-rsa", res.Options[6])
}

func TestParseDaemonCommandLine_SeparateOptionArguments(t *testing.T) {
	// AlmaLinux 8 with EC2 Instance Connect: -o and its value are separate
	// argv entries and the value holds spaces.
	res, ok := ParseDaemonCommandLine(readCmdline(t, "cmdline-alma8.bin"))
	require.True(t, ok)
	assert.Equal(t, []string{
		"AuthorizedKeysCommand /opt/aws/bin/eic_run_authorized_keys %u %f",
		"AuthorizedKeysCommandUser ec2-instance-connect",
	}, res.Options)
}

func TestParseDaemonCommandLine_ListenerTitle(t *testing.T) {
	// Fedora 44: the listener rewrote argv into one process title. The
	// AuthorizedKeysCommand value has spaces and cannot be recovered.
	res, ok := ParseDaemonCommandLine(readCmdline(t, "cmdline-fed44.bin"))
	require.True(t, ok)
	assert.Empty(t, res.Options)

	// RHEL 9: no options at all.
	res, ok = ParseDaemonCommandLine(readCmdline(t, "cmdline-rhel9.bin"))
	require.True(t, ok)
	assert.Empty(t, res.Options)
	assert.Equal(t, "", res.ConfigFile)

	// algorithm lists in a title are kept, other options are not
	title := "sshd: /usr/sbin/sshd -D -oCiphers=aes128-cbc,aes256-ctr -o MACs=hmac-sha1 -o Banner=/etc/issue -f /etc/ssh/alt_config [listener] 0 of 10-100 startups\x00"
	res, ok = ParseDaemonCommandLine([]byte(title))
	require.True(t, ok)
	assert.Equal(t, []string{"Ciphers=aes128-cbc,aes256-ctr", "MACs=hmac-sha1"}, res.Options)
	assert.Equal(t, "/etc/ssh/alt_config", res.ConfigFile)
}

func TestParseDaemonCommandLine_FlagArguments(t *testing.T) {
	// -p takes an argument, so "-oX" after it is still an option and the
	// port is not; -De is a cluster of flags without arguments.
	cmdline := "/usr/sbin/sshd\x00-De\x00-p\x002222\x00-f/etc/ssh/custom\x00-o\x00Ciphers=aes256-ctr\x00"
	res, ok := ParseDaemonCommandLine([]byte(cmdline))
	require.True(t, ok)
	assert.Equal(t, "/etc/ssh/custom", res.ConfigFile)
	assert.Equal(t, []string{"Ciphers=aes256-ctr"}, res.Options)

	// a trailing -o without a value is ignored
	res, ok = ParseDaemonCommandLine([]byte("/usr/sbin/sshd\x00-D\x00-o\x00"))
	require.True(t, ok)
	assert.Empty(t, res.Options)
}

func TestParseDaemonCommandLine_NotSshd(t *testing.T) {
	for _, cmdline := range []string{
		"",
		"/usr/bin/bash\x00-c\x00sleep 1\x00",
		"/usr/sbin/sshd-session\x00-R\x00",
		"sshd: ec2-user [priv]\x00",
	} {
		_, ok := ParseDaemonCommandLine([]byte(cmdline))
		assert.False(t, ok, "%q", cmdline)
	}
}

func TestParseDaemonCommandLine_ListenerTitleSpaceForm(t *testing.T) {
	// Fedora 44 with `-o "Ciphers aes128-cbc,aes256-ctr,aes128-ctr"` added to
	// the EC2 Instance Connect ExecStart: in the title the keyword and its
	// list are separate fields.
	res, ok := ParseDaemonCommandLine(readCmdline(t, "cmdline-fed44-space.bin"))
	require.True(t, ok)
	assert.Equal(t, []string{"Ciphers=aes128-cbc,aes256-ctr,aes128-ctr"}, res.Options)

	// the keyword glued to -o, any case, and a list that removes algorithms
	title := "sshd: /usr/sbin/sshd -D -oMACs hmac-sha1 -o kexalgorithms -diffie-hellman-group1-sha1 -o Banner /etc/issue [listener] 0 of 10-100 startups\x00"
	res, ok = ParseDaemonCommandLine([]byte(title))
	require.True(t, ok)
	assert.Equal(t, []string{"MACs=hmac-sha1", "kexalgorithms=-diffie-hellman-group1-sha1"}, res.Options)

	// a keyword at the very end of the title has no list to join
	res, ok = ParseDaemonCommandLine([]byte("sshd: /usr/sbin/sshd -D -o Ciphers [listener] 0 of 10-100 startups\x00"))
	require.True(t, ok)
	assert.Empty(t, res.Options)
}
