// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Drop-in from an Ubuntu 24.04 host, with PermitRootLogin no and a DenyUsers
// line placed under Match only. sshd -T on that host reports permitrootlogin
// without-password, allowtcpforwarding yes, maxsessions 64 and only the two
// global denyusers entries: none of the Match block values are global.
const flattenDropIn = `# test sshd drop-in
ciphers aes256-gcm@openssh.com,aes128-ctr
MACs=hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521
X11Forwarding no
LoginGraceTime 1m
MaxAuthTries 4
DenyUsers mqlt_locked
DenyUsers mqlt_nopw
Match User mqlt_bash
    AllowTcpForwarding no
    MaxSessions 2
    DenyUsers mqlt_bash
Match Address 10.0.0.0/8
    PermitRootLogin no
`

const flattenMain = `Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
MaxStartups 200:30:300
MaxSessions 64
`

func parseInMemory(t *testing.T, files map[string]string, root string) MatchBlocks {
	t.Helper()
	fileContent := func(path string) (string, error) {
		c, ok := files[path]
		if !ok {
			return "", os.ErrNotExist
		}
		return c, nil
	}
	globExpand := func(glob string) ([]string, error) {
		switch glob {
		case "/etc/ssh/sshd_config.d/*.conf":
			return []string{"/etc/ssh/sshd_config.d/50-mqltest.conf", "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"}, nil
		default:
			if _, ok := files[glob]; ok {
				return []string{glob}, nil
			}
			return nil, nil
		}
	}
	blocks, err := ParseBlocksWithGlob(root, fileContent, globExpand)
	require.NoError(t, err)
	return blocks
}

func TestFlattenExcludesMatchBlockValues_Include(t *testing.T) {
	blocks := parseInMemory(t, map[string]string{
		"/etc/ssh/sshd_config":                             flattenMain,
		"/etc/ssh/sshd_config.d/50-mqltest.conf":           flattenDropIn,
		"/etc/ssh/sshd_config.d/60-cloudimg-settings.conf": "PasswordAuthentication no\n",
	}, "/etc/ssh/sshd_config")

	params := blocks.Flatten()

	// Set only under Match: absent from the global view.
	assert.NotContains(t, params, "PermitRootLogin")
	assert.NotContains(t, params, "AllowTcpForwarding")
	// Set globally and under Match: the global value, not the Match one.
	assert.Equal(t, "64", params["MaxSessions"])
	// Multi-value keyword: Match values are not appended to the global list.
	assert.Equal(t, "mqlt_locked,mqlt_nopw", params["DenyUsers"])
	// First value wins across the include, as in sshd -T.
	assert.Equal(t, "no", params["X11Forwarding"])
	assert.Equal(t, "no", params["PasswordAuthentication"])
	assert.Equal(t, "aes256-gcm@openssh.com,aes128-ctr", params["Ciphers"])
	assert.Equal(t, "Address 10.0.0.0/8,User mqlt_bash", params["Match"])

	// The Match block values remain available on their blocks.
	var addr *MatchBlock
	for _, b := range blocks {
		if b.Criteria == "Address 10.0.0.0/8" {
			addr = b
		}
	}
	require.NotNil(t, addr)
	assert.Equal(t, "no", addr.Params["PermitRootLogin"])
}

// Ubuntu 16.04 ships OpenSSH 7.2, which has no Include: the Match blocks are
// appended to sshd_config itself.
func TestFlattenExcludesMatchBlockValues_SingleFile(t *testing.T) {
	cfg := `Port 22
#PermitRootLogin prohibit-password
MaxSessions 64
X11Forwarding yes
Match User mqlt_bash
    AllowTcpForwarding no
    MaxSessions 2
Match Address 10.0.0.0/8
    PermitRootLogin no
`
	blocks := parseInMemory(t, map[string]string{"/etc/ssh/sshd_config": cfg}, "/etc/ssh/sshd_config")
	params := blocks.Flatten()

	assert.NotContains(t, params, "PermitRootLogin")
	assert.NotContains(t, params, "AllowTcpForwarding")
	assert.Equal(t, "64", params["MaxSessions"])
	assert.Equal(t, "yes", params["X11Forwarding"])
}

func TestFlattenNoMatchBlocks(t *testing.T) {
	blocks := parseInMemory(t, map[string]string{"/etc/ssh/sshd_config": "PermitRootLogin no\n"}, "/etc/ssh/sshd_config")
	params := blocks.Flatten()
	assert.Equal(t, map[string]any{"PermitRootLogin": "no"}, params)
	assert.Nil(t, MatchBlocks{}.Flatten())
}
