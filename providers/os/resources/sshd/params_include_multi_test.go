// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sshd accumulates AcceptEnv, AllowUsers, DenyUsers, AllowGroups, DenyGroups,
// HostKey, Port and ListenAddress across every line that sets them, in every
// included file. The layout is RHEL 9's: sshd_config includes
// sshd_config.d/*.conf before its own settings.
func TestSSHParseMultiValueAcrossIncludes(t *testing.T) {
	files := map[string]string{
		"/etc/ssh/sshd_config": `Include /etc/ssh/sshd_config.d/*.conf
AuthorizedKeysFile	.ssh/authorized_keys
AcceptEnv LANG
DenyUsers carol
PermitRootLogin yes
`,
		"/etc/ssh/sshd_config.d/00-mqltest.conf": `AcceptEnv MQLONE
AcceptEnv MQLTWO
DenyUsers mallory
AllowGroups wheel
PermitRootLogin no
Match User mqlt_bash
    AllowGroups sftp
`,
		"/etc/ssh/sshd_config.d/50-redhat.conf": `port 22
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ecdsa_key
DenyUsers eve
AllowGroups admins
Match User mqlt_bash
    AllowGroups backup
`,
	}
	fileContent := func(p string) (string, error) {
		c, ok := files[p]
		if !ok {
			return "", errors.New("no such file " + p)
		}
		return c, nil
	}
	globExpand := func(glob string) ([]string, error) {
		if glob == "/etc/ssh/sshd_config.d/*.conf" {
			return []string{"/etc/ssh/sshd_config.d/00-mqltest.conf", "/etc/ssh/sshd_config.d/50-redhat.conf"}, nil
		}
		return []string{glob}, nil
	}

	blocks, err := ParseBlocksWithGlob("/etc/ssh/sshd_config", fileContent, globExpand)
	require.NoError(t, err)

	var global, matchUser *MatchBlock
	for _, b := range blocks {
		switch b.Criteria {
		case "":
			global = b
		case "User mqlt_bash":
			matchUser = b
		}
	}
	require.NotNil(t, global)
	require.NotNil(t, matchUser)

	assert.Equal(t, "MQLONE,MQLTWO,LANG", global.Params["AcceptEnv"])
	assert.Equal(t, "mallory,eve,carol", global.Params["DenyUsers"])
	assert.Equal(t, "wheel,admins", global.Params["AllowGroups"])
	assert.Equal(t, "/etc/ssh/ssh_host_rsa_key,/etc/ssh/ssh_host_ecdsa_key", global.Params["HostKey"])
	// single-value keywords: the first one sshd reads wins
	assert.Equal(t, "no", global.Params["PermitRootLogin"])
	// Match blocks with the same criteria in two included files accumulate too
	assert.Equal(t, "sftp,backup", matchUser.Params["AllowGroups"])
}
