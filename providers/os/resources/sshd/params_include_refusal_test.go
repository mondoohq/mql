// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshd

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Debian 11 to 13 ship /etc/ssh/sshd_config with
// `Include /etc/ssh/sshd_config.d/*.conf`, and a drop-in written with
// mode 0600 cannot be read by a non-root scan. The drop-in below is the one
// that holds the server's Ciphers line, so skipping it dropped every
// cipher and `sshd.config.ciphers.none(_ == /cbc/)` passed on a server that
// allows aes128-cbc.
const debianSshdConfig = `Include /etc/ssh/sshd_config.d/*.conf
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
ClientAliveInterval 120
`

func debianIncludeFixture(readErr error) (fileContentFunc, globExpandFunc) {
	files := map[string]string{
		"/etc/ssh/sshd_config":                   debianSshdConfig,
		"/etc/ssh/sshd_config.d/00-sweep.conf":   "MaxStartups 200:30:300\nMaxSessions 64\n",
		"/etc/ssh/sshd_config.d/00-mqltest.conf": "Ciphers aes128-cbc,aes256-ctr\nPermitRootLogin no\n",
	}
	fileContent := func(path string) (string, error) {
		if path == "/etc/ssh/sshd_config.d/00-mqltest.conf" && readErr != nil {
			return "", readErr
		}
		content, ok := files[path]
		if !ok {
			return "", fs.ErrNotExist
		}
		return content, nil
	}
	globExpand := func(glob string) ([]string, error) {
		if glob == "/etc/ssh/sshd_config.d/*.conf" {
			return []string{"/etc/ssh/sshd_config.d/00-mqltest.conf", "/etc/ssh/sshd_config.d/00-sweep.conf"}, nil
		}
		return []string{glob}, nil
	}
	return fileContent, globExpand
}

func TestParseBlocksWithGlob_UnreadableIncludeIsAnError(t *testing.T) {
	denied := llx.Forbidden(&fs.PathError{Op: "open", Path: "/etc/ssh/sshd_config.d/00-mqltest.conf", Err: fs.ErrPermission})
	fileContent, globExpand := debianIncludeFixture(denied)

	blocks, err := ParseBlocksWithGlob("/etc/ssh/sshd_config", fileContent, globExpand)
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden))
	assert.Nil(t, blocks)
}

func TestParseBlocksWithGlob_UnreadableIncludeInNestedInclude(t *testing.T) {
	denied := llx.Forbidden(errors.New("open /etc/ssh/inner.conf: permission denied"))
	fileContent := func(path string) (string, error) {
		switch path {
		case "/etc/ssh/sshd_config":
			return "Include /etc/ssh/outer.conf\n", nil
		case "/etc/ssh/outer.conf":
			return "Include /etc/ssh/inner.conf\n", nil
		}
		return "", denied
	}
	globExpand := func(glob string) ([]string, error) { return []string{glob}, nil }

	_, err := ParseBlocksWithGlob("/etc/ssh/sshd_config", fileContent, globExpand)
	assert.True(t, errors.Is(err, llx.ErrForbidden))
}

func TestParseBlocksWithGlob_UnlistableIncludeDirIsAnError(t *testing.T) {
	fileContent, _ := debianIncludeFixture(nil)
	globExpand := func(glob string) ([]string, error) {
		if glob == "/etc/ssh/sshd_config.d/*.conf" {
			return nil, llx.Forbidden(errors.New("open /etc/ssh/sshd_config.d: permission denied"))
		}
		return []string{glob}, nil
	}

	_, err := ParseBlocksWithGlob("/etc/ssh/sshd_config", fileContent, globExpand)
	assert.True(t, errors.Is(err, llx.ErrForbidden))
}

// An error that is not a refusal keeps the previous behavior: the include
// is skipped and the rest of the configuration is still reported. v13 scans
// (StructuredErrors off) pass the unclassified permission error through this
// path.
func TestParseBlocksWithGlob_UnclassifiedReadErrorSkipsInclude(t *testing.T) {
	fileContent, globExpand := debianIncludeFixture(&fs.PathError{Op: "open", Path: "/etc/ssh/sshd_config.d/00-mqltest.conf", Err: fs.ErrPermission})

	blocks, err := ParseBlocksWithGlob("/etc/ssh/sshd_config", fileContent, globExpand)
	require.NoError(t, err)
	params := blocks.Flatten()
	assert.Equal(t, "64", params["MaxSessions"])
	assert.NotContains(t, params, "Ciphers")
}

func TestParseBlocksWithGlob_ReadableIncludes(t *testing.T) {
	fileContent, globExpand := debianIncludeFixture(nil)

	blocks, err := ParseBlocksWithGlob("/etc/ssh/sshd_config", fileContent, globExpand)
	require.NoError(t, err)
	params := blocks.Flatten()
	assert.Equal(t, "aes128-cbc,aes256-ctr", params["Ciphers"])
	assert.Equal(t, "64", params["MaxSessions"])
}
