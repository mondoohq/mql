// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestWindowsCurlCmdQuotesToken(t *testing.T) {
	// A bare token is parsed as a command name, and the header is never set.
	cmd := windowsCurlCmd("fake-imds-token==", identityURLPath)
	assert.Contains(t, cmd, `"X-aws-ec2-metadata-token" = 'fake-imds-token=='`)

	cmd = windowsCurlCmd("it's", identityURLPath)
	assert.Contains(t, cmd, `"X-aws-ec2-metadata-token" = 'it''s'`)
}

// countingConn counts the commands run through it.
type countingConn struct {
	*mock.Connection
	commands []string
}

func (c *countingConn) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	return c.Connection.RunCommand(command)
}

func TestWindowsIdentifyFetchesTokenOnce(t *testing.T) {
	mconn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance-identity_document_windows.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(mconn)
	require.True(t, ok)

	conn := &countingConn{Connection: mconn}
	ident, err := NewCommandInstanceMetadata(conn, platform, nil).Identify()
	require.NoError(t, err)
	assert.Equal(t, "ec2-name-windows", ident.InstanceName)

	token := windowsTokenCmdString()
	n := 0
	for _, c := range conn.commands {
		if strings.EqualFold(c, token) {
			n++
		}
	}
	assert.Equal(t, 1, n, "the identity document and the name tag share one token")
	assert.Len(t, conn.commands, 3)
}
