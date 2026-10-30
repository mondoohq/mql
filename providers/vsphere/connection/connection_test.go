// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/vsphere/connection/vsimulator"
)

func TestVSphereTransport(t *testing.T) {
	vs, err := vsimulator.New()
	require.NoError(t, err)
	defer vs.Close()

	port := vs.Server.URL.Port()
	portNum, err := strconv.Atoi(port)
	require.NoError(t, err)

	conn, err := NewVsphereConnection(
		1,
		&inventory.Asset{},
		&inventory.Config{
			Type:     "vsphere",
			Host:     vs.Server.URL.Hostname(),
			Port:     int32(portNum),
			Insecure: true, // allows self-signed certificates
			Credentials: []*vault.Credential{
				{
					Type:   vault.CredentialType_password,
					User:   vsimulator.Username,
					Secret: []byte(vsimulator.Password),
				},
			},
		})
	require.NoError(t, err)

	ver := conn.Client().ServiceContent.About
	assert.Equal(t, "6.5", ver.ApiVersion)
}
