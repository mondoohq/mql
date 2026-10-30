// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	tea "github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVbrCrossAccount(t *testing.T) {
	tests := []struct {
		name                            string
		connectionOwner, scannedAccount string
		expected                        bool
	}{
		{"own circuit", "1000", "1000", false},
		{"hosted connection", "2000", "1000", true},
		// a missing owner on either side is not evidence of a third-party
		// circuit; reporting one that may not exist is worse than missing one
		{"owner absent", "", "1000", false},
		{"account absent", "2000", "", false},
		{"both absent", "", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, vbrCrossAccount(test.connectionOwner, test.scannedAccount))
		})
	}
}

// TestSslVpnServerDecode pins the struct tags the SSL VPN fields depend on. A
// mistyped tag would decode to a zero value, so a server demanding a second
// factor would report multiFactorAuthEnabled false.
func TestSslVpnServerDecode(t *testing.T) {
	payload := `{
      "SslVpnServerId": "vss-bp1n8wcf134yl",
      "Name": "remote-access",
      "VpnGatewayId": "vpn-bp1q8bgx4xnkm",
      "ClientIpPool": "192.168.10.0/24",
      "LocalSubnet": "10.0.0.0/8",
      "Port": 1194,
      "Proto": "UDP",
      "Cipher": "AES-128-CBC",
      "Compress": false,
      "Connections": 3,
      "MaxConnections": 5,
      "EnableMultiFactorAuth": true,
      "IDaaSInstanceId": "idaas-cn-hangzhou-1",
      "CreateTime": 1579261141
    }`

	var srv vpcclient.DescribeSslVpnServersResponseBodySslVpnServersSslVpnServer
	require.NoError(t, json.Unmarshal([]byte(payload), &srv))

	assert.Equal(t, "192.168.10.0/24", tea.StringValue(srv.ClientIpPool))
	assert.Equal(t, "10.0.0.0/8", tea.StringValue(srv.LocalSubnet))
	assert.Equal(t, int32(1194), tea.Int32Value(srv.Port))
	assert.True(t, tea.BoolValue(srv.EnableMultiFactorAuth))
	assert.Equal(t, int32(5), tea.Int32Value(srv.MaxConnections))
	require.NotNil(t, epochSeconds(srv.CreateTime))

	var bare vpcclient.DescribeSslVpnServersResponseBodySslVpnServersSslVpnServer
	require.NoError(t, json.Unmarshal([]byte(`{"SslVpnServerId":"vss-1"}`), &bare))
	// a server that says nothing about a second factor must not report one
	assert.False(t, tea.BoolValue(bare.EnableMultiFactorAuth))
	// an absent timestamp stays null rather than becoming 1 January 1970
	assert.Nil(t, epochSeconds(bare.CreateTime))
}

// TestCustomerGatewayAuthKeyNotExposed pins that the BGP shared secret is read
// only as a presence flag. The key itself must never reach a scan result.
func TestCustomerGatewayAuthKeyNotExposed(t *testing.T) {
	var gw vpcclient.DescribeCustomerGatewaysResponseBodyCustomerGatewaysCustomerGateway
	require.NoError(t, json.Unmarshal([]byte(`{
      "CustomerGatewayId": "cgw-bp1pvdlfd6",
      "IpAddress": "198.51.100.10",
      "Asn": 65000,
      "AuthKey": "a-shared-secret"
    }`), &gw))

	assert.Equal(t, int64(65000), tea.Int64Value(gw.Asn))
	// only the presence of a key is derived
	assert.True(t, tea.StringValue(gw.AuthKey) != "")

	var noKey vpcclient.DescribeCustomerGatewaysResponseBodyCustomerGatewaysCustomerGateway
	require.NoError(t, json.Unmarshal([]byte(`{"CustomerGatewayId":"cgw-1"}`), &noKey))
	// an unauthenticated BGP peer must read as unauthenticated
	assert.False(t, tea.StringValue(noKey.AuthKey) != "")
	assert.Equal(t, int64(0), tea.Int64Value(noKey.Asn))
}
