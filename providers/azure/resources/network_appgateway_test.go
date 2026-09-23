// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
)

func TestAzureAppGatewaySSLPolicyFields(t *testing.T) {
	t.Run("nil policy returns empty values", func(t *testing.T) {
		policyType, policyName, minProto, ciphers := azureAppGatewaySSLPolicyFields(nil)
		assert.Empty(t, policyType)
		assert.Empty(t, policyName)
		assert.Empty(t, minProto)
		assert.Equal(t, []any{}, ciphers)
	})

	t.Run("custom policy flattens type, name, min version, and ciphers", func(t *testing.T) {
		sp := &network.ApplicationGatewaySSLPolicy{
			PolicyType:         to.Ptr(network.ApplicationGatewaySSLPolicyTypeCustom),
			PolicyName:         to.Ptr(network.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20220101S),
			MinProtocolVersion: to.Ptr(network.ApplicationGatewaySSLProtocolTLSv12),
			CipherSuites: []*network.ApplicationGatewaySSLCipherSuite{
				to.Ptr(network.ApplicationGatewaySSLCipherSuiteTLSECDHERSAWITHAES128CBCSHA256),
				nil, // nil entries must be skipped
				to.Ptr(network.ApplicationGatewaySSLCipherSuiteTLSECDHEECDSAWITHAES128CBCSHA256),
			},
		}
		policyType, policyName, minProto, ciphers := azureAppGatewaySSLPolicyFields(sp)
		assert.Equal(t, "Custom", policyType)
		assert.Equal(t, "AppGwSslPolicy20220101S", policyName)
		assert.Equal(t, "TLSv1_2", minProto)
		assert.Equal(t, []any{
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		}, ciphers)
	})
}
