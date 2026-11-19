// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestLbListenerPredefinedSuiteOnlyByName pins why sslCipherSuiteName is not
// deprecated: for a listener on an OCI-predefined suite, the name is the only
// field that carries anything. sslCipherSuite resolves against the load
// balancer's own collection, which never contains the predefined suites.
func TestLbListenerPredefinedSuiteOnlyByName(t *testing.T) {
	ssl := lbSslFieldsFrom(&loadbalancer.SslConfiguration{
		CipherSuiteName: new("oci-modern-ssl-cipher-suite-v1"),
		Protocols:       []string{"TLSv1.2"},
	})
	assert.Equal(t, "oci-modern-ssl-cipher-suite-v1", ssl.cipherSuiteName)

	var field plugin.TValue[*mqlOciLoadBalancerSslCipherSuite]
	suite, err := resolveLbCipherSuite(testRuntime(), testLbId, ssl.cipherSuiteName, testCipherSuites(), &field)
	require.NoError(t, err)
	assert.Nil(t, suite)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
}
