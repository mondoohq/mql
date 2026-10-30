// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/network/connection"
	"go.mondoo.com/mql/providers/network/resources"
	"go.mondoo.com/mql/utils/syncx"
)

func TestResource_TLS(t *testing.T) {
	res := x.TestQuery(t, "tls(\"mondoo.com\").certificates")
	assert.NotEmpty(t, res)
	assert.Nil(t, res[0].Data.Error)
}

func TestResource_TlsCipherSuites(t *testing.T) {
	// A modern endpoint negotiates forward-secret, AEAD suites and offers no
	// NULL/export/anonymous ones.
	res := x.TestQuery(t, `tls("mondoo.com").cipherSuites != empty`)
	assert.NotEmpty(t, res)
	assert.Nil(t, res[0].Data.Error)

	res = x.TestQuery(t, `tls("mondoo.com").cipherSuites.none(nullCipher || export || anonymous)`)
	assert.NotEmpty(t, res)
	assert.Nil(t, res[0].Data.Error)
	assert.Equal(t, true, res[0].Data.Value)

	res = x.TestQuery(t, `tls("mondoo.com").cipherSuites.all(name != "")`)
	assert.NotEmpty(t, res)
	assert.Nil(t, res[0].Data.Error)
	assert.Equal(t, true, res[0].Data.Value)
}

func TestResource_TlsFqdn(t *testing.T) {
	testCases := []struct {
		hostName   string
		expectedId string
	}{
		{
			hostName:   "www.mondoo.com",
			expectedId: "tls+tcp://www.mondoo.com:443",
		},
	}

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	for _, tc := range testCases {
		conf := &inventory.Config{
			Host: tc.hostName,
		}
		runtime.Connection = connection.NewHostConnection(1, &inventory.Asset{}, conf)

		dns, err := resources.NewResource(
			runtime,
			"tls",
			map[string]*llx.RawData{},
		)
		require.NoError(t, err)
		require.Equal(t, tc.expectedId, dns.MqlID())
	}
}
