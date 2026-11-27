// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOciListVaultKeysAsksTheGivenCompartment pins the request that lists a
// vault's keys. ListKeys answers only for the compartment it is given, so a
// key created outside its vault's compartment is found only when that
// compartment is asked.
func TestOciListVaultKeysAsksTheGivenCompartment(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id": "ocid1.key..k1", "displayName": "key",
			"compartmentId": "ocid1.compartment..app", "vaultId": "ocid1.vault..v1",
			"protectionMode": "HSM", "lifecycleState": "ENABLED"}]`))
	}))
	t.Cleanup(srv.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy..t", "ocid1.user..u", "us-ashburn-1",
		"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", string(keyPEM), nil)
	client, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(provider, srv.URL)
	require.NoError(t, err)

	keys, err := ociListVaultKeys(context.Background(), &client, "ocid1.compartment..app")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "ocid1.compartment..app", *keys[0].CompartmentId)
	assert.Equal(t, "ocid1.vault..v1", *keys[0].VaultId)
	require.Len(t, queries, 1)
	assert.Contains(t, queries[0], "compartmentId=ocid1.compartment..app")
}
