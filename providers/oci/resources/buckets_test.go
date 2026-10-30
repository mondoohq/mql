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
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bucketsServer answers ListBuckets with one tagged bucket and records the
// query of each request.
func bucketsServer(t *testing.T, queries *[]string) *objectstorage.ObjectStorageClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*queries = append(*queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"namespace": "ns", "name": "b1", "compartmentId": "ocid1.compartment..c1",
			"freeformTags": {"cep-testbed": "true"}, "definedTags": {}}]`))
	}))
	t.Cleanup(srv.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy..t", "ocid1.user..u", "us-ashburn-1",
		"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", string(keyPEM), nil)
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	require.NoError(t, err)
	client.Host = srv.URL
	return &client
}

func TestGetBucketsForRegionAsksForTags(t *testing.T) {
	var queries []string
	client := bucketsServer(t, &queries)
	o := &mqlOciObjectStorage{}

	buckets, err := o.getBucketsForRegion(context.Background(), client, "ocid1.compartment..c1", "ns")
	require.NoError(t, err)
	require.Len(t, buckets, 1)
	assert.Equal(t, "true", buckets[0].FreeformTags["cep-testbed"], "the listed tags decode")
	require.Len(t, queries, 1)
	assert.Contains(t, queries[0], "fields=tags", "without fields=tags ListBuckets returns no tags and every bucket fails a tag filter")
	assert.Contains(t, queries[0], "compartmentId=ocid1.compartment..c1", "the compartment asked about is the one passed in")
}
