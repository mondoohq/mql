// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

// awsCatalog builds a catalog from the trimmed service reference files, the
// way loadAWSCatalog does from the downloaded ones.
func awsCatalog(t *testing.T) *catalog {
	t.Helper()
	c := newCatalog()
	for _, svc := range []string{"s3", "vpc-lattice", "access-analyzer", "bedrock"} {
		require.NoError(t, parseAWSServiceReference(fixture(t, filepath.Join("aws-service-reference", svc+".json")), c))
	}
	// The index names every service, fetched or not.
	c.addService("ec2")
	return c
}

// gcpCatalog builds a catalog from per-scope API results in the API's own
// shape, the way loadGCPCatalog does from the live responses.
func gcpCatalog(t *testing.T) *catalog {
	t.Helper()
	var byScope map[string][]gcpTestablePermission
	require.NoError(t, json.Unmarshal(fixture(t, "gcp-testable-permissions.json"), &byScope))
	c := newCatalog()
	addGCPPermissions(c, byScope)
	return c
}

// azureCatalog builds a catalog from a trimmed registry response.
func azureCatalog(t *testing.T) *catalog {
	t.Helper()
	c := newCatalog()
	require.NoError(t, parseAzureProviderOperations(fixture(t, "provider-operations.json"), c))
	return c
}
