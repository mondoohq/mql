// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeFixture writes a single Go source file into a fresh temp dir and returns
// the dir. The extractor only parses syntax (no type checking), so the fixture
// need not compile against the real Azure SDK.
func writeFixture(t *testing.T, name, src string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600))
	return dir
}

func hasPermissionDetail(details []PermissionDetail, permission, action, sourceFile string) bool {
	for _, d := range details {
		if d.Permission == permission && d.Action == action && d.SourceFile == sourceFile {
			return true
		}
	}
	return false
}

// TestExtractAzurePermissions_StructFieldClient covers the idiomatic pattern
// where an ARM client is cached in a struct field by a constructor and used
// across methods via the receiver (c.client.Get / c.client.NewListPager),
// rather than constructed as a local variable in the same function.
func TestExtractAzurePermissions_StructFieldClient(t *testing.T) {
	src := `package fixture

import (
	"context"

	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
)

type SubscriptionsClient struct {
	client *subscriptions.Client
}

func NewSubscriptionsClient() (*SubscriptionsClient, error) {
	client, err := subscriptions.NewClient(nil, nil)
	if err != nil {
		return nil, err
	}
	return &SubscriptionsClient{client: client}, nil
}

func (c *SubscriptionsClient) GetSubscriptions() error {
	res := c.client.NewListPager(nil)
	_ = res
	return nil
}

func (c *SubscriptionsClient) GetSubscriptionTags(id string) error {
	_, err := c.client.Get(context.Background(), id, nil)
	return err
}
`
	dir := writeFixture(t, "client_subscriptions.go", src)
	details := extractAzurePermissions(dir)

	require.True(t,
		hasPermissionDetail(details, "Microsoft.Resources/subscriptions/read", "Get", "client_subscriptions.go"),
		"expected the c.client.Get read to be attributed; got: %+v", details)
	require.True(t,
		hasPermissionDetail(details, "Microsoft.Resources/subscriptions/read", "NewListPager", "client_subscriptions.go"),
		"expected the c.client.NewListPager read to be attributed; got: %+v", details)
}

// TestExtractAzurePermissions_LocalClient is a regression guard: the pre-existing
// local-variable pattern (client built and used in the same function) must keep
// working.
func TestExtractAzurePermissions_LocalClient(t *testing.T) {
	src := `package fixture

import (
	"context"

	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
)

func listVMs() error {
	client, err := armcompute.NewVirtualMachinesClient("sub", nil, nil)
	if err != nil {
		return err
	}
	_ = client.NewListAllPager(nil)
	_, _ = client.Get(context.Background(), "rg", "vm", nil)
	return nil
}
`
	dir := writeFixture(t, "compute.go", src)
	details := extractAzurePermissions(dir)

	require.True(t,
		hasPermissionDetail(details, "Microsoft.Compute/virtualMachines/read", "NewListAllPager", "compute.go"),
		"expected local-client list read; got: %+v", details)
	require.True(t,
		hasPermissionDetail(details, "Microsoft.Compute/virtualMachines/read", "Get", "compute.go"),
		"expected local-client get read; got: %+v", details)
}
