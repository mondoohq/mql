// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package connection

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestApiAccess(t *testing.T) {
	p, err := NewVcdConnection(0, nil, &inventory.Config{
		Host: "<host>",
		Credentials: []*vault.Credential{
			{
				User:     "<user>",
				Password: "<password>",
			},
		},
		Options: map[string]string{
			"organization": "system",
		},
		Insecure: false,
	})
	require.NoError(t, err)

	client := p.Client()

	orgs, err := client.GetOrgList()
	require.NoError(t, err)
	for i := range orgs.Org {
		org := orgs.Org[i]
		fmt.Println(org.Name)
	}

	networks, err := client.GetExternalNetworks()
	require.NoError(t, err)
	for i := range networks.ExternalNetworkReference {
		net := networks.ExternalNetworkReference[i]
		fmt.Printf(net.Name)
	}
}
