// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package googleworkspace

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

var x = testutils.InitTester(googleWorkspaceProvider(), Registry)

func googleWorkspaceProvider() *googleWorkspaceConnection {
	provider, err := googleworkspace.NewGoogleWorkspaceConnection(&inventory.Config{
		Type: "google-workspace",
		Options: map[string]string{
			"customer-id": "<add-here>",
		},
	})
	if err != nil {
		panic(err.Error())
	}

	return m.Connection
}

func TestResource_Domain(t *testing.T) {
	res := x.TestQuery(t, "googleworkspace.users")
	assert.NotEmpty(t, res)
}
