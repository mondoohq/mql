// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package connection

import (
	"context"
	"fmt"
	"testing"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	org   = "dev-12345.okta.com"
	token = "<token goes here>"
)

func TestOkta(t *testing.T) {
	config, err := okta.NewConfiguration(
		okta.WithOrgUrl("https://"+org),
		okta.WithToken(token),
	)
	require.NoError(t, err)
	client := okta.NewAPIClient(config)

	fmt.Printf("Client: %+v\n", client)

	ctx := context.Background()
	users, _, err := client.UserAPI.ListUsers(ctx).Execute()
	require.NoError(t, err)
	assert.NotNil(t, users)

	// second call
	_, resp, err := client.UserAPI.ListUsers(ctx).Limit(200).Execute()
	require.NoError(t, err)

	for resp != nil && resp.HasNextPage() {
		var userSetSlice []okta.User
		resp, err = resp.Next(&userSetSlice)
		require.NoError(t, err)
	}
}
