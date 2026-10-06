// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

func (r *mqlAzuredevops) id() (string, error) {
	return "azuredevops", nil
}

// connectionOf is the Azure DevOps connection of the runtime.
func connectionOf(runtime *plugin.Runtime) *connection.AzuredevopsConnection {
	return runtime.Connection.(*connection.AzuredevopsConnection)
}

// apiContext is the context of every REST call a resource makes. A resource
// field is computed on demand and has no request to inherit a context from.
func apiContext() context.Context {
	return context.Background()
}
