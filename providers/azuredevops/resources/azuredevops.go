// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
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

// classifyForbidden marks a 403 as a forbidden error (ADR 046), so a field the
// credential may not read reports the refusal instead of a value. Every other
// error is returned unchanged; a rejected credential (401) still fails as is.
func classifyForbidden(err error) error {
	if connection.IsForbidden(err) {
		return llx.Forbidden(err)
	}
	return err
}
