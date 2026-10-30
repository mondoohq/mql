// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/opensearch/connection"
)

func (r *mqlOpensearch) id() (string, error) {
	return "opensearch", nil
}

func osConnection(runtime *plugin.Runtime) *connection.OpensearchConnection {
	return runtime.Connection.(*connection.OpensearchConnection)
}

// toStringSlice converts a decoded JSON string array to []any for llx.
func toStringSlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// Permissions the scanner needs, named in a refusal. The security REST API
// admits roles listed in plugins.security.restapi.roles_enabled, by default
// security_rest_api_access; health needs the cluster_monitor action group.
const (
	permSecurityAPI   = "security_rest_api_access"
	permClusterHealth = "cluster_monitor"
)

// refusal classifies a 401 or 403 from the cluster: a 401 is a credential the
// cluster did not accept, a 403 a missing permission, named by permissions.
// Any other error is returned unchanged.
func refusal(err error, permissions ...string) error {
	var pe *connection.PermissionError
	if !errors.As(err, &pe) {
		return err
	}
	if pe.StatusCode == http.StatusUnauthorized {
		return llx.Unauthenticated(err)
	}
	return llx.Forbidden(err, llx.WithPermissions(permissions...))
}

// refusedList is what a list accessor returns for a failed request. v13 read
// a 401 or 403 as an empty list, which let a check over the list pass on a
// cluster the scanner could not read; with StructuredErrors it is an error
// naming the permission the scanner lacks (ADR 046).
func refusedList(err error, permissions ...string) ([]any, error) {
	if !connection.IsPermissionError(err) {
		return nil, err
	}
	if !plugin.StructuredErrors() {
		return []any{}, nil
	}
	return nil, refusal(err, permissions...)
}
