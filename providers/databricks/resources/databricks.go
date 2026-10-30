// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"time"

	databricks "github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/service/iam"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/databricks/connection"
)

func (r *mqlDatabricks) id() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatabricksConnection)
	if conn.Plane() == connection.PlaneWorkspace {
		id := conn.WorkspaceID()
		if id == "" {
			id = conn.Host()
		}
		return "databricks/workspace/" + id, nil
	}
	return "databricks/account/" + conn.AccountID(), nil
}

// accountClient returns the account console client, or an error when the asset
// is connected to a single workspace rather than the account.
func accountClient(runtime *plugin.Runtime) (*databricks.AccountClient, error) {
	conn := runtime.Connection.(*connection.DatabricksConnection)
	acc := conn.Account()
	if acc == nil {
		return nil, errors.New("this resource requires connecting to the Databricks account console (use --account-id)")
	}
	return acc, nil
}

// workspaceClient returns the workspace client, or an error when the asset is
// connected to the account console rather than a workspace.
func workspaceClient(runtime *plugin.Runtime) (*databricks.WorkspaceClient, error) {
	conn := runtime.Connection.(*connection.DatabricksConnection)
	ws := conn.Workspace()
	if ws == nil {
		return nil, errors.New("this resource requires connecting to a Databricks workspace")
	}
	return ws, nil
}

// complexValues extracts the meaningful Value of each SCIM ComplexValue,
// dropping empties. Used for entitlements, roles, and group membership.
func complexValues(vals []iam.ComplexValue) []any {
	out := []any{}
	for i := range vals {
		if vals[i].Value != "" {
			out = append(out, vals[i].Value)
		}
	}
	return out
}

// strSlice converts a string slice to the []any form llx.ArrayData expects.
func strSlice(vals []string) []any {
	out := make([]any, 0, len(vals))
	for _, v := range vals {
		out = append(out, v)
	}
	return out
}

// nonEmptyString reports a string the API omits when unset, or null when it
// is empty.
func nonEmptyString(v string) *llx.RawData {
	if v == "" {
		return llx.NilData
	}
	return llx.StringData(v)
}

// strMap converts a string map to the map[string]any form llx.MapData expects.
func strMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// epochMsTime converts a Databricks epoch-millisecond timestamp to a time,
// returning nil for the zero/negative sentinels the API uses for "unset".
func epochMsTime(ms int64) *time.Time {
	if ms <= 0 {
		return nil
	}
	t := time.UnixMilli(ms)
	return &t
}

// rfc3339Time parses the RFC 3339 timestamps the OAuth account APIs return as
// strings, rather than the epoch milliseconds the rest of the API uses.
// Returns nil for an empty value, which is how those APIs report "never" (a
// secret with no expiry, for instance), and for a value this parser does not
// recognize, so an unexpected format reads as unset rather than as a date.
func rfc3339Time(value string) *time.Time {
	if value == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return &t
}

// nullableBool reports a boolean the API may not have answered at all. A nil
// value marks the field null rather than returning false. MQL evaluates
// `null && null` as true, so a fabricated false on a security toggle lets every
// assertion written over it pass while nothing was actually read.
func nullableBool(v *bool, state *plugin.State) (bool, error) {
	if v == nil {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

// nullableString reports a string the API may not have answered at all,
// marking the field null rather than returning an empty string.
func nullableString(v *string, state *plugin.State) (string, error) {
	if v == nil {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

// nullableList reports a list the API may not have answered at all. A nil
// slice marks the field null; an allocated but empty slice stays empty,
// because "no members" and "not read" are different answers.
func nullableList(v []any, state *plugin.State) ([]any, error) {
	if v == nil {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return v, nil
}
