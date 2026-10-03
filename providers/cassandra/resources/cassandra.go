// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cassandra/connection"
)

func (r *mqlCassandra) id() (string, error) {
	return "cassandra", nil
}

func cassandraConnection(runtime *plugin.Runtime) *connection.CassandraConnection {
	return runtime.Connection.(*connection.CassandraConnection)
}

// toAnySlice converts a string slice to []any for llx.
func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// refused classifies a CQL authorization failure as Forbidden, naming the
// grant the read needed.
func refused(err error, permission string) error {
	return llx.Forbidden(err, llx.WithPermissions(permission))
}
