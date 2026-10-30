// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cockroachdb/connection"
)

func (r *mqlCockroachdb) id() (string, error) {
	return "cockroachdb", nil
}

func crdbConnection(runtime *plugin.Runtime) *connection.CockroachdbConnection {
	return runtime.Connection.(*connection.CockroachdbConnection)
}

// query runs a read-only statement on the cluster and returns its rows.
func query(runtime *plugin.Runtime, sql string, args ...any) (pgx.Rows, error) {
	pool, err := crdbConnection(runtime).Client()
	if err != nil {
		return nil, err
	}
	return pool.Query(context.Background(), sql, args...)
}

// isPermissionDenied reports whether CockroachDB refused a statement for lack
// of a privilege (SQLSTATE 42501, insufficient_privilege).
func isPermissionDenied(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}

// refused classifies a privilege refusal as Forbidden, naming the privilege
// the read needed. Any other error is returned as is.
func refused(err error, permission string) error {
	if isPermissionDenied(err) {
		return llx.Forbidden(err, llx.WithPermissions(permission))
	}
	return err
}

// toAnySlice converts a string slice to []any for llx.
func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}
