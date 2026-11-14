// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/yugabyte/connection"
)

func (r *mqlYugabyte) id() (string, error) {
	return "yugabyte", nil
}

func ybConnection(runtime *plugin.Runtime) *connection.YugabyteConnection {
	return runtime.Connection.(*connection.YugabyteConnection)
}

// ysqlTimeout bounds one YSQL statement, from sending it to reading its last
// row, as the HTTP calls are bounded, so that a server that stops answering
// cannot hold a scan.
const ysqlTimeout = 30 * time.Second

// ysqlQuery runs a read-only statement over YSQL and returns its rows. The
// statement's deadline is released when the rows are closed.
func ysqlQuery(runtime *plugin.Runtime, sql string, args ...any) (pgx.Rows, error) {
	pool, err := ybConnection(runtime).YSQL()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), ysqlTimeout)
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		cancel()
		return nil, err
	}
	return &timedRows{Rows: rows, cancel: cancel}, nil
}

// timedRows releases the statement's deadline when the rows are closed.
type timedRows struct {
	pgx.Rows
	cancel context.CancelFunc
}

func (r *timedRows) Close() {
	r.Rows.Close()
	r.cancel()
}

// isPermissionDenied reports whether YSQL refused a statement for lack of a
// privilege (SQLSTATE 42501, insufficient_privilege).
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
