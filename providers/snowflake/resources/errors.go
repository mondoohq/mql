// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	gosnowflake "github.com/snowflakedb/gosnowflake/v2"
	"go.mondoo.com/mql/llx"
)

// sqlStateInsufficientPrivilege is the SQL standard SQLSTATE for a statement
// the current role is not allowed to run. Snowflake reports it as error 003001,
// "SQL access control error".
const sqlStateInsufficientPrivilege = "42501"

// isAccessDenied reports whether err is Snowflake refusing a statement for lack
// of privilege, as opposed to the object being absent or the connection having
// failed.
//
// The distinction decides what a field may claim. A denied read means the value
// is unknown and the field has to say so; treating it as an empty result would
// report the absence of a setting as fact. A transport failure is not a denial
// and must keep propagating, or a network blip degrades into a silently
// unpopulated field.
//
// Matched on the typed error rather than the message text, so a reworded
// server message cannot turn every denial into a hard failure.
func isAccessDenied(err error) bool {
	var sfErr *gosnowflake.SnowflakeError
	if !errors.As(err, &sfErr) {
		return false
	}
	return sfErr.SQLState == sqlStateInsufficientPrivilege
}

// snowflakeErrNoWarehouse is Snowflake error 000606, "No active warehouse
// selected in the current session", taken from Snowflake's error reference and
// not measured here. Account usage views run on a warehouse, so a connection
// without one cannot read them at all.
const snowflakeErrNoWarehouse = 606

// accountUsagePrivilege is what a role needs to read SNOWFLAKE.ACCOUNT_USAGE.
const accountUsagePrivilege = "IMPORTED PRIVILEGES on database SNOWFLAKE"

// isNoWarehouse reports whether err is Snowflake refusing a statement because
// the session has no current warehouse.
func isNoWarehouse(err error) bool {
	var sfErr *gosnowflake.SnowflakeError
	if !errors.As(err, &sfErr) {
		return false
	}
	return sfErr.Number == snowflakeErrNoWarehouse
}

// classifySnowflakeUsageError maps a failed SNOWFLAKE.ACCOUNT_USAGE read to its
// error kind: a privilege refusal is Forbidden with the privilege named, a
// session without a warehouse is NotApplicable, anything else (transport,
// timeout) is returned unchanged.
func classifySnowflakeUsageError(err error) error {
	switch {
	case err == nil:
		return nil
	case isAccessDenied(err):
		return llx.Forbidden(err, llx.WithPermissions(accountUsagePrivilege))
	case isNoWarehouse(err):
		return llx.NotApplicable(fmt.Errorf("no warehouse for account usage reads: %w", err))
	}
	return err
}
