// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	gosnowflake "github.com/snowflakedb/gosnowflake/v2"
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
