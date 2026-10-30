// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net"
	"testing"

	gosnowflake "github.com/snowflakedb/gosnowflake/v2"
)

func TestIsAccessDenied(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			// Verbatim shape of the error DESCRIBE NETWORK RULE returns for a
			// rule the role does not own, observed live 2026-08-20.
			"insufficient privilege",
			&gosnowflake.SnowflakeError{
				Number:   3001,
				SQLState: "42501",
				Message:  "SQL access control error:\nInsufficient privileges to operate on network_rule 'PYPI_RULE'.",
			},
			true,
		},
		{
			"insufficient privilege, wrapped",
			fmt.Errorf("describe network rule: %w", &gosnowflake.SnowflakeError{
				Number: 3001, SQLState: "42501",
			}),
			true,
		},
		{
			// Object-does-not-exist is a different condition and must not be
			// swallowed as a denial.
			"object does not exist",
			&gosnowflake.SnowflakeError{Number: 2003, SQLState: "42S02"},
			false,
		},
		{
			// The one that matters most: a transport failure degrading to a
			// null field would let an audit pass on data never read.
			"network error",
			&net.OpError{Op: "dial", Err: errors.New("connection refused")},
			false,
		},
		{"plain error", errors.New("something went wrong"), false},
		{
			// The classifier must key on the typed error, not the text, so a
			// lookalike message cannot trip it.
			"lookalike message, untyped",
			errors.New("003001 (42501): SQL access control error: Insufficient privileges"),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAccessDenied(tc.err); got != tc.want {
				t.Errorf("isAccessDenied(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestErrSchemaNotFoundIsMatchable guards the sentinel that lets a reference
// resolver degrade a missing schema while still propagating a real failure.
func TestErrSchemaNotFoundIsMatchable(t *testing.T) {
	notFound := fmt.Errorf("snowflake.schema %q not found in database %q: %w",
		"EXTERNAL_ACCESS", "SNOWFLAKE", errSchemaNotFound)

	if !errors.Is(notFound, errSchemaNotFound) {
		t.Error("wrapped not-found error must match errSchemaNotFound")
	}
	if errors.Is(errors.New("connection reset by peer"), errSchemaNotFound) {
		t.Error("an unrelated error must not match errSchemaNotFound")
	}
	// The message a user sees still has to name what was missing.
	if got := notFound.Error(); got == "" ||
		!errors.Is(notFound, errSchemaNotFound) {
		t.Errorf("unexpected message %q", got)
	}
}
