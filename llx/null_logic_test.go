// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// A null operand of `&&` or `||` is falsy (ADR 040 part 4).
//
// Two defects lived in the shared `bind.Value == nil` shortcut:
//
//   - `null && null` returned **true**, so an assertion over two fields that
//     could not be read reported success having measured neither. Nine
//     providers carry regression tests whose only purpose is keeping their
//     resources from tripping it.
//   - `null || true` returned **false**, because the OR helper carried the AND
//     rule verbatim. That is wrong under three-valued logic, under
//     null-as-false, and under null-as-true alike.
//
// Comparison is deliberately excluded: `null == null` stays true. Whether two
// absent values are equal is a different question from whether an absent value
// satisfies a check.
func TestNullIsFalsyInLogicalOperators(t *testing.T) {
	runtime := testutils.LinuxMock()

	// Two map keys that are not present, so each reads as a genuine runtime
	// null rather than a schema or provider error.
	null := `sshd.config.params["NoSuchKey"]`
	otherNull := `sshd.config.params["AlsoNoSuchKey"]`

	tests := []struct {
		query string
		want  bool
	}{
		// && : a null operand can never satisfy the conjunction.
		{null + ` && ` + otherNull, false}, // regressed: was true
		{null + ` && true`, false},
		{null + ` && false`, false},
		{`true && ` + null, false},
		{`false && ` + null, false},

		// || : a null operand contributes nothing, so the other side decides.
		{null + ` || ` + otherNull, false}, // regressed: was true
		{null + ` || true`, true},          // regressed: was false
		{null + ` || false`, false},
		{`true || ` + null, true},
		{`false || ` + null, false},

		// Comparison keeps its own meaning.
		{null + ` == ` + otherNull, true},
		{null + ` != ` + otherNull, false},
	}

	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			res, err := exec.Exec(tc.query, runtime, mql.Features{}, nil)
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, tc.want, res.Value)
		})
	}
}

// The typed variants all route through the same two helpers, so the rule has to
// hold for a null compared against something other than a bool.
func TestNullIsFalsyAcrossOperandTypes(t *testing.T) {
	runtime := testutils.LinuxMock()
	null := `sshd.config.params["NoSuchKey"]`

	for _, query := range []string{
		null + ` && sshd.config.params`,
		null + ` && sshd.config.file.path`,
		null + ` && 1`,
		null + ` && "x"`,
	} {
		t.Run(query, func(t *testing.T) {
			res, err := exec.Exec(query, runtime, mql.Features{}, nil)
			require.NoError(t, err)
			assert.Equal(t, false, res.Value, "a null left side is falsy regardless of the right")
		})
	}
}
