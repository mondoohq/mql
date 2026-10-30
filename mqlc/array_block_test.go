// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
)

// TestCompiler_ArrayLiteralWithBlock covers an array literal whose elements are
// resources, with a block attached.
//
// The elements compile to refs, so the stack is already non-empty by the time the
// block is handled. compileOperand only pushed the value onto the stack when the
// stack looked empty, so for this shape the array primitive was never pushed and
// the operand's own ref stayed 0 -- leaving the block bound to a chunk that is
// not on the stack. Computing checksums then hit
//
//	panic: cannot compute checksum for chunk, it doesn't seem to reference a
//	       function on the stack        (llx/chunk.go, Function.checksumV2)
//
// Compile() recovers only to re-panic with a wrapped error, so this crashed the
// caller -- the CLI died and health.ReportPanic fired -- instead of returning a
// compile error. A scalar array ([1,2] { _ }) was unaffected, which is why this
// went unnoticed.
func TestCompiler_ArrayLiteralWithBlock(t *testing.T) {
	codes := []string{
		"[asset] { name }",
		"[mondoo] { version }",
		"[asset] { name platform }",
		// the shape that first surfaced this: two parameterized instances of one
		// resource compared side by side
		`[asset, asset] { name }`,
		// scalars kept working throughout; pin them so the fix cannot regress them
		"[1, 2] { _ }",
		`["a", "b"] { _ }`,
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			require.NotPanics(t, func() {
				res, err := mqlc.Compile(code, nil, conf)
				require.NoError(t, err)
				require.NotNil(t, res)
				require.NotNil(t, res.CodeV2)
				assert.NoError(t, mqlc.Invariants.Check(res))
				require.NotEmpty(t, res.CodeV2.Blocks)
			}, "compiling %q must not panic", code)
		})
	}
}
