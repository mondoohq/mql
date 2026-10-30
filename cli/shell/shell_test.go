// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shell_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/cli/shell"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

func localShell() *shell.ShellProgram {
	runtime := testutils.LinuxMock()
	return shell.NewShell(runtime)
}

func TestShell_RunOnce(t *testing.T) {
	sh := localShell()
	assert.NotPanics(t, func() {
		_, _, _ = sh.RunOnce("mondoo.build")
	}, "should not panic on partial queries")

	assert.NotPanics(t, func() {
		_, _, _ = sh.RunOnce("mondoo { build version }")
	}, "should not panic on partial queries")

	assert.NotPanics(t, func() {
		_, _, _ = sh.RunOnce("mondoo { _.version }")
	}, "should not panic on partial queries")
}

func TestShell_Centos8(t *testing.T) {
	sh := localShell()
	assert.NotPanics(t, func() {
		_, _, _ = sh.RunOnce("platform { title name release arch }")
	}, "should not panic on partial queries")
}

// The shell has no content to declare a mode, so `--strict` / the `strict`
// config key is the only thing that turns strict mode on for a typed query.
// This covers that wiring: WithStrict has to reach the compiler config the
// shell compiles with.
func TestShell_Strict(t *testing.T) {
	const query = `parse.json("/dummy.json").params.NOPE == "no"`

	lenient := shell.NewShell(testutils.LinuxMock())
	_, res, err := lenient.RunOnce(query)
	require.NoError(t, err, "a missing key is silently false without strict mode")
	require.NotEmpty(t, res)
	assert.False(t, anyResultErrored(res), "non-strict must not error on a missing key")

	strict := shell.NewShell(testutils.LinuxMock(), shell.WithStrict(true))
	_, res, err = strict.RunOnce(query)
	require.NoError(t, err, "the query still compiles; the failure is at runtime")
	require.NotEmpty(t, res)
	assert.True(t, anyResultErrored(res), "strict mode must surface the missing key as an error")
}

func anyResultErrored(res map[string]*llx.RawResult) bool {
	for _, r := range res {
		if r != nil && r.Data != nil && r.Data.Error != nil {
			return true
		}
	}
	return false
}
