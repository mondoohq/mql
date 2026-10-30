// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// The interactive prompt compiles every typed query through
// shellModel.compilerConfig, so `--strict` only takes effect there if the flag
// reaches the model itself. It used to reach only the completer, which meant
// autocomplete knew about strict mode while the query the user pressed enter on
// silently compiled permissive.
func TestShellModel_strictReachesCompilerConfig(t *testing.T) {
	runtime := testutils.LinuxMock()

	for _, strict := range []bool{false, true} {
		m := newShellModel(runtime, DefaultShellTheme, mql.DefaultFeatures, strict, "", nil)
		assert.Equal(t, strict, m.strict, "strict must be stored on the model")
		assert.Equal(t, strict, m.compilerConfig().Strict,
			"strict must reach the config the interactive prompt compiles with")
		assert.Equal(t, strict, m.completer.compilerConfig().Strict,
			"completion must compile in the same mode as the query")
	}
}
