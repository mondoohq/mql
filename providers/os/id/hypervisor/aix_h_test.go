// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAixHypervisor(t *testing.T) {
	// uname -L on an AIX 7.3 LPAR in IBM Power Virtual Server
	name, ok := parseAixHypervisor("25 aix73-00000000-00000000\n")
	assert.True(t, ok)
	assert.Equal(t, "IBM PowerVM", name)

	for _, out := range []string{"-1 NULL\n", "", "uname: illegal option -- L\n"} {
		name, ok := parseAixHypervisor(out)
		assert.False(t, ok, out)
		assert.Empty(t, name, out)
	}
}
