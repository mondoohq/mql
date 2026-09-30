// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

func TestParseWindowsProcessesSingleObject(t *testing.T) {
	ps, err := processes.ParseWindowsProcesses(strings.NewReader(`{"Id":4,"Name":"System","Path":null}`))
	require.NoError(t, err)
	require.Len(t, ps, 1)
	assert.Equal(t, int64(4), ps[0].ID)
}
