// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// On RHEL 9, a scan that is not root gets "permission denied on key
// 'fs.protected_hardlinks'" from sysctl -a. The parameter exists, so it is
// active, and its value is a refusal rather than a null that a `value !=`
// check passes on.
func TestLiveParameter(t *testing.T) {
	state := &kernelSysctls{
		live:       map[string]string{"kernel.randomize_va_space": "2"},
		denied:     map[string]bool{"fs.protected_hardlinks": true},
		observable: true,
		exists: func(name string) bool {
			return name == "net.ipv6.conf.all.stable_secret"
		},
	}

	active, value := liveParameter(state, "kernel.randomize_va_space")
	assert.Equal(t, true, active.Value)
	assert.Equal(t, "2", value.Value)
	assert.NoError(t, value.Error)

	active, value = liveParameter(state, "fs.protected_hardlinks")
	assert.Equal(t, true, active.Value)
	assert.Nil(t, value.Value)
	require.Error(t, value.Error)
	assert.True(t, errors.Is(value.Error, llx.ErrForbidden))

	// exists, but sysctl read no value and reported no refusal
	active, value = liveParameter(state, "net.ipv6.conf.all.stable_secret")
	assert.Equal(t, true, active.Value)
	assert.Nil(t, value.Value)
	assert.NoError(t, value.Error)

	active, value = liveParameter(state, "kernel.g01_absent_param")
	assert.Equal(t, false, active.Value)
	assert.Nil(t, value.Value)
	assert.NoError(t, value.Error)
}
