// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserArgsInactivity(t *testing.T) {
	// RouterOS 7.25.1 default: an idle session is never closed
	rows := liveRows(t, "user.json")
	args := userArgs(rows[0])
	assert.Equal(t, "mikrotik.user/admin", args["__id"].Value)
	assert.Equal(t, "none", args["inactivityPolicy"].Value)
	assert.Equal(t, "10m", args["inactivityTimeout"].Value)

	locked := userArgs(map[string]string{
		"name":               "ops",
		"inactivity-policy":  "lockscreen",
		"inactivity-timeout": "5m",
	})
	assert.Equal(t, "lockscreen", locked["inactivityPolicy"].Value)
	assert.Equal(t, "5m", locked["inactivityTimeout"].Value)
}

func TestUserArgsWithoutInactivitySettings(t *testing.T) {
	args := userArgs(map[string]string{"name": "legacy", "disabled": "false"})
	assert.Equal(t, "", args["inactivityPolicy"].Value)
	assert.Equal(t, "", args["inactivityTimeout"].Value)
	assert.Equal(t, false, args["disabled"].Value)
}
