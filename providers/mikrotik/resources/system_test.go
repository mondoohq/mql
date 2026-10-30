// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchedulerArgs(t *testing.T) {
	row := map[string]string{
		"name":       "reinstate",
		"start-date": "2026-08-01",
		"start-time": "startup",
		"interval":   "00:05:00",
		"on-event":   "restore-access",
		"owner":      "admin",
		"policy":     "read,write,policy,ftp,test,password,sniff,sensitive",
		"run-count":  "412",
		"next-run":   "00:04:12",
		"disabled":   "false",
	}
	args := schedulerArgs(row)

	assert.Equal(t, "mikrotik.system.scheduler/reinstate", args["__id"].Value)
	assert.Equal(t, "startup", args["startTime"].Value)
	assert.Equal(t, "00:05:00", args["interval"].Value)
	assert.Equal(t, "restore-access", args["onEvent"].Value)
	assert.Equal(t, int64(412), args["runCount"].Value)
	assert.Equal(t, false, args["disabled"].Value)
	// the policy set is what makes a scheduled task a persistence mechanism
	policy, ok := args["policy"].Value.([]any)
	require.True(t, ok)
	assert.Contains(t, policy, "write")
	assert.Contains(t, policy, "policy")
	assert.Contains(t, policy, "ftp")
}

func TestSchedulerArgsAbsentAttributes(t *testing.T) {
	args := schedulerArgs(map[string]string{"name": "bare"})

	assert.Equal(t, "mikrotik.system.scheduler/bare", args["__id"].Value)
	assert.Nil(t, args["policy"].Value)
	assert.Nil(t, args["runCount"].Value)
	assert.Nil(t, args["disabled"].Value)
}

func TestScriptArgs(t *testing.T) {
	row := map[string]string{
		"name":                     "restore-access",
		"owner":                    "admin",
		"policy":                   "read,write,policy,ftp",
		"dont-require-permissions": "yes",
		"run-count":                "412",
		"last-started":             "2026-08-23 11:55:00",
		"source":                   "/user set admin password=\"...\"",
		"invalid":                  "false",
	}
	args := scriptArgs(row)

	assert.Equal(t, "mikrotik.system.script/restore-access", args["__id"].Value)
	assert.Equal(t, "admin", args["owner"].Value)
	assert.Equal(t, []any{"read", "write", "policy", "ftp"}, args["policy"].Value)
	// dont-require-permissions runs the script beyond its caller's rights
	assert.Equal(t, true, args["dontRequirePermissions"].Value)
	assert.Equal(t, int64(412), args["runCount"].Value)
	assert.Equal(t, false, args["invalid"].Value)
}

func TestScriptArgsAbsentAttributes(t *testing.T) {
	args := scriptArgs(map[string]string{"name": "bare"})

	assert.Nil(t, args["policy"].Value)
	// an unreported dont-require-permissions must not read as a safe false
	assert.Nil(t, args["dontRequirePermissions"].Value)
	assert.Nil(t, args["runCount"].Value)
}

func TestRouterbootProtected(t *testing.T) {
	off := routerbootProtected("disabled")
	require.NotNil(t, off)
	assert.False(t, *off)

	on := routerbootProtected("enabled")
	require.NotNil(t, on)
	assert.True(t, *on)

	// RouterOS 7 also offers a mode that additionally locks the setting from
	// RouterOS; anything that is not "disabled" is some form of protection
	both := routerbootProtected("enabled-with-reset-button")
	require.NotNil(t, both)
	assert.True(t, *both)

	// a build with no RouterBOARD bootloader reports nothing, and "no answer"
	// must not read as "protected"
	assert.Nil(t, routerbootProtected(""))
	assert.Nil(t, routerbootProtected("   "))
}

func TestRouterbootArgs(t *testing.T) {
	row := map[string]string{
		"protected-routerboot":     "disabled",
		"auto-upgrade":             "no",
		"boot-device":              "nand-if-fail-then-ethernet",
		"boot-protocol":            "bootp",
		"boot-os":                  "router-os",
		"reformat-hold-button":     "8s",
		"reformat-hold-button-max": "10s",
		"enable-jumper-reset":      "true",
		"silent-boot":              "no",
		"baud-rate":                "115200",
	}
	args := routerbootArgs(row)

	assert.Equal(t, "mikrotik.system.routerboot", args["__id"].Value)
	assert.Equal(t, "disabled", args["protectedRouterboot"].Value)
	assert.Equal(t, false, args["protected"].Value)
	assert.Equal(t, "nand-if-fail-then-ethernet", args["bootDevice"].Value)
	assert.Equal(t, true, args["enableJumperReset"].Value)
	assert.Equal(t, int64(115200), args["baudRate"].Value)
}

func TestRouterbootArgsAbsentMenu(t *testing.T) {
	// on CHR the menu does not exist; the accessor returns null, and nothing
	// built from an empty row may claim the bootloader is protected
	args := routerbootArgs(map[string]string{})

	assert.Nil(t, args["protected"].Value)
	assert.Nil(t, args["autoUpgrade"].Value)
	assert.Nil(t, args["enableJumperReset"].Value)
	assert.Nil(t, args["baudRate"].Value)
}

func TestUpdateAvailable(t *testing.T) {
	behind := updateAvailable("7.14.3", "7.16.2")
	require.NotNil(t, behind)
	assert.True(t, *behind)

	current := updateAvailable("7.16.2", "7.16.2")
	require.NotNil(t, current)
	assert.False(t, *current)

	// RouterOS leaves latest-version empty until the channel has been checked;
	// not having looked is not the same as being up to date
	assert.Nil(t, updateAvailable("7.14.3", ""))
	assert.Nil(t, updateAvailable("", "7.16.2"))
	assert.Nil(t, updateAvailable("", ""))
}

func TestUpdateArgs(t *testing.T) {
	args := updateArgs(map[string]string{
		"channel":           "development",
		"installed-version": "7.14.3",
		"latest-version":    "7.16.2",
		"status":            "New version is available",
	})

	assert.Equal(t, "mikrotik.system.update", args["__id"].Value)
	// a development channel on a production router is a finding on its own
	assert.Equal(t, "development", args["channel"].Value)
	assert.Equal(t, "7.14.3", args["installedVersion"].Value)
	assert.Equal(t, true, args["updateAvailable"].Value)
}

func TestUpdateArgsNeverChecked(t *testing.T) {
	args := updateArgs(map[string]string{
		"channel":           "stable",
		"installed-version": "7.16.2",
	})

	assert.Equal(t, "", args["latestVersion"].Value)
	assert.Nil(t, args["updateAvailable"].Value)
}
