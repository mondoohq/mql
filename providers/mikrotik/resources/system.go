// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- system.script ---

func scriptArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                   llx.StringData("mikrotik.system.script/" + row["name"]),
		"name":                   llx.StringData(row["name"]),
		"owner":                  llx.StringData(row["owner"]),
		"policy":                 listField(row, "policy"),
		"dontRequirePermissions": boolField(row, "dont-require-permissions"),
		"runCount":               intField(row, "run-count"),
		"lastStarted":            llx.StringData(row["last-started"]),
		"source":                 llx.StringData(row["source"]),
		"invalid":                boolField(row, "invalid"),
		"comment":                llx.StringData(row["comment"]),
	}
}

func newMikrotikScript(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.system.script", scriptArgs(row))
}

func (r *mqlMikrotik) scripts() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/system/script")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikScript)
}

// --- system.scheduler ---

type mqlMikrotikSystemSchedulerInternal struct {
	cacheOnEvent string
}

func schedulerArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData("mikrotik.system.scheduler/" + row["name"]),
		"name":      llx.StringData(row["name"]),
		"startDate": llx.StringData(row["start-date"]),
		"startTime": llx.StringData(row["start-time"]),
		"interval":  llx.StringData(row["interval"]),
		"onEvent":   llx.StringData(row["on-event"]),
		"owner":     llx.StringData(row["owner"]),
		"policy":    listField(row, "policy"),
		"runCount":  intField(row, "run-count"),
		"nextRun":   llx.StringData(row["next-run"]),
		"disabled":  boolField(row, "disabled"),
		"comment":   llx.StringData(row["comment"]),
	}
}

func newMikrotikScheduler(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.system.scheduler", schedulerArgs(row))
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikSystemScheduler).cacheOnEvent = strings.TrimSpace(row["on-event"])
	return res, nil
}

func (r *mqlMikrotik) schedulers() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/system/scheduler")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikScheduler)
}

// script resolves the task's on-event against the already-cached script
// listing. A task's on-event is usually inline RouterOS commands rather than a
// script name, so a miss is a legitimate null rather than an error.
func (r *mqlMikrotikSystemScheduler) script() (*mqlMikrotikSystemScript, error) {
	null := func() (*mqlMikrotikSystemScript, error) {
		r.Script.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if r.cacheOnEvent == "" {
		return null()
	}
	rows, err := mikrotikConn(r.MqlRuntime).Print("/system/script")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row["name"] == r.cacheOnEvent {
			res, err := newMikrotikScript(r.MqlRuntime, row)
			if err != nil {
				return nil, err
			}
			return res.(*mqlMikrotikSystemScript), nil
		}
	}
	return null()
}

// --- system.routerboot ---

// routerbootProtected reports whether RouterBOOT is protected against a
// bootloader-level takeover, or nil when the device did not report the
// setting, which is the case on builds with no RouterBOARD bootloader.
func routerbootProtected(mode string) *bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return nil
	}
	protected := mode != "disabled"
	return &protected
}

func routerbootArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                  llx.StringData("mikrotik.system.routerboot"),
		"protectedRouterboot":   llx.StringData(row["protected-routerboot"]),
		"protected":             llx.BoolDataPtr(routerbootProtected(row["protected-routerboot"])),
		"autoUpgrade":           boolField(row, "auto-upgrade"),
		"bootDevice":            llx.StringData(row["boot-device"]),
		"bootProtocol":          llx.StringData(row["boot-protocol"]),
		"bootOs":                llx.StringData(row["boot-os"]),
		"reformatHoldButton":    llx.StringData(row["reformat-hold-button"]),
		"reformatHoldButtonMax": llx.StringData(row["reformat-hold-button-max"]),
		"enableJumperReset":     boolField(row, "enable-jumper-reset"),
		"enterSetupOn":          llx.StringData(row["enter-setup-on"]),
		"silentBoot":            boolField(row, "silent-boot"),
		"forceBackupBooter":     boolField(row, "force-backup-booter"),
		"cpuFrequency":          llx.StringData(row["cpu-frequency"]),
		"baudRate":              intField(row, "baud-rate"),
	}
}

func (r *mqlMikrotik) routerboot() (*mqlMikrotikSystemRouterboot, error) {
	// the menu does not exist on CHR and other non-RouterBOARD builds
	row, err := mikrotikConn(r.MqlRuntime).PrintOneOptional("/system/routerboard/settings")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.Routerboot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.system.routerboot", routerbootArgs(row))
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikSystemRouterboot), nil
}

func initMikrotikSystemRouterboot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOneOptional("/system/routerboard/settings")
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu("/system/routerboard/settings")
	}
	return routerbootArgs(row), nil, nil
}

// --- system.update ---

// updateAvailable compares the version offered on the channel against the
// installed one. It is nil until the device has checked the channel: not having
// looked is not the same as being up to date.
func updateAvailable(installed, latest string) *bool {
	installed = strings.TrimSpace(installed)
	latest = strings.TrimSpace(latest)
	if installed == "" || latest == "" {
		return nil
	}
	behind := installed != latest
	return &behind
}

func updateArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData("mikrotik.system.update"),
		"channel":          llx.StringData(row["channel"]),
		"installedVersion": llx.StringData(row["installed-version"]),
		"latestVersion":    llx.StringData(row["latest-version"]),
		"updateAvailable":  llx.BoolDataPtr(updateAvailable(row["installed-version"], row["latest-version"])),
		"status":           llx.StringData(row["status"]),
	}
}

func (r *mqlMikrotik) packageUpdate() (*mqlMikrotikSystemUpdate, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOneOptional("/system/package/update")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.PackageUpdate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.system.update", updateArgs(row))
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikSystemUpdate), nil
}

func initMikrotikSystemUpdate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOneOptional("/system/package/update")
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu("/system/package/update")
	}
	return updateArgs(row), nil, nil
}
