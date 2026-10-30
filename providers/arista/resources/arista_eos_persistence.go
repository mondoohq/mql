// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/arista/resources/eos"
)

// =====================================================================
// arista.eos.eventHandler (list)
// =====================================================================

func (a *mqlAristaEosEventHandler) id() (string, error) {
	return "arista.eos.eventHandler/" + a.Name.Data, a.Name.Error
}

func (a *mqlAristaEos) eventHandlers() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	handlers := eos.ParseEventHandlers(rc)

	res := make([]any, 0, len(handlers))
	for _, h := range handlers {
		mqlHandler, err := CreateResource(a.MqlRuntime, "arista.eos.eventHandler", map[string]*llx.RawData{
			"name":          llx.StringData(h.Name),
			"trigger":       llx.StringData(h.Trigger),
			"triggerDetail": llx.StringData(h.TriggerDetail),
			"actionType":    llx.StringData(h.ActionType),
			"action":        llx.StringData(h.Action),
			"delay":         llx.IntData(int64(h.Delay)),
			"timeout":       llx.IntData(int64(h.Timeout)),
			"asynchronous":  llx.BoolData(h.Asynchronous),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlHandler)
	}
	return res, nil
}

// =====================================================================
// arista.eos.schedule (list)
// =====================================================================

func (a *mqlAristaEosSchedule) id() (string, error) {
	return "arista.eos.schedule/" + a.Name.Data, a.Name.Error
}

func (a *mqlAristaEos) schedules() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	tasks := eos.ParseScheduledTasks(rc)

	res := make([]any, 0, len(tasks))
	for _, t := range tasks {
		mqlTask, err := CreateResource(a.MqlRuntime, "arista.eos.schedule", map[string]*llx.RawData{
			"name":        llx.StringData(t.Name),
			"interval":    llx.IntData(int64(t.Interval)),
			"maxLogFiles": llx.IntData(int64(t.MaxLogFiles)),
			"timeout":     llx.IntData(int64(t.Timeout)),
			"command":     llx.StringData(t.Command),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTask)
	}
	return res, nil
}

// =====================================================================
// arista.eos.extension (list)
// =====================================================================

func (a *mqlAristaEosExtension) id() (string, error) {
	return "arista.eos.extension/" + a.Name.Data, a.Name.Error
}

func (a *mqlAristaEos) extensions() ([]any, error) {
	eosClient := aristaClient(a.MqlRuntime)
	resp, err := eosClient.Extensions()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(resp.Extensions))
	for name, ext := range resp.Extensions {
		mqlExt, err := CreateResource(a.MqlRuntime, "arista.eos.extension", map[string]*llx.RawData{
			"name":        llx.StringData(name),
			"version":     llx.StringData(ext.Version),
			"release":     llx.StringData(ext.Release),
			"presence":    llx.StringData(ext.Presence),
			"status":      llx.StringData(ext.Status),
			"numPackages": llx.IntData(ext.NumPackages),
			"error":       llx.BoolData(ext.Error),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlExt)
	}
	return res, nil
}

// =====================================================================
// arista.eos.bootConfig
// =====================================================================

func (a *mqlAristaEosBootConfig) id() (string, error) {
	return "arista.eos.bootConfig", nil
}

func (a *mqlAristaEos) bootConfig() (*mqlAristaEosBootConfig, error) {
	eosClient := aristaClient(a.MqlRuntime)
	cfg, err := eosClient.BootConfig()
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(a.MqlRuntime, "arista.eos.bootConfig", map[string]*llx.RawData{
		"softwareImage": llx.StringData(cfg.SoftwareImage),
		"consoleSpeed":  llx.IntData(cfg.ConsoleSpeed),
		"memoryTest":    llx.StringData(cfg.MemoryTest),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosBootConfig), nil
}

// =====================================================================
// arista.eos.startupConfig
// =====================================================================

func (a *mqlAristaEosStartupConfig) id() (string, error) {
	return "arista.eos.startupConfig", nil
}

type mqlAristaEosStartupConfigInternal struct {
	contentFetched atomic.Bool
	contentCache   string
	contentErr     error
	lock           sync.Mutex
}

// fetchContent caches the startup-config so the drift comparison and a direct
// read of `content` share one fetch.
func (a *mqlAristaEosStartupConfig) fetchContent() (string, error) {
	if a.contentFetched.Load() {
		return a.contentCache, a.contentErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.contentFetched.Load() {
		return a.contentCache, a.contentErr
	}
	eosClient := aristaClient(a.MqlRuntime)
	a.contentCache, a.contentErr = eosClient.StartupConfig()
	a.contentFetched.Store(true)
	return a.contentCache, a.contentErr
}

func (a *mqlAristaEosStartupConfig) content() (string, error) {
	return a.fetchContent()
}

func (a *mqlAristaEos) startupConfig() (*mqlAristaEosStartupConfig, error) {
	res, err := CreateResource(a.MqlRuntime, "arista.eos.startupConfig", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosStartupConfig), nil
}

// fetchStartupConfig returns the startup-config through the cached
// arista.eos.startupConfig resource, so repeated readers share one fetch.
func fetchStartupConfig(runtime *plugin.Runtime) (string, error) {
	sc, err := CreateResource(runtime, "arista.eos.startupConfig", map[string]*llx.RawData{})
	if err != nil {
		return "", err
	}
	return sc.(*mqlAristaEosStartupConfig).fetchContent()
}

// configSavedToStartup reports whether a reload would bring the device back in
// the state it is in now.
//
// Both sides must be rendered the same way. The cached running-config is
// fetched with `all`, which expands every default so the parsers see the
// effective state; the startup-config never carries those defaults. Comparing
// those two returned false on every device, including one saved seconds
// earlier, so this fetches its own plainly-rendered copy instead.
func (a *mqlAristaEos) configSavedToStartup() (bool, error) {
	// Not the cached fetch: that one is `all`, and it also strips banners,
	// either of which would show up as drift that is not there.
	eosClient := aristaClient(a.MqlRuntime)
	running, err := eosClient.RunningConfigPlain()
	if err != nil {
		return false, err
	}
	startup, err := fetchStartupConfig(a.MqlRuntime)
	if err != nil {
		return false, err
	}

	return eos.NormalizeConfigForComparison(running) ==
		eos.NormalizeConfigForComparison(startup), nil
}
