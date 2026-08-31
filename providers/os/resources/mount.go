// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/mount"
	"go.mondoo.com/mql/types"
)

func (m *mqlMount) id() (string, error) {
	return "mount", nil
}

func (m *mqlMount) list() ([]any, error) {
	// find suitable mount manager
	conn := m.MqlRuntime.Connection.(shared.Connection)
	mm, err := mount.ResolveManager(conn)
	if mm == nil || err != nil {
		return nil, fmt.Errorf("could not detect suitable mount manager for platform")
	}

	// retrieve all system packages
	osMounts, err := mm.List()
	if err != nil {
		return nil, fmt.Errorf("could not retrieve mount list for platform")
	}
	log.Debug().Int("mounts", len(osMounts)).Msg("mql[mount]> mounted volumes")

	// create MQL mount entry resources for each mount
	mountEntries := make([]any, len(osMounts))
	for i, osMount := range osMounts {
		// convert options
		opts := map[string]any{}
		for k := range osMount.Options {
			opts[k] = osMount.Options[k]
		}

		o, err := CreateResource(m.MqlRuntime, "mount.point", map[string]*llx.RawData{
			"device":  llx.StringData(osMount.Device),
			"path":    llx.StringData(osMount.MountPoint),
			"fstype":  llx.StringData(osMount.FSType),
			"options": llx.MapData(opts, types.String),
			"mounted": llx.BoolTrue,
		})
		if err != nil {
			return nil, err
		}
		mountEntries[i] = o.(*mqlMountPoint)
	}

	// return the mounts as new entries
	return mountEntries, nil
}

func (m *mqlMountPoint) id() (string, error) {
	return m.Path.Data, nil
}

func initMountPoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	pathRaw := args["path"]
	if pathRaw == nil {
		return args, nil, nil
	}

	path, ok := pathRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	obj, err := CreateResource(runtime, "mount", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	mount := obj.(*mqlMount)

	list := mount.GetList()
	if list.Error != nil {
		return nil, nil, list.Error
	}

	for i := range list.Data {
		mp := list.Data[i].(*mqlMountPoint)
		if mp.Path.Data == path {
			return nil, mp, nil
		}
	}

	return map[string]*llx.RawData{
		"device":  llx.StringData(""),
		"path":    llx.StringData(path),
		"fstype":  llx.StringData(""),
		"options": llx.MapData(nil, types.String),
		"mounted": llx.BoolFalse,
	}, nil, nil
}

type mqlMountInternal struct {
	dfFetched bool
	dfEntries map[string]*mount.DfEntry
	lock      sync.Mutex
}

// fetchDfEntries runs "df -P -k" once and caches the result for all mount points.
func (m *mqlMount) fetchDfEntries() (map[string]*mount.DfEntry, error) {
	if m.dfFetched {
		return m.dfEntries, nil
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.dfFetched {
		return m.dfEntries, nil
	}

	o, err := CreateResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("df -P -k"),
	})
	if err != nil {
		// df may not exist on this system (e.g., minimal containers)
		log.Debug().Err(err).Msg("mql[mount]> df command not available")
		m.dfEntries = map[string]*mount.DfEntry{}
		m.dfFetched = true
		return m.dfEntries, nil
	}
	cmd := o.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return nil, err
	}
	if run.exitcode != 0 {
		// df failed (not installed, no permission, etc.) — return empty, not error
		log.Debug().Str("stderr", run.stderr).Msg("mql[mount]> df command failed")
		m.dfEntries = map[string]*mount.DfEntry{}
		m.dfFetched = true
		return m.dfEntries, nil
	}

	m.dfEntries = mount.ParseDf(strings.NewReader(run.stdout))
	m.dfFetched = true
	return m.dfEntries, nil
}

func (m *mqlMountPoint) fetchDfEntry() (*mount.DfEntry, error) {
	obj, err := CreateResource(m.MqlRuntime, "mount", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	mnt := obj.(*mqlMount)
	entries, err := mnt.fetchDfEntries()
	if err != nil {
		return nil, err
	}
	return entries[m.Path.Data], nil
}

func (m *mqlMountPoint) size() (int64, error) {
	entry, err := m.fetchDfEntry()
	if err != nil {
		return 0, err
	}
	if entry == nil {
		m.Size.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return entry.Size, nil
}

func (m *mqlMountPoint) used() (int64, error) {
	entry, err := m.fetchDfEntry()
	if err != nil {
		return 0, err
	}
	if entry == nil {
		m.Used.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return entry.Used, nil
}

func (m *mqlMountPoint) available() (int64, error) {
	entry, err := m.fetchDfEntry()
	if err != nil {
		return 0, err
	}
	if entry == nil {
		m.Available.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return entry.Available, nil
}
