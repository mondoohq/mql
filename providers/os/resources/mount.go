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
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
)

func (m *mqlMount) id() (string, error) {
	return "mount", nil
}

// isWindowsRuntime reports whether the asset is a Windows system, where mount
// paths compare without regard to case and capacity comes with the listing.
func isWindowsRuntime(runtime *plugin.Runtime) bool {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return false
	}
	pf := conn.Asset().Platform
	return pf != nil && pf.IsFamily("windows")
}

func (m *mqlMount) list() ([]any, error) {
	// find suitable mount manager
	conn := m.MqlRuntime.Connection.(shared.Connection)
	mm, err := mount.ResolveManager(conn)
	if mm == nil || err != nil {
		return nil, fmt.Errorf("could not detect suitable mount manager for platform: %w", err)
	}

	osMounts, err := mm.List()
	if err != nil {
		// %w keeps the error's kind (ADR 046): a scan that cannot read the
		// mount table has to stay distinguishable from one that was refused.
		return nil, fmt.Errorf("could not retrieve mount list for platform: %w", err)
	}
	log.Debug().Int("mounts", len(osMounts)).Msg("mql[mount]> mounted volumes")

	usage := map[string]*mount.DfEntry{}

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
			"mounted": llx.BoolData(!osMount.Unmounted),
		})
		if err != nil {
			return nil, err
		}
		mountEntries[i] = o.(*mqlMountPoint)
		if osMount.Usage != nil {
			usage[osMount.MountPoint] = osMount.Usage
		}
	}

	m.lock.Lock()
	m.listUsage = usage
	m.lock.Unlock()

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

	matches := mountPathMatcher(isWindowsRuntime(runtime), path)
	for i := range list.Data {
		mp := list.Data[i].(*mqlMountPoint)
		if matches(mp.Path.Data) {
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

// mountPathMatcher returns the test that selects a listed mount point for the
// path a query asked for. Unix paths match exactly. Windows paths match without
// regard to case, slash direction, or a trailing backslash, since C:, C:\ and
// c:\ all name the same volume.
func mountPathMatcher(windowsPaths bool, path string) func(string) bool {
	if !windowsPaths {
		return func(p string) bool { return p == path }
	}
	key := windows.VolumePathKey(path)
	if key == "" {
		return func(string) bool { return false }
	}
	return func(p string) bool { return windows.VolumePathKey(p) == key }
}

type mqlMountInternal struct {
	dfFetched bool
	dfEntries map[string]*mount.DfEntry
	// listUsage is the capacity the mount listing carried itself, keyed by
	// mount path. Windows reports it with the volumes, so no df runs there.
	listUsage map[string]*mount.DfEntry
	lock      sync.Mutex
}

// fetchDfEntries returns the capacity of every mount point, fetched once for
// all of them: from the mount listing on Windows, from "df -P -k" elsewhere.
func (m *mqlMount) fetchDfEntries() (map[string]*mount.DfEntry, error) {
	if isWindowsRuntime(m.MqlRuntime) {
		// GetList runs the listing at most once. Its error is the reason the
		// capacity is unknown, so it reaches the caller instead of a null.
		if list := m.GetList(); list.Error != nil {
			return nil, list.Error
		}
		m.lock.Lock()
		defer m.lock.Unlock()
		return m.listUsage, nil
	}

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
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		// df failed (not installed, no permission, etc.) — return empty, not error
		log.Debug().Str("stderr", cmd.Stderr.Data).Msg("mql[mount]> df command failed")
		m.dfEntries = map[string]*mount.DfEntry{}
		m.dfFetched = true
		return m.dfEntries, nil
	}

	m.dfEntries = mount.ParseDf(strings.NewReader(cmd.Stdout.Data))
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

func (m *mqlMountPoint) blockDevice() (*mqlLsblkEntry, error) {
	// Only a device path can name a block device. Pseudo and network
	// filesystems (tmpfs, proc, overlay, server:/export) are not backed by
	// one, and asking lsblk about them would turn a plain absence into an
	// error on hosts that have no lsblk.
	if !strings.HasPrefix(m.Device.Data, "/dev/") {
		m.BlockDevice.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	entry, err := lookupBlockDevice(m.MqlRuntime, m.Device.Data, m.Path.Data)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		m.BlockDevice.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return entry, nil
}
