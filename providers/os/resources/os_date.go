// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/date"
)

type mqlOsDateInternal struct {
	lock    sync.Mutex
	fetched bool
	result  *date.Result

	syncLock    sync.Mutex
	syncFetched bool
	syncResult  *date.TimeSync
}

func (p *mqlOsBase) date() (*mqlOsDate, error) {
	o, err := CreateResource(p.MqlRuntime, "os.date", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return o.(*mqlOsDate), nil
}

func (p *mqlOs) date() (*mqlOsDate, error) {
	base, err := osBase(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	v := base.GetDate()
	if v.Error != nil {
		return nil, v.Error
	}
	return v.Data, nil
}

func (d *mqlOsDate) id() (string, error) {
	return "os.date", nil
}

func (d *mqlOsDate) fetch() (*date.Result, error) {
	if d.fetched {
		return d.result, nil
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.fetched {
		return d.result, nil
	}

	conn := d.MqlRuntime.Connection.(shared.Connection)
	dt, err := date.New(conn)
	if err != nil {
		return nil, err
	}

	res, err := dt.Get()
	if err != nil {
		return nil, err
	}

	d.fetched = true
	d.result = res
	return res, nil
}

func (d *mqlOsDate) time() (*time.Time, error) {
	res, err := d.fetch()
	if err != nil {
		return nil, err
	}
	if res.Time == nil {
		d.Time.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.Time, nil
}

func (d *mqlOsDate) timezone() (string, error) {
	res, err := d.fetch()
	if err != nil {
		return "", err
	}
	return res.Timezone, nil
}

func (d *mqlOsDate) windowsTimezone() (string, error) {
	res, err := d.fetch()
	if err != nil {
		return "", err
	}
	if res.WindowsTimezone == nil {
		d.WindowsTimezone.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *res.WindowsTimezone, nil
}

func (d *mqlOsDate) utcOffset() (int64, error) {
	res, err := d.fetch()
	if err != nil {
		return 0, err
	}
	if res.UTCOffset == nil {
		d.UtcOffset.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return *res.UTCOffset, nil
}

func (d *mqlOsDate) fetchTimeSync() (*date.TimeSync, error) {
	if d.syncFetched {
		return d.syncResult, nil
	}
	d.syncLock.Lock()
	defer d.syncLock.Unlock()
	if d.syncFetched {
		return d.syncResult, nil
	}

	conn := d.MqlRuntime.Connection.(shared.Connection)
	pf := conn.Asset().Platform
	var res *date.TimeSync
	var err error
	switch {
	case pf.IsFamily(inventory.FAMILY_WINDOWS):
		res, err = date.WindowsTimeSync(conn)
	case pf.IsFamily(inventory.FAMILY_DARWIN):
		// Whether macOS is synchronized is only readable with administrator
		// rights (systemsetup, and timed's state under /var/db/timed), so
		// only the configured server is reported.
		res = &date.TimeSync{Source: date.MacOSTimeSource(conn.FileSystem())}
	case pf.IsFamily(inventory.FAMILY_LINUX) && conn.Capabilities().Has(shared.Capability_RunCommand):
		res, err = linuxTimeSync(d.MqlRuntime)
	default:
		res = &date.TimeSync{}
	}
	if err != nil {
		return nil, err
	}

	d.syncFetched = true
	d.syncResult = res
	return res, nil
}

// linuxTimeSync reads the clock's synchronization state from systemd's
// timedated, which reports the kernel's view and so covers every NTP daemon,
// and the source from a running systemd-timesyncd or chronyd.
func linuxTimeSync(runtime *plugin.Runtime) (*date.TimeSync, error) {
	res := &date.TimeSync{}

	if stdout, ok, err := runSystemctl(runtime, "timedatectl show --no-pager"); err != nil {
		return nil, err
	} else if ok {
		if v, found := parseSystemdShowOutput(stdout)["NTPSynchronized"]; found {
			synced := v == "yes"
			res.Synchronized = &synced
		}
	}
	if res.Synchronized == nil {
		// systemd < 239 has no `timedatectl show`
		if stdout, ok, err := runSystemctl(runtime, "timedatectl status --no-pager"); err != nil {
			return nil, err
		} else if ok {
			if synced, found := lookupTimedatectlStatusSynchronized(stdout); found {
				res.Synchronized = &synced
			}
		}
	}

	// Ask systemd-timesyncd only when it runs: a query starts it through
	// D-Bus activation otherwise (see systemd.timesyncd).
	running, err := isSystemdUnitActive(runtime, "systemd-timesyncd")
	if err != nil {
		return nil, err
	}
	if running {
		if stdout, ok, err := runSystemctl(runtime, "timedatectl show-timesync --no-pager"); err != nil {
			return nil, err
		} else if ok {
			res.Source = parseTimesyncProperties(stdout).serverName
		}
	}

	if res.Source == nil || res.Synchronized == nil {
		if stdout, ok, err := runSystemctl(runtime, "chronyc -n -c tracking"); err != nil {
			return nil, err
		} else if ok {
			chrony := date.ParseChronycTracking(stdout)
			if res.Synchronized == nil {
				res.Synchronized = chrony.Synchronized
			}
			if res.Source == nil {
				res.Source = chrony.Source
			}
		}
	}

	// A server the clock is not synchronized to is not its source.
	if res.Synchronized == nil || !*res.Synchronized {
		res.Source = nil
	}
	return res, nil
}

func (d *mqlOsDate) synchronized() (bool, error) {
	res, err := d.fetchTimeSync()
	if err != nil {
		return false, err
	}
	if res.Synchronized == nil {
		d.Synchronized.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return *res.Synchronized, nil
}

func (d *mqlOsDate) timeSource() (string, error) {
	res, err := d.fetchTimeSync()
	if err != nil {
		return "", err
	}
	if res.Source == nil {
		d.TimeSource.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *res.Source, nil
}
