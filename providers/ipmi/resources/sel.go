// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ipmi/connection"
	"go.mondoo.com/mql/providers/ipmi/connection/client"
)

// mqlIpmiSelInternal memoizes the Get SEL Info read that every field except
// loggingEnabled comes out of.
type mqlIpmiSelInternal struct {
	lock sync.Mutex
	info *client.SELInfo
	err  error
	done bool
}

func (r *mqlIpmiSel) id() (string, error) {
	return "ipmi.sel", nil
}

func (r *mqlIpmiSel) load() (*client.SELInfo, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.done {
		return r.info, r.err
	}

	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	r.info, r.err = conn.Client().SELInfo()
	r.done = true
	return r.info, r.err
}

func (r *mqlIpmiSel) version() (string, error) {
	info, err := r.load()
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

func (r *mqlIpmiSel) entryCount() (int64, error) {
	info, err := r.load()
	if err != nil {
		return 0, err
	}
	return info.Entries, nil
}

func (r *mqlIpmiSel) freeSpaceBytes() (int64, error) {
	info, err := r.load()
	if err != nil {
		return 0, err
	}
	return info.FreeSpaceBytes, nil
}

func (r *mqlIpmiSel) lastAddTime() (*time.Time, error) {
	info, err := r.load()
	if err != nil {
		return nil, err
	}
	if info.LastAddTime == nil {
		r.LastAddTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return info.LastAddTime, nil
}

func (r *mqlIpmiSel) lastEraseTime() (*time.Time, error) {
	info, err := r.load()
	if err != nil {
		return nil, err
	}
	if info.LastEraseTime == nil {
		r.LastEraseTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return info.LastEraseTime, nil
}

func (r *mqlIpmiSel) overflow() (bool, error) {
	info, err := r.load()
	if err != nil {
		return false, err
	}
	return info.Overflow, nil
}

func (r *mqlIpmiSel) supportsDelete() (bool, error) {
	info, err := r.load()
	if err != nil {
		return false, err
	}
	return info.SupportsDelete, nil
}

func (r *mqlIpmiSel) supportsPartialAdd() (bool, error) {
	info, err := r.load()
	if err != nil {
		return false, err
	}
	return info.SupportsPartialAdd, nil
}

func (r *mqlIpmiSel) supportsReserve() (bool, error) {
	info, err := r.load()
	if err != nil {
		return false, err
	}
	return info.SupportsReserve, nil
}

func (r *mqlIpmiSel) supportsGetAllocationInfo() (bool, error) {
	info, err := r.load()
	if err != nil {
		return false, err
	}
	return info.SupportsGetAllocationInfo, nil
}

// loggingEnabled comes from Get BMC Global Enables rather than from Get SEL
// Info, because whether the controller writes to the log is a controller
// setting rather than a property of the log itself.
func (r *mqlIpmiSel) loggingEnabled() (bool, error) {
	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	return conn.Client().SystemEventLoggingEnabled()
}
