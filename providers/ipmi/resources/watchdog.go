// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/providers/ipmi/connection"
	"go.mondoo.com/mql/providers/ipmi/connection/client"
)

// mqlIpmiWatchdogInternal memoizes the single Get Watchdog Timer read that
// every field of the resource comes out of.
type mqlIpmiWatchdogInternal struct {
	lock sync.Mutex
	wd   *client.Watchdog
	err  error
	done bool
}

func (r *mqlIpmiWatchdog) id() (string, error) {
	return "ipmi.watchdog", nil
}

func (r *mqlIpmiWatchdog) load() (*client.Watchdog, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.done {
		return r.wd, r.err
	}

	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	r.wd, r.err = conn.Client().Watchdog()
	r.done = true
	return r.wd, r.err
}

func (r *mqlIpmiWatchdog) running() (bool, error) {
	wd, err := r.load()
	if err != nil {
		return false, err
	}
	return wd.Running, nil
}

func (r *mqlIpmiWatchdog) dontLog() (bool, error) {
	wd, err := r.load()
	if err != nil {
		return false, err
	}
	return wd.DontLog, nil
}

func (r *mqlIpmiWatchdog) timerUse() (string, error) {
	wd, err := r.load()
	if err != nil {
		return "", err
	}
	return wd.TimerUse, nil
}

func (r *mqlIpmiWatchdog) timeoutAction() (string, error) {
	wd, err := r.load()
	if err != nil {
		return "", err
	}
	return wd.TimeoutAction, nil
}

func (r *mqlIpmiWatchdog) preTimeoutInterrupt() (string, error) {
	wd, err := r.load()
	if err != nil {
		return "", err
	}
	return wd.PreTimeoutInterrupt, nil
}

func (r *mqlIpmiWatchdog) preTimeoutIntervalSeconds() (int64, error) {
	wd, err := r.load()
	if err != nil {
		return 0, err
	}
	return wd.PreTimeoutIntervalSecs, nil
}

func (r *mqlIpmiWatchdog) expiredTimerUses() ([]any, error) {
	wd, err := r.load()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(wd.ExpiredTimerUses))
	for _, use := range wd.ExpiredTimerUses {
		out = append(out, use)
	}
	return out, nil
}

func (r *mqlIpmiWatchdog) initialCountdownSeconds() (float64, error) {
	wd, err := r.load()
	if err != nil {
		return 0, err
	}
	return wd.InitialCountdownSeconds, nil
}

func (r *mqlIpmiWatchdog) presentCountdownSeconds() (float64, error) {
	wd, err := r.load()
	if err != nil {
		return 0, err
	}
	return wd.PresentCountdownSeconds, nil
}
