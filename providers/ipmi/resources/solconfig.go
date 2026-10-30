// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ipmi/connection"
	"go.mondoo.com/mql/providers/ipmi/connection/client"
)

// mqlIpmiSolConfigInternal memoizes the Serial-over-LAN configuration read,
// which every field of the resource shares.
type mqlIpmiSolConfigInternal struct {
	lock sync.Mutex
	cfg  *client.SOLConfig
	err  error
	done bool
}

func (r *mqlIpmiSolConfig) id() (string, error) {
	return "ipmi.solConfig", nil
}

func (r *mqlIpmiSolConfig) load() (*client.SOLConfig, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.done {
		return r.cfg, r.err
	}

	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	r.cfg, r.err = conn.Client().SOLConfig(client.ChannelSelf)
	r.done = true
	return r.cfg, r.err
}

func (r *mqlIpmiSolConfig) enabled() (bool, error) {
	cfg, err := r.load()
	if err != nil {
		return false, err
	}
	if cfg.Enabled == nil {
		r.Enabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *cfg.Enabled, nil
}

func (r *mqlIpmiSolConfig) forceEncryption() (bool, error) {
	cfg, err := r.load()
	if err != nil {
		return false, err
	}
	if cfg.Authentication == nil {
		r.ForceEncryption.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return cfg.Authentication.ForceEncryption, nil
}

func (r *mqlIpmiSolConfig) forceAuthentication() (bool, error) {
	cfg, err := r.load()
	if err != nil {
		return false, err
	}
	if cfg.Authentication == nil {
		r.ForceAuthentication.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return cfg.Authentication.ForceAuthentication, nil
}

func (r *mqlIpmiSolConfig) privilegeLevel() (string, error) {
	cfg, err := r.load()
	if err != nil {
		return "", err
	}
	if cfg.Authentication == nil {
		r.PrivilegeLevel.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return cfg.Authentication.PrivilegeLevel, nil
}

func (r *mqlIpmiSolConfig) payloadPort() (int64, error) {
	cfg, err := r.load()
	if err != nil {
		return 0, err
	}
	if cfg.PayloadPort == nil {
		r.PayloadPort.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *cfg.PayloadPort, nil
}
