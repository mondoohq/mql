// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ipmi/connection"
	"go.mondoo.com/mql/providers/ipmi/connection/client"
)

// mqlIpmiLanConfigInternal memoizes the LAN configuration read. Every field
// of the resource comes out of the same set of parameter requests, so
// without this each field would repeat six round trips to the controller.
type mqlIpmiLanConfigInternal struct {
	lock sync.Mutex
	cfg  *client.LanConfig
	err  error
	done bool
}

func (r *mqlIpmiLanConfig) id() (string, error) {
	return "ipmi.lanConfig", nil
}

func (r *mqlIpmiLanConfig) load() (*client.LanConfig, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.done {
		return r.cfg, r.err
	}

	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)
	r.cfg, r.err = conn.Client().LanConfig(client.ChannelSelf)
	r.done = true
	return r.cfg, r.err
}

func (r *mqlIpmiLanConfig) authTypeEnables() (map[string]any, error) {
	cfg, err := r.load()
	if err != nil {
		return nil, err
	}
	if cfg.AuthTypeEnables == nil {
		r.AuthTypeEnables.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	out := make(map[string]any, len(cfg.AuthTypeEnables))
	for level, authTypes := range cfg.AuthTypeEnables {
		values := make([]any, 0, len(authTypes))
		for _, t := range authTypes {
			values = append(values, t)
		}
		out[level] = values
	}
	return out, nil
}

func (r *mqlIpmiLanConfig) cipherSuites() ([]any, error) {
	cfg, err := r.load()
	if err != nil {
		return nil, err
	}
	if cfg.CipherSuites == nil {
		r.CipherSuites.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	out := make([]any, 0, len(cfg.CipherSuites))
	for _, id := range cfg.CipherSuites {
		out = append(out, id)
	}
	return out, nil
}

func (r *mqlIpmiLanConfig) cipherSuitePrivilegeLevels() (map[string]any, error) {
	cfg, err := r.load()
	if err != nil {
		return nil, err
	}
	if cfg.CipherSuitePrivilegeLevels == nil {
		r.CipherSuitePrivilegeLevels.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	out := make(map[string]any, len(cfg.CipherSuitePrivilegeLevels))
	for suite, level := range cfg.CipherSuitePrivilegeLevels {
		out[suite] = level
	}
	return out, nil
}

func (r *mqlIpmiLanConfig) cipherZeroEnabled() (bool, error) {
	cfg, err := r.load()
	if err != nil {
		return false, err
	}
	if cfg.CipherZeroEnabled == nil {
		r.CipherZeroEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *cfg.CipherZeroEnabled, nil
}

func (r *mqlIpmiLanConfig) badPasswordThreshold() (int64, error) {
	cfg, err := r.load()
	if err != nil {
		return 0, err
	}
	if cfg.BadPassword == nil {
		r.BadPasswordThreshold.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return cfg.BadPassword.Threshold, nil
}

func (r *mqlIpmiLanConfig) attemptCountResetIntervalSeconds() (int64, error) {
	cfg, err := r.load()
	if err != nil {
		return 0, err
	}
	if cfg.BadPassword == nil {
		r.AttemptCountResetIntervalSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return cfg.BadPassword.AttemptCountResetIntervalSeconds, nil
}

func (r *mqlIpmiLanConfig) userLockoutIntervalSeconds() (int64, error) {
	cfg, err := r.load()
	if err != nil {
		return 0, err
	}
	if cfg.BadPassword == nil {
		r.UserLockoutIntervalSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return cfg.BadPassword.UserLockoutIntervalSeconds, nil
}

func (r *mqlIpmiLanConfig) invalidPasswordEventEnabled() (bool, error) {
	cfg, err := r.load()
	if err != nil {
		return false, err
	}
	if cfg.BadPassword == nil {
		r.InvalidPasswordEventEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return cfg.BadPassword.InvalidPasswordEventEnabled, nil
}

func (r *mqlIpmiLanConfig) vlanEnabled() (bool, error) {
	cfg, err := r.load()
	if err != nil {
		return false, err
	}
	if cfg.Vlan == nil {
		r.VlanEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return cfg.Vlan.Enabled, nil
}

func (r *mqlIpmiLanConfig) vlanId() (int64, error) {
	cfg, err := r.load()
	if err != nil {
		return 0, err
	}
	if cfg.Vlan == nil {
		r.VlanId.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return cfg.Vlan.ID, nil
}
