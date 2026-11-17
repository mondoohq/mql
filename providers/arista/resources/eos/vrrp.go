// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import "errors"

// VrrpGroup represents a single VRRP virtual router as returned by
// `show vrrp all | json`. Field tags follow the EOS eAPI JSON schema.
type VrrpGroup struct {
	Interface             string   `json:"interface"`
	GroupId               int64    `json:"groupId"`
	Version               int64    `json:"version"`
	Priority              int64    `json:"priority"`
	Preempt               bool     `json:"preempt"`
	PreemptDelay          int64    `json:"preemptDelay"`
	State                 string   `json:"groupState"`
	PrimaryIp             string   `json:"primaryIp"`
	VirtualMac            string   `json:"virtualMac"`
	AdvertisementInterval float64  `json:"advertisementInterval"`
	SkewTime              float64  `json:"skewTime"`
	VirtualIps            []string `json:"virtualIps"`
}

type showVrrp struct {
	VirtualRouters []VrrpGroup `json:"virtualRouters"`
}

func (s *showVrrp) GetCmd() string {
	return "show vrrp all"
}

// VrrpGroups returns the VRRP groups configured on the device. Returns an
// empty slice if VRRP is not configured (the EOS response is an empty
// virtualRouters array, not an error), and on a platform without VRRP, where
// EOS refuses the command as "% Unavailable command (not supported on this
// hardware platform)" (cEOS before 4.35, for example).
func (eos *Eos) VrrpGroups() ([]VrrpGroup, error) {
	shRsp := &showVrrp{}
	if err := eos.runJSON(shRsp.GetCmd(), shRsp); err != nil {
		if IsUnsupportedOnPlatform(err) {
			return []VrrpGroup{}, nil
		}
		return nil, err
	}
	return shRsp.VirtualRouters, nil
}

// IsUnsupportedOnPlatform reports whether the device refused a command
// because its platform does not have the feature, which leaves nothing of it
// to report.
func IsUnsupportedOnPlatform(err error) bool {
	var cerr *CommandError
	return errors.As(err, &cerr) && cerr.HasMessage("not supported on this hardware platform")
}
