// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/arista/resources/eos"
	"go.mondoo.com/mql/types"
)

// =====================================================================
// arista.eos.dot1x
// =====================================================================

func (a *mqlAristaEosDot1x) id() (string, error) {
	return "arista.eos.dot1x", nil
}

func (a *mqlAristaEos) dot1x() (*mqlAristaEosDot1x, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cfg := eos.ParseDot1xConfig(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.dot1x", map[string]*llx.RawData{
		"systemAuthControl":      llx.BoolData(cfg.SystemAuthControl),
		"dynamicAuthorization":   llx.BoolData(cfg.DynamicAuthorization),
		"macBasedAuthHoldPeriod": llx.IntData(int64(cfg.MacBasedAuthHoldPeriod)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosDot1x), nil
}

func (a *mqlAristaEosDot1xInterface) id() (string, error) {
	return "arista.eos.dot1x.interface/" + a.Interface.Data, a.Interface.Error
}

func (a *mqlAristaEosDot1x) interfaces() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cfg := eos.ParseDot1xConfig(rc)

	res := make([]any, 0, len(cfg.Interfaces))
	for _, i := range cfg.Interfaces {
		mqlIface, err := CreateResource(a.MqlRuntime, "arista.eos.dot1x.interface", map[string]*llx.RawData{
			"interface":        llx.StringData(i.Interface),
			"paeMode":          llx.StringData(i.PaeMode),
			"portControl":      llx.StringData(i.PortControl),
			"hostMode":         llx.StringData(i.HostMode),
			"macBasedAuth":     llx.BoolData(i.MacBasedAuth),
			"reauthentication": llx.BoolData(i.Reauthentication),
			"reauthPeriod":     llx.IntData(int64(i.ReauthPeriod)),
			"txPeriod":         llx.IntData(int64(i.TxPeriod)),
			"quietPeriod":      llx.IntData(int64(i.QuietPeriod)),
			"eapolDisabled":    llx.BoolData(i.EapolDisabled),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIface)
	}
	return res, nil
}

// =====================================================================
// arista.eos.dhcpSnooping
// =====================================================================

func (a *mqlAristaEosDhcpSnooping) id() (string, error) {
	return "arista.eos.dhcpSnooping", nil
}

func (a *mqlAristaEos) dhcpSnooping() (*mqlAristaEosDhcpSnooping, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cfg := eos.ParseDhcpSnooping(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.dhcpSnooping", map[string]*llx.RawData{
		"enabled":           llx.BoolData(cfg.Enabled),
		"vlans":             llx.ArrayData(stringSliceToAny(cfg.Vlans), types.String),
		"insertOption82":    llx.BoolData(cfg.InsertOption82),
		"bridging":          llx.BoolData(cfg.Bridging),
		"trustedInterfaces": llx.ArrayData(stringSliceToAny(cfg.TrustedInterfaces), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosDhcpSnooping), nil
}

// =====================================================================
// arista.eos.arpInspection
// =====================================================================

func (a *mqlAristaEosArpInspection) id() (string, error) {
	return "arista.eos.arpInspection", nil
}

func (a *mqlAristaEos) arpInspection() (*mqlAristaEosArpInspection, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cfg := eos.ParseArpInspection(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.arpInspection", map[string]*llx.RawData{
		"enabled":           llx.BoolData(cfg.Enabled),
		"vlans":             llx.ArrayData(stringSliceToAny(cfg.Vlans), types.String),
		"trustedInterfaces": llx.ArrayData(stringSliceToAny(cfg.TrustedInterfaces), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosArpInspection), nil
}
