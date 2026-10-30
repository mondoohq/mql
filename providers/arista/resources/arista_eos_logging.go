// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/arista/resources/eos"
)

// =====================================================================
// arista.eos.logging
// =====================================================================

func (a *mqlAristaEosLogging) id() (string, error) {
	return "arista.eos.logging", nil
}

func (a *mqlAristaEos) logging() (*mqlAristaEosLogging, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	c := eos.ParseLoggingConfig(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.logging", map[string]*llx.RawData{
		"enabled":           llx.BoolData(c.Enabled),
		"trapSeverity":      llx.StringData(c.TrapSeverity),
		"consoleSeverity":   llx.StringData(c.ConsoleSeverity),
		"monitorSeverity":   llx.StringData(c.MonitorSeverity),
		"bufferedSeverity":  llx.StringData(c.BufferedSeverity),
		"bufferedSize":      llx.IntData(int64(c.BufferedSize)),
		"persistentEnabled": llx.BoolData(c.PersistentEnabled),
		"persistentSize":    llx.IntData(int64(c.PersistentSize)),
		"sourceInterface":   llx.StringData(c.SourceInterface),
		"facility":          llx.StringData(c.Facility),
		"timestampFormat":   llx.StringData(c.TimestampFormat),
		"hostnameFormat":    llx.StringData(c.HostnameFormat),
		"rfc5424Format":     llx.BoolData(c.Rfc5424Format),
		"synchronous":       llx.BoolData(c.Synchronous),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosLogging), nil
}

// =====================================================================
// arista.eos.logging.host (list)
// =====================================================================

// id keys a collector on the tuple that makes it distinct on the device: the
// same address can be configured twice in different VRFs, twice in one VRF on
// different ports, or twice on one port over different transports. Protocol is
// part of the key for that last case: a collector reached over TCP and one
// reached over plaintext UDP are different egress paths, and collapsing them
// hides whichever was parsed second behind the other's transport.
func (a *mqlAristaEosLoggingHost) id() (string, error) {
	if a.Host.Error != nil {
		return "", a.Host.Error
	}
	if a.Vrf.Error != nil {
		return "", a.Vrf.Error
	}
	if a.Port.Error != nil {
		return "", a.Port.Error
	}
	if a.Protocol.Error != nil {
		return "", a.Protocol.Error
	}
	return "arista.eos.logging.host/" + a.Vrf.Data + "/" + a.Host.Data + "/" +
		strconv.FormatInt(a.Port.Data, 10) + "/" + a.Protocol.Data, nil
}

func (a *mqlAristaEosLogging) hosts() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	c := eos.ParseLoggingConfig(rc)

	res := make([]any, 0, len(c.Hosts))
	for _, h := range c.Hosts {
		mqlHost, err := CreateResource(a.MqlRuntime, "arista.eos.logging.host", map[string]*llx.RawData{
			"host":     llx.StringData(h.Host),
			"port":     llx.IntData(int64(h.Port)),
			"protocol": llx.StringData(h.Protocol),
			"vrf":      llx.StringData(h.VRF),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlHost)
	}
	return res, nil
}

// =====================================================================
// arista.eos banners
// =====================================================================

func (a *mqlAristaEos) loginBanner() (string, error) {
	rc, err := fetchRawRunningConfig(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	return eos.ParseBanners(rc).Login, nil
}

func (a *mqlAristaEos) motdBanner() (string, error) {
	rc, err := fetchRawRunningConfig(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	return eos.ParseBanners(rc).Motd, nil
}
