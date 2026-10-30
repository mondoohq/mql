// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/arista/resources/eos"
	"go.mondoo.com/mql/types"
)

// =====================================================================
// arista.eos.monitorSession (list)
// =====================================================================

func (a *mqlAristaEosMonitorSession) id() (string, error) {
	return "arista.eos.monitorSession/" + a.Name.Data, a.Name.Error
}

// id keys a source on its session, interface and direction: one session can
// mirror the same interface in both directions with separate source lines.
func (a *mqlAristaEosMonitorSessionSource) id() (string, error) {
	if a.SessionName.Error != nil {
		return "", a.SessionName.Error
	}
	if a.Interface.Error != nil {
		return "", a.Interface.Error
	}
	return "arista.eos.monitorSession.source/" + a.SessionName.Data + "/" +
		a.Interface.Data + "/" + a.Direction.Data, a.Direction.Error
}

func (a *mqlAristaEos) monitorSessions() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	sessions := eos.ParseMonitorSessions(rc)

	res := make([]any, 0, len(sessions))
	for _, s := range sessions {
		sources := make([]any, 0, len(s.Sources))
		for _, src := range s.Sources {
			mqlSource, err := CreateResource(a.MqlRuntime, "arista.eos.monitorSession.source", map[string]*llx.RawData{
				"sessionName": llx.StringData(s.Name),
				"interface":   llx.StringData(src.Interface),
				"direction":   llx.StringData(src.Direction),
			})
			if err != nil {
				return nil, err
			}
			sources = append(sources, mqlSource)
		}

		mqlSession, err := CreateResource(a.MqlRuntime, "arista.eos.monitorSession", map[string]*llx.RawData{
			"name":                  llx.StringData(s.Name),
			"sources":               llx.ArrayData(sources, types.Resource("arista.eos.monitorSession.source")),
			"destinationInterfaces": llx.ArrayData(stringSliceToAny(s.DestinationInterfaces), types.String),
			"tunnelDestinations":    llx.ArrayData(stringSliceToAny(s.TunnelDestinations), types.String),
			"truncateEnabled":       llx.BoolData(s.TruncateEnabled),
			"truncateSize":          llx.IntData(int64(s.TruncateSize)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSession)
	}
	return res, nil
}

// =====================================================================
// arista.eos.sflow
// =====================================================================

func (a *mqlAristaEosSflow) id() (string, error) {
	return "arista.eos.sflow", nil
}

func (a *mqlAristaEos) sflow() (*mqlAristaEosSflow, error) {
	rc, err := runningConfigResource(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cfg, err := rc.fetchSflowConfig()
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(a.MqlRuntime, "arista.eos.sflow", map[string]*llx.RawData{
		"enabled":         llx.BoolData(cfg.Enabled),
		"sampleRate":      llx.IntData(int64(cfg.SampleRate)),
		"pollingInterval": llx.IntData(int64(cfg.PollingInterval)),
		"sourceInterface": llx.StringData(cfg.SourceInterface),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosSflow), nil
}

func (a *mqlAristaEosSflowDestination) id() (string, error) {
	if a.Address.Error != nil {
		return "", a.Address.Error
	}
	if a.Vrf.Error != nil {
		return "", a.Vrf.Error
	}
	return "arista.eos.sflow.destination/" + a.Vrf.Data + "/" + a.Address.Data + "/" +
		strconv.FormatInt(a.Port.Data, 10), a.Port.Error
}

func (a *mqlAristaEosSflow) destinations() ([]any, error) {
	rc, err := runningConfigResource(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cfg, err := rc.fetchSflowConfig()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(cfg.Destinations))
	for _, d := range cfg.Destinations {
		mqlDest, err := CreateResource(a.MqlRuntime, "arista.eos.sflow.destination", map[string]*llx.RawData{
			"address": llx.StringData(d.Address),
			"port":    llx.IntData(int64(d.Port)),
			"vrf":     llx.StringData(d.VRF),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDest)
	}
	return res, nil
}

// =====================================================================
// arista.eos.interface hardening
// =====================================================================

// interfaceHardening looks up the Layer 3 posture of this interface. An
// interface absent from the running-config we parsed falls back to the device
// defaults, which is what an interface configuring none of this has anyway.
func (a *mqlAristaEosInterface) interfaceHardening() (eos.InterfaceHardening, error) {
	if a.Name.Error != nil {
		return eos.InterfaceHardening{}, a.Name.Error
	}
	fallback := eos.InterfaceHardening{
		Interface:            a.Name.Data,
		IcmpRedirectsEnabled: true,
	}

	rc, err := runningConfigResource(a.MqlRuntime)
	if err != nil {
		return fallback, err
	}
	hardening, err := rc.fetchInterfaceHardening()
	if err != nil {
		return eos.InterfaceHardening{}, err
	}
	if h, ok := hardening[a.Name.Data]; ok {
		return h, nil
	}
	return fallback, nil
}

func (a *mqlAristaEosInterface) proxyArpEnabled() (bool, error) {
	h, err := a.interfaceHardening()
	if err != nil {
		return false, err
	}
	return h.ProxyArpEnabled, nil
}

func (a *mqlAristaEosInterface) icmpRedirectsEnabled() (bool, error) {
	h, err := a.interfaceHardening()
	if err != nil {
		return false, err
	}
	return h.IcmpRedirectsEnabled, nil
}

func (a *mqlAristaEosInterface) unicastRpfMode() (string, error) {
	h, err := a.interfaceHardening()
	if err != nil {
		return "", err
	}
	return h.UnicastRpfMode, nil
}
