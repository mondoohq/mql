// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

func (a *mqlAristaEos) eapi() (*mqlAristaEosEapi, error) {
	eosClient := aristaClient(a.MqlRuntime)

	status, err := eosClient.EapiStatus()
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(a.MqlRuntime, "arista.eos.eapi", map[string]*llx.RawData{
		"enabled":                    llx.BoolData(status.Enabled),
		"httpServerConfigured":       llx.BoolData(status.HttpServer.Configured),
		"httpServerRunning":          llx.BoolData(status.HttpServer.Running),
		"httpServerPort":             llx.IntData(status.HttpServer.Port),
		"httpsServerConfigured":      llx.BoolData(status.HttpsServer.Configured),
		"httpsServerRunning":         llx.BoolData(status.HttpsServer.Running),
		"httpsServerPort":            llx.IntData(status.HttpsServer.Port),
		"localHttpServerConfigured":  llx.BoolData(status.LocalHttpServer.Configured),
		"localHttpServerRunning":     llx.BoolData(status.LocalHttpServer.Running),
		"localHttpServerPort":        llx.IntData(status.LocalHttpServer.Port),
		"unixSocketServerConfigured": llx.BoolData(status.UnixSocketServer.Configured),
		"unixSocketServerRunning":    llx.BoolData(status.UnixSocketServer.Running),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosEapi), nil
}

func (v *mqlAristaEosEapi) id() (string, error) {
	return "arista.eos.eapi", nil
}

func (a *mqlAristaEos) vrrp() (*mqlAristaEosVrrp, error) {
	res, err := CreateResource(a.MqlRuntime, "arista.eos.vrrp", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosVrrp), nil
}

func (v *mqlAristaEosVrrp) id() (string, error) {
	return "arista.eos.vrrp", nil
}

func (v *mqlAristaEosVrrp) groups() ([]any, error) {
	eosClient := aristaClient(v.MqlRuntime)

	groups, err := eosClient.VrrpGroups()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(groups))
	for _, g := range groups {
		mqlGroup, err := CreateResource(v.MqlRuntime, "arista.eos.vrrp.group", map[string]*llx.RawData{
			"interface":             llx.StringData(g.Interface),
			"groupId":               llx.IntData(g.GroupId),
			"version":               llx.IntData(g.Version),
			"priority":              llx.IntData(g.Priority),
			"preempt":               llx.BoolData(g.Preempt),
			"preemptDelay":          llx.IntData(g.PreemptDelay),
			"state":                 llx.StringData(g.State),
			"primaryIp":             llx.StringData(g.PrimaryIp),
			"virtualMac":            llx.StringData(g.VirtualMac),
			"advertisementInterval": llx.FloatData(g.AdvertisementInterval),
			"skewTime":              llx.FloatData(g.SkewTime),
			"virtualIps":            llx.ArrayData(convert.SliceAnyToInterface[string](g.VirtualIps), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

func (g *mqlAristaEosVrrpGroup) id() (string, error) {
	if g.Interface.Error != nil {
		return "", g.Interface.Error
	}
	if g.GroupId.Error != nil {
		return "", g.GroupId.Error
	}
	return "arista.eos.vrrp.group/" + g.Interface.Data + "/" + strconv.FormatInt(g.GroupId.Data, 10), nil
}
