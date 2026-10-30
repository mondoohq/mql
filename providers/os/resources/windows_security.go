// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func (w *mqlWindowsSecurity) products() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	products, err := windows.GetSecurityProducts(conn)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range products {
		p := products[i]

		mqlProduct, err := CreateResource(w.MqlRuntime, "windows.security.product", map[string]*llx.RawData{
			"type":           llx.StringData(p.Type),
			"guid":           llx.StringData(p.Guid),
			"name":           llx.StringData(p.Name),
			"state":          llx.IntData(p.State),
			"productState":   llx.StringData(p.ProductStatus),
			"signatureState": llx.StringData(p.SignatureStatus),
			"timestamp":      llx.TimeData(p.Timestamp),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProduct)
	}

	return res, nil
}

func (w *mqlWindowsSecurityProduct) id() (string, error) {
	return "windows.security.product/" + w.Guid.Data, nil
}

func initWindowsSecurityHealth(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args == nil {
		args = map[string]*llx.RawData{}
	}

	conn := runtime.Connection.(shared.Connection)

	health, err := windows.GetSecurityProviderHealth(conn)
	if err != nil {
		return nil, nil, err
	}

	firewall, _ := convert.JsonToDict(health.Firewall)
	autoupdate, _ := convert.JsonToDict(health.AutoUpdate)
	antivirus, _ := convert.JsonToDict(health.AntiVirus)
	antispyware, _ := convert.JsonToDict(health.AntiSpyware)
	internetsettings, _ := convert.JsonToDict(health.InternetSettings)
	uac, _ := convert.JsonToDict(health.Uac)
	securitycenterservice, _ := convert.JsonToDict(health.SecurityCenterService)

	args["firewall"] = llx.DictData(firewall)
	args["autoUpdate"] = llx.DictData(autoupdate)
	args["antiVirus"] = llx.DictData(antivirus)
	args["antiSpyware"] = llx.DictData(antispyware)
	args["internetSettings"] = llx.DictData(internetsettings)
	args["uac"] = llx.DictData(uac)
	args["securityCenterService"] = llx.DictData(securitycenterservice)

	return args, nil, nil
}
