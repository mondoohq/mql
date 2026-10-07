// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/IBM/platform-services-go-sdk/atrackerv2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// atrackerSettingsRead reads the account's routing settings once.
func atrackerSettingsRead(runtime *plugin.Runtime) (*atrackerv2.Settings, error) {
	c := conn(runtime)
	v, err := c.Memo("atracker/settings", func() (any, error) {
		svc, err := c.Atracker()
		if err != nil {
			return nil, err
		}
		res, _, err := svc.GetSettings(&atrackerv2.GetSettingsOptions{})
		if err != nil {
			return nil, classifyError(err, "atracker.setting.get")
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*atrackerv2.Settings), nil
}

func (r *mqlIbm) atrackerSettings() (*mqlIbmAtrackerSettings, error) {
	s, err := atrackerSettingsRead(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "ibm.atracker.settings", map[string]*llx.RawData{
		"__id":                   llx.StringData("ibm.atracker.settings/" + r.AccountId.Data),
		"permittedTargetRegions": stringsData(s.PermittedTargetRegions),
		"metadataRegionPrimary":  strData(s.MetadataRegionPrimary),
		"metadataRegionBackup":   strData(s.MetadataRegionBackup),
		"privateApiEndpointOnly": llx.BoolDataPtr(s.PrivateAPIEndpointOnly),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlIbmAtrackerSettings)
	m.cacheDefaultTargetIDs = s.DefaultTargets
	return m, nil
}

type mqlIbmAtrackerSettingsInternal struct {
	cacheDefaultTargetIDs []string
}

func (r *mqlIbmAtrackerSettings) defaultTargets() ([]any, error) {
	return atrackerTargetsByID(r.MqlRuntime, r.cacheDefaultTargetIDs)
}

// ---- targets ----

type mqlIbmAtrackerTargetInternal struct {
	cacheBucket         string
	cacheDestinationCRN string
}

func (r *mqlIbm) atrackerTargets() ([]any, error) {
	svc, err := conn(r.MqlRuntime).Atracker()
	if err != nil {
		return nil, err
	}
	res, _, err := svc.ListTargets(&atrackerv2.ListTargetsOptions{})
	if err != nil {
		return nil, classifyError(err, "atracker.target.list")
	}
	out := make([]any, 0, len(res.Targets))
	for _, t := range res.Targets {
		m, err := CreateResource(r.MqlRuntime, "ibm.atracker.target", targetArgs(t))
		if err != nil {
			return nil, err
		}
		tm := m.(*mqlIbmAtrackerTarget)
		tm.cacheBucket, tm.cacheDestinationCRN = targetDestination(t)
		out = append(out, tm)
	}
	return out, nil
}

func targetArgs(t atrackerv2.Target) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                    llx.StringData("ibm.atracker.target/" + derefStr(t.ID)),
		"id":                      strData(t.ID),
		"crn":                     strData(t.CRN),
		"name":                    strData(t.Name),
		"type":                    strData(t.TargetType),
		"region":                  strData(t.Region),
		"writeStatus":             llx.StringData(""),
		"lastFailureAt":           llx.NilData,
		"lastFailureReason":       llx.StringData(""),
		"serviceToServiceEnabled": llx.BoolFalse,
		"cosEndpoint":             llx.StringData(""),
		"managedBy":               strData(t.ManagedBy),
		"createdAt":               dateTimeData(t.CreatedAt),
		"updatedAt":               dateTimeData(t.UpdatedAt),
	}
	if ws := t.WriteStatus; ws != nil {
		args["writeStatus"] = strData(ws.Status)
		args["lastFailureAt"] = dateTimeData(ws.LastFailure)
		args["lastFailureReason"] = strData(ws.ReasonForLastFailure)
	}
	switch {
	case t.CosEndpoint != nil:
		args["cosEndpoint"] = strData(t.CosEndpoint.Endpoint)
		args["serviceToServiceEnabled"] = llx.BoolData(isTrue(t.CosEndpoint.ServiceToServiceEnabled))
	case t.EventstreamsEndpoint != nil:
		args["serviceToServiceEnabled"] = llx.BoolData(isTrue(t.EventstreamsEndpoint.ServiceToServiceEnabled))
	case t.CloudlogsEndpoint != nil, t.AppconfigEndpoint != nil:
		// Cloud Logs and App Configuration targets always authorize service to service.
		args["serviceToServiceEnabled"] = llx.BoolTrue
	}
	return args
}

// targetDestination returns the bucket and the service instance a target
// writes to. Only the API key an Event Streams or Cloud Object Storage target
// may carry is left out.
func targetDestination(t atrackerv2.Target) (bucket, instanceCRN string) {
	switch {
	case t.CosEndpoint != nil:
		return derefStr(t.CosEndpoint.Bucket), derefStr(t.CosEndpoint.TargetCRN)
	case t.EventstreamsEndpoint != nil:
		return "", derefStr(t.EventstreamsEndpoint.TargetCRN)
	case t.CloudlogsEndpoint != nil:
		return "", derefStr(t.CloudlogsEndpoint.TargetCRN)
	case t.AppconfigEndpoint != nil:
		return "", derefStr(t.AppconfigEndpoint.TargetCRN)
	}
	return "", ""
}

func (r *mqlIbmAtrackerTarget) cosBucket() (*mqlIbmCosBucket, error) {
	if r.cacheBucket == "" {
		nullResource(&r.CosBucket)
		return nil, nil
	}
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return resolveOne(&r.CosBucket, ns.GetCosBuckets(), r.cacheBucket, func(b *mqlIbmCosBucket) string { return b.Name.Data })
}

func (r *mqlIbmAtrackerTarget) destination() (*mqlIbmResourceInstance, error) {
	if r.cacheDestinationCRN == "" {
		nullResource(&r.Destination)
		return nil, nil
	}
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return resolveOne(&r.Destination, ns.GetResourceInstances(), r.cacheDestinationCRN, func(i *mqlIbmResourceInstance) string { return i.Id.Data })
}

func atrackerTargetsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetAtrackerTargets()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, ids, func(t *mqlIbmAtrackerTarget) string { return t.Id.Data }), nil
}

// ---- routes ----

type mqlIbmAtrackerRouteInternal struct {
	cacheRules []atrackerv2.Rule
}

func (r *mqlIbm) atrackerRoutes() ([]any, error) {
	svc, err := conn(r.MqlRuntime).Atracker()
	if err != nil {
		return nil, err
	}
	res, _, err := svc.ListRoutes(&atrackerv2.ListRoutesOptions{})
	if err != nil {
		return nil, classifyError(err, "atracker.route.list")
	}
	out := make([]any, 0, len(res.Routes))
	for _, rt := range res.Routes {
		m, err := CreateResource(r.MqlRuntime, "ibm.atracker.route", map[string]*llx.RawData{
			"__id":      llx.StringData("ibm.atracker.route/" + derefStr(rt.ID)),
			"id":        strData(rt.ID),
			"crn":       strData(rt.CRN),
			"name":      strData(rt.Name),
			"version":   intPtrData(rt.Version),
			"managedBy": strData(rt.ManagedBy),
			"createdAt": dateTimeData(rt.CreatedAt),
			"updatedAt": dateTimeData(rt.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		m.(*mqlIbmAtrackerRoute).cacheRules = rt.Rules
		out = append(out, m)
	}
	return out, nil
}

type mqlIbmAtrackerRouteRuleInternal struct {
	cacheTargetIDs []string
}

// rules keep the API order; a rule has no id of its own, so its position in
// the route identifies it.
func (r *mqlIbmAtrackerRoute) rules() ([]any, error) {
	out := make([]any, 0, len(r.cacheRules))
	for i, rule := range r.cacheRules {
		m, err := CreateResource(r.MqlRuntime, "ibm.atracker.route.rule", map[string]*llx.RawData{
			"__id":      llx.StringData("ibm.atracker.route.rule/" + r.Id.Data + "/" + strconv.Itoa(i)),
			"locations": stringsData(rule.Locations),
		})
		if err != nil {
			return nil, err
		}
		m.(*mqlIbmAtrackerRouteRule).cacheTargetIDs = rule.TargetIds
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmAtrackerRouteRule) targets() ([]any, error) {
	return atrackerTargetsByID(r.MqlRuntime, r.cacheTargetIDs)
}
