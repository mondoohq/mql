// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"strconv"
	"strings"

	"github.com/IBM/platform-services-go-sdk/contextbasedrestrictionsv1"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// cbrPermission is the IAM action reading rules and zones needs.
const cbrPermission = "context-based-restrictions.policy.read"

// cbrDefaultEnforcementMode is the mode IBM Cloud applies to a rule that
// sets none.
const cbrDefaultEnforcementMode = "enabled"

// ---- rules ----

func (r *mqlIbm) cbrRules() ([]any, error) {
	c := conn(r.MqlRuntime)
	svc, err := c.ContextBasedRestrictions()
	if err != nil {
		return nil, err
	}
	accountID := c.AccountID()
	res, resp, err := svc.ListRules(&contextbasedrestrictionsv1.ListRulesOptions{AccountID: &accountID})
	if err != nil {
		return nil, classifyError(withStatus(err, resp), cbrPermission)
	}
	out := make([]any, 0, len(res.Rules))
	for _, rule := range res.Rules {
		m, err := cbrRuleResource(r.MqlRuntime, rule)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func cbrRuleResource(runtime *plugin.Runtime, rule contextbasedrestrictionsv1.Rule) (plugin.Resource, error) {
	id := derefStr(rule.ID)
	resources := make([]any, 0, len(rule.Resources))
	for i, res := range rule.Resources {
		args := cbrResourceArgs(res)
		args["__id"] = llx.StringData("ibm.cbr.rule.resource/" + id + "/" + strconv.Itoa(i))
		m, err := CreateResource(runtime, "ibm.cbr.rule.resource", args)
		if err != nil {
			return nil, err
		}
		resources = append(resources, m)
	}
	contexts := make([]any, 0, len(rule.Contexts))
	for i, ctx := range rule.Contexts {
		attrs := map[string]string{}
		var endpointTypes, zoneIDs []string
		for _, a := range ctx.Attributes {
			name, value := derefStr(a.Name), derefStr(a.Value)
			attrs[name] = value
			switch name {
			case "endpointType":
				endpointTypes = append(endpointTypes, splitList(&value)...)
			case "networkZoneId":
				zoneIDs = append(zoneIDs, splitList(&value)...)
			}
		}
		m, err := CreateResource(runtime, "ibm.cbr.rule.context", map[string]*llx.RawData{
			"__id":           llx.StringData("ibm.cbr.rule.context/" + id + "/" + strconv.Itoa(i)),
			"attributes":     stringMapData(attrs),
			"endpointTypes":  stringsData(endpointTypes),
			"networkZoneIds": stringsData(zoneIDs),
		})
		if err != nil {
			return nil, err
		}
		contexts = append(contexts, m)
	}
	apiTypes := []string{}
	if rule.Operations != nil {
		for _, t := range rule.Operations.APITypes {
			if s := derefStr(t.APITypeID); s != "" {
				apiTypes = append(apiTypes, s)
			}
		}
	}
	mode := derefStr(rule.EnforcementMode)
	if mode == "" {
		mode = cbrDefaultEnforcementMode
	}
	return CreateResource(runtime, "ibm.cbr.rule", map[string]*llx.RawData{
		"__id":            llx.StringData("ibm.cbr.rule/" + id),
		"id":              llx.StringData(id),
		"crn":             strData(rule.CRN),
		"description":     strData(rule.Description),
		"enforcementMode": llx.StringData(mode),
		"apiTypes":        stringsData(apiTypes),
		"resources":       llx.ArrayData(resources, types.Resource("ibm.cbr.rule.resource")),
		"contexts":        llx.ArrayData(contexts, types.Resource("ibm.cbr.rule.context")),
		"createdAt":       dateTimeData(rule.CreatedAt),
		"lastModifiedAt":  dateTimeData(rule.LastModifiedAt),
	})
}

func cbrResourceArgs(res contextbasedrestrictionsv1.Resource) map[string]*llx.RawData {
	attrs, ops, tags := map[string]string{}, map[string]string{}, map[string]string{}
	for _, a := range res.Attributes {
		name := derefStr(a.Name)
		attrs[name] = derefStr(a.Value)
		if op := derefStr(a.Operator); op != "" {
			ops[name] = op
		}
	}
	for _, t := range res.Tags {
		tags[derefStr(t.Name)] = derefStr(t.Value)
	}
	return map[string]*llx.RawData{
		"serviceName":     llx.StringData(attrs["serviceName"]),
		"serviceInstance": llx.StringData(attrs["serviceInstance"]),
		"region":          llx.StringData(attrs["region"]),
		"resourceGroupId": llx.StringData(attrs["resourceGroupId"]),
		"attributes":      stringMapData(attrs),
		"operators":       stringMapData(ops),
		"tags":            stringMapData(tags),
	}
}

func (r *mqlIbmCbrRuleContext) zones() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetCbrZones()
	if list.Error != nil {
		return nil, list.Error
	}
	ids := make([]string, 0, len(r.NetworkZoneIds.Data))
	for _, e := range r.NetworkZoneIds.Data {
		if s, ok := e.(string); ok {
			ids = append(ids, s)
		}
	}
	return pickByID(list.Data, ids, func(z *mqlIbmCbrZone) string { return z.Id.Data }), nil
}

// cbrTarget is what a rule resource is matched against: one service instance.
type cbrTarget struct {
	accountID       string
	serviceName     string
	serviceInstance string
	region          string
	resourceGroupID string
	tags            []string
}

// cbrMatch compares an attribute value by its operator: stringEquals (the
// default) or stringMatch, where * matches any run of characters and ? one.
func cbrMatch(operator, pattern, value string) bool {
	if operator == "stringMatch" {
		ok, err := path.Match(pattern, value)
		return err == nil && ok
	}
	return pattern == value
}

// cbrCovers reports whether a rule resource covers the whole of a service
// instance: every attribute matches it and the instance has every tag. A
// resource narrowed to part of an instance (resourceType, resource) or by an
// attribute that is not known here does not cover the instance.
func cbrCovers(attrs, ops, tags map[string]string, t cbrTarget) bool {
	if attrs["serviceName"] == "" {
		return false
	}
	for name, want := range attrs {
		var have string
		switch name {
		case "accountId":
			have = t.accountID
		case "serviceName":
			have = t.serviceName
		case "serviceInstance":
			have = t.serviceInstance
		case "region":
			have = t.region
		case "resourceGroupId":
			have = t.resourceGroupID
		default:
			return false
		}
		if !cbrMatch(ops[name], want, have) {
			return false
		}
	}
	for name, want := range tags {
		found := false
		for _, tag := range t.tags {
			k, v, _ := strings.Cut(tag, ":")
			if k == name && v == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// cbrRulesCovering returns the rules with a resource that covers the target.
func cbrRulesCovering(runtime *plugin.Runtime, t cbrTarget) ([]any, error) {
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetCbrRules()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, e := range list.Data {
		rule := e.(*mqlIbmCbrRule)
		for _, re := range rule.Resources.Data {
			res := re.(*mqlIbmCbrRuleResource)
			if cbrCovers(toStringMap(res.Attributes.Data), toStringMap(res.Operators.Data), toStringMap(res.Tags.Data), t) {
				out = append(out, rule)
				break
			}
		}
	}
	return out, nil
}

func toStringMap(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// cbrRules returns the rules that cover the whole deployment. Tag conditions
// are checked against the deployment's user tags only when a rule sets one.
func (r *mqlIbmDatabase) cbrRules() ([]any, error) {
	t := cbrTarget{
		accountID:       conn(r.MqlRuntime).AccountID(),
		serviceName:     r.Service.Data,
		serviceInstance: r.Guid.Data,
		region:          r.Region.Data,
		resourceGroupID: r.cacheResourceGroupID,
	}
	if needsTags, err := cbrRulesUseTags(r.MqlRuntime); err != nil {
		return nil, err
	} else if needsTags {
		tags := r.GetTags()
		if tags.Error != nil {
			return nil, tags.Error
		}
		for _, e := range tags.Data {
			if s, ok := e.(string); ok {
				t.tags = append(t.tags, s)
			}
		}
	}
	return cbrRulesCovering(r.MqlRuntime, t)
}

// cbrRulesUseTags reports whether any rule narrows its resources by tag, so
// tags are only read when a rule needs them.
func cbrRulesUseTags(runtime *plugin.Runtime) (bool, error) {
	ns, err := root(runtime)
	if err != nil {
		return false, err
	}
	list := ns.GetCbrRules()
	if list.Error != nil {
		return false, list.Error
	}
	for _, e := range list.Data {
		for _, re := range e.(*mqlIbmCbrRule).Resources.Data {
			if len(re.(*mqlIbmCbrRuleResource).Tags.Data) > 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// ---- zones ----

func (r *mqlIbm) cbrZones() ([]any, error) {
	c := conn(r.MqlRuntime)
	svc, err := c.ContextBasedRestrictions()
	if err != nil {
		return nil, err
	}
	accountID := c.AccountID()
	res, resp, err := svc.ListZones(&contextbasedrestrictionsv1.ListZonesOptions{AccountID: &accountID})
	if err != nil {
		return nil, classifyError(withStatus(err, resp), cbrPermission)
	}
	out := make([]any, 0, len(res.Zones))
	for _, z := range res.Zones {
		m, err := CreateResource(r.MqlRuntime, "ibm.cbr.zone", map[string]*llx.RawData{
			"__id":           llx.StringData("ibm.cbr.zone/" + derefStr(z.ID)),
			"id":             strData(z.ID),
			"crn":            strData(z.CRN),
			"name":           strData(z.Name),
			"description":    strData(z.Description),
			"addressCount":   intPtrData(z.AddressCount),
			"excludedCount":  intPtrData(z.ExcludedCount),
			"createdAt":      dateTimeData(z.CreatedAt),
			"lastModifiedAt": dateTimeData(z.LastModifiedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// zone reads the zone with its addresses once; the listing carries only a
// preview of them.
func (r *mqlIbmCbrZone) zone() (*contextbasedrestrictionsv1.Zone, error) {
	c := conn(r.MqlRuntime)
	v, err := c.Memo("cbr/zone/"+r.Id.Data, func() (any, error) {
		svc, err := c.ContextBasedRestrictions()
		if err != nil {
			return nil, err
		}
		z, resp, err := svc.GetZone(&contextbasedrestrictionsv1.GetZoneOptions{ZoneID: &r.Id.Data})
		if err != nil {
			return nil, classifyError(withStatus(err, resp), cbrPermission)
		}
		return z, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*contextbasedrestrictionsv1.Zone), nil
}

// cbrAddress is the flat form of every zone address type.
type cbrAddress struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Ref   *struct {
		ServiceName     string `json:"service_name"`
		ServiceType     string `json:"service_type"`
		ServiceInstance string `json:"service_instance"`
		Location        string `json:"location"`
	} `json:"ref"`
}

func cbrAddressArgs(a cbrAddress) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"type":            llx.StringData(a.Type),
		"value":           llx.StringData(a.Value),
		"serviceName":     llx.StringData(""),
		"serviceType":     llx.StringData(""),
		"serviceInstance": llx.StringData(""),
		"location":        llx.StringData(""),
	}
	if a.Ref != nil {
		args["serviceName"] = llx.StringData(a.Ref.ServiceName)
		args["serviceType"] = llx.StringData(a.Ref.ServiceType)
		args["serviceInstance"] = llx.StringData(a.Ref.ServiceInstance)
		args["location"] = llx.StringData(a.Ref.Location)
	}
	return args
}

func (r *mqlIbmCbrZone) addressList(kind string, items []contextbasedrestrictionsv1.AddressIntf) ([]any, error) {
	out := make([]any, 0, len(items))
	for i, it := range items {
		var a cbrAddress
		if err := asJSON(it, &a); err != nil {
			return nil, err
		}
		args := cbrAddressArgs(a)
		args["__id"] = llx.StringData("ibm.cbr.zone.address/" + r.Id.Data + "/" + kind + "/" + strconv.Itoa(i))
		m, err := CreateResource(r.MqlRuntime, "ibm.cbr.zone.address", args)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmCbrZone) addresses() ([]any, error) {
	z, err := r.zone()
	if err != nil {
		return nil, err
	}
	return r.addressList("addresses", z.Addresses)
}

func (r *mqlIbmCbrZone) excluded() ([]any, error) {
	z, err := r.zone()
	if err != nil {
		return nil, err
	}
	return r.addressList("excluded", z.Excluded)
}
