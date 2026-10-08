// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func initIbm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if args == nil {
		args = map[string]*llx.RawData{}
	}
	args["accountId"] = llx.StringData(conn(runtime).AccountID())
	return args, nil, nil
}

func (r *mqlIbm) id() (string, error) {
	return "ibm/" + r.AccountId.Data, nil
}

// ---- resource groups ----

func (r *mqlIbm) resourceGroups() ([]any, error) {
	c := conn(r.MqlRuntime)
	accountID := c.AccountID()
	res, _, err := c.ResourceManager().ListResourceGroups(&resourcemanagerv2.ListResourceGroupsOptions{AccountID: &accountID})
	if err != nil {
		return nil, classifyError(err, "resource-controller.group.retrieve")
	}
	out := make([]any, 0, len(res.Resources))
	for _, g := range res.Resources {
		m, err := CreateResource(r.MqlRuntime, "ibm.resourceGroup", map[string]*llx.RawData{
			"__id":      llx.StringData("ibm.resourceGroup/" + derefStr(g.ID)),
			"id":        strData(g.ID),
			"name":      strData(g.Name),
			"crn":       strData(g.CRN),
			"state":     strData(g.State),
			"default":   llx.BoolDataPtr(g.Default),
			"createdAt": dateTimeData(g.CreatedAt),
			"updatedAt": dateTimeData(g.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// resourceGroupByID resolves a resource group reference through the listed
// groups.
func resourceGroupByID(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlIbmResourceGroup]) (*mqlIbmResourceGroup, error) {
	if id == "" {
		nullResource(field)
		return nil, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	return resolveOne(field, ns.GetResourceGroups(), id, func(g *mqlIbmResourceGroup) string { return g.Id.Data })
}

// ---- resource instances ----

type mqlIbmResourceInstanceInternal struct {
	cacheResourceGroupID string
}

// listResourceInstances reads every resource instance of the account once per
// connection. The Power VS workspaces are found through it too.
func listResourceInstances(runtime *plugin.Runtime) ([]resourcecontrollerv2.ResourceInstance, error) {
	c := conn(runtime)
	v, err := c.Memo("resourceInstances", func() (any, error) {
		pager, err := c.ResourceController().NewResourceInstancesPager(&resourcecontrollerv2.ListResourceInstancesOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, classifyError(err, "resource-controller.instance.retrieve")
	}
	return v.([]resourcecontrollerv2.ResourceInstance), nil
}

func (r *mqlIbm) resourceInstances() ([]any, error) {
	items, err := listResourceInstances(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, ri := range items {
		m, err := CreateResource(r.MqlRuntime, "ibm.resourceInstance", map[string]*llx.RawData{
			"__id":           llx.StringData("ibm.resourceInstance/" + derefStr(ri.CRN)),
			"id":             strData(ri.CRN),
			"crn":            strData(ri.CRN),
			"guid":           strData(ri.GUID),
			"name":           strData(ri.Name),
			"service":        llx.StringData(crnService(derefStr(ri.CRN))),
			"region":         strData(ri.RegionID),
			"state":          strData(ri.State),
			"type":           strData(ri.Type),
			"resourceId":     strData(ri.ResourceID),
			"resourcePlanId": strData(ri.ResourcePlanID),
			"locked":         llx.BoolDataPtr(ri.Locked),
			"createdAt":      dateTimeData(ri.CreatedAt),
			"updatedAt":      dateTimeData(ri.UpdatedAt),
			"createdBy":      strData(ri.CreatedBy),
		})
		if err != nil {
			return nil, err
		}
		m.(*mqlIbmResourceInstance).cacheResourceGroupID = derefStr(ri.ResourceGroupID)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmResourceInstance) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}
