// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	loadbalancer "github.com/stackitcloud/stackit-sdk-go/services/loadbalancer/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlStackit) loadBalancers() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.LoadBalancer()
	if err != nil {
		return nil, err
	}
	out := []any{}
	pageId := ""
	for {
		req := client.DefaultAPI.ListLoadBalancers(bgctx(), c.ProjectID(), c.Region())
		if pageId != "" {
			req = req.PageId(pageId)
		}
		resp, err := req.Execute()
		if err != nil {
			if isAccessDenied(err) {
				return deniedList(err)
			}
			return nil, err
		}
		items, _ := resp.GetLoadBalancersOk()
		for i := range items {
			res, err := buildLoadBalancer(r.MqlRuntime, &items[i], c.Region())
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		next, ok := resp.GetNextPageIdOk()
		if !ok || next == nil || *next == "" {
			break
		}
		pageId = *next
	}
	return out, nil
}

// mqlStackitLoadBalancerInternal caches the raw listener and target-pool
// slices so the computed listeners()/targetPools() accessors can build
// typed sub-resources on access without re-fetching the load balancer.
type mqlStackitLoadBalancerInternal struct {
	rawListeners   []loadbalancer.Listener
	rawTargetPools []loadbalancer.TargetPool

	// Security group ids the balancer object names inline, resolved into
	// resources on access so the group list is fetched once per connection
	// rather than once per balancer.
	cacheLoadBalancerSecurityGroupId string
	cacheTargetSecurityGroupId       string
}

func buildLoadBalancer(runtime *plugin.Runtime, lb *loadbalancer.LoadBalancer, region string) (plugin.Resource, error) {
	status := string(lb.GetStatus())
	var privateOnly bool
	if v, ok := lb.GetOptionsOk(); ok {
		if pno, ok := v.GetPrivateNetworkOnlyOk(); ok {
			privateOnly = pno != nil && *pno
		}
	}

	args := map[string]*llx.RawData{
		"name":               llx.StringData(lb.GetName()),
		"externalAddress":    llx.StringData(lb.GetExternalAddress()),
		"planId":             llx.StringData(lb.GetPlanId()),
		"status":             llx.StringData(status),
		"privateNetworkOnly": llx.BoolData(privateOnly),
		"region":             llx.StringData(region),
		"privateAddress":     llx.StringData(lb.GetPrivateAddress()),
		"labels":             labelData(lb.GetLabels()),
		"disableTargetSecurityGroupAssignment": llx.BoolDataPtr(
			lbDisableTargetSecurityGroupAssignment(lb)),
		"networks": llx.ArrayData(anySliceToDict(lb.GetNetworks()), types.Dict),
		"options":  llx.DictData(toDict(lb.GetOptions())),
		"errors":   llx.ArrayData(anySliceToDict(lb.GetErrors()), types.Dict),
	}
	res, err := CreateResource(runtime, "stackit.loadBalancer", args)
	if err != nil {
		return nil, err
	}
	if mlb, ok := res.(*mqlStackitLoadBalancer); ok {
		mlb.rawListeners = lb.GetListeners()
		mlb.rawTargetPools = lb.GetTargetPools()
		if sg, ok := lb.GetLoadBalancerSecurityGroupOk(); ok && sg != nil {
			mlb.cacheLoadBalancerSecurityGroupId = sg.GetId()
		}
		if sg, ok := lb.GetTargetSecurityGroupOk(); ok && sg != nil {
			mlb.cacheTargetSecurityGroupId = sg.GetId()
		}
	}
	return res, nil
}

// targetSecurityGroupAssignmentFlag is the slice of a load balancer (network
// or application) that lbDisableTargetSecurityGroupAssignment reads. Both SDKs
// generate the same accessor on their LoadBalancer models.
type targetSecurityGroupAssignmentFlag interface {
	GetDisableTargetSecurityGroupAssignmentOk() (*bool, bool)
}

// lbDisableTargetSecurityGroupAssignment reports whether the operator opted
// out of attaching the managed target security group to the backends, or nil
// when the API reports no setting.
//
// The flag is fixed at creation and the API omits it rather than sending
// false, so nil is the only honest reading of an absent value. Reporting false
// would assert that the managed group is being attached on a balancer whose
// setting was never read, which is the reassuring answer and the wrong one.
// The network and application load balancers share this reading.
func lbDisableTargetSecurityGroupAssignment(lb targetSecurityGroupAssignmentFlag) *bool {
	if lb == nil {
		return nil
	}
	disabled, ok := lb.GetDisableTargetSecurityGroupAssignmentOk()
	if !ok {
		return nil
	}
	return disabled
}

// loadBalancerSecurityGroup resolves the group STACKIT manages for the
// balancer itself.
func (r *mqlStackitLoadBalancer) loadBalancerSecurityGroup() (*mqlStackitSecurityGroup, error) {
	return r.resolveSecurityGroup(r.cacheLoadBalancerSecurityGroupId, &r.LoadBalancerSecurityGroup)
}

// targetSecurityGroup resolves the group STACKIT manages for the backends.
func (r *mqlStackitLoadBalancer) targetSecurityGroup() (*mqlStackitSecurityGroup, error) {
	return r.resolveSecurityGroup(r.cacheTargetSecurityGroupId, &r.TargetSecurityGroup)
}

// resolveSecurityGroup turns a security group id carried on the balancer into
// the security group resource, reading it out of the project's group list
// rather than fetching the group once per balancer.
//
// A group id the list does not answer for is an error, not a null. Null is
// what a balancer with no managed group reports, and that is precisely the
// finding these fields exist to surface, so a failed lookup must not be able
// to imitate it.
func (r *mqlStackitLoadBalancer) resolveSecurityGroup(
	id string, field *plugin.TValue[*mqlStackitSecurityGroup],
) (*mqlStackitSecurityGroup, error) {
	return securityGroupFromProjectList(r.MqlRuntime, id, r.Name.Data, field)
}

// securityGroupFromProjectList is the shared body of the network and
// application balancers' security-group accessors: null for an empty id, an
// error for an id the project's group list does not answer for, and the
// built group otherwise. ownerName names the balancer in the error.
func securityGroupFromProjectList(
	runtime *plugin.Runtime, id, ownerName string, field *plugin.TValue[*mqlStackitSecurityGroup],
) (*mqlStackitSecurityGroup, error) {
	if id == "" {
		return markNull(field)
	}
	groups, err := conn(runtime).SecurityGroups(bgctx())
	if err != nil {
		return nil, err
	}
	sg, ok := groups[id]
	if !ok {
		return nil, fmt.Errorf(
			"stackit.securityGroup with id %q referenced by load balancer %q not found",
			id, ownerName)
	}
	res, err := buildSecurityGroup(runtime, &sg)
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSecurityGroup), nil
}

func (r *mqlStackitLoadBalancer) listeners() ([]any, error) {
	out := make([]any, 0, len(r.rawListeners))
	for i := range r.rawListeners {
		l := &r.rawListeners[i]
		args := map[string]*llx.RawData{
			"name":                 llx.StringData(l.GetName()),
			"displayName":          llx.StringData(l.GetDisplayName()),
			"loadBalancerName":     llx.StringData(r.Name.Data),
			"port":                 llx.IntData(l.GetPort()),
			"protocol":             llx.StringData(string(l.GetProtocol())),
			"targetPool":           llx.StringData(l.GetTargetPool()),
			"serverNameIndicators": strSliceData(listenerSNINames(l.GetServerNameIndicators())),
			"tcp":                  llx.DictData(toDict(l.GetTcp())),
			"udp":                  llx.DictData(toDict(l.GetUdp())),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.loadBalancer.listener", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// listenerSNINames extracts the Name field from each ServerNameIndicator
// struct so the schema can expose them as []string.
func listenerSNINames(snis []loadbalancer.ServerNameIndicator) []string {
	out := make([]string, 0, len(snis))
	for i := range snis {
		out = append(out, snis[i].GetName())
	}
	return out
}

func (r *mqlStackitLoadBalancer) targetPools() ([]any, error) {
	out := make([]any, 0, len(r.rawTargetPools))
	for i := range r.rawTargetPools {
		tp := &r.rawTargetPools[i]
		hcTls, hcSkip := poolHealthCheckTls(tp)
		args := map[string]*llx.RawData{
			"name":                                 llx.StringData(tp.GetName()),
			"loadBalancerName":                     llx.StringData(r.Name.Data),
			"targetPort":                           llx.IntData(tp.GetTargetPort()),
			"targets":                              llx.ArrayData(anySliceToDict(tp.GetTargets()), types.Dict),
			"activeHealthCheck":                    llx.DictData(toDict(tp.GetActiveHealthCheck())),
			"sessionPersistence":                   llx.DictData(toDict(tp.GetSessionPersistence())),
			"healthCheckTlsEnabled":                llx.BoolDataPtr(hcTls),
			"healthCheckSkipCertificateValidation": llx.BoolDataPtr(hcSkip),
			"sessionPersistenceSourceIp":           llx.BoolDataPtr(poolSessionPersistenceSourceIp(tp)),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.loadBalancer.targetPool", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitLoadBalancerListener) id() (string, error) {
	return "stackit.loadBalancer.listener/" + r.LoadBalancerName.Data + "/" + r.Name.Data, nil
}

func (r *mqlStackitLoadBalancerTargetPool) id() (string, error) {
	return "stackit.loadBalancer.targetPool/" + r.LoadBalancerName.Data + "/" + r.Name.Data, nil
}

func (r *mqlStackitLoadBalancer) id() (string, error) {
	return "stackit.loadBalancer/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Name.Data, nil
}

func initStackitLoadBalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	v, ok := args["name"]
	if !ok || v == nil {
		return args, nil, nil
	}
	name, ok := v.Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.LoadBalancer()
	if err != nil {
		return nil, nil, err
	}
	lb, err := client.DefaultAPI.GetLoadBalancer(bgctx(), c.ProjectID(), c.Region(), name).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildLoadBalancer(runtime, lb, c.Region())
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}
