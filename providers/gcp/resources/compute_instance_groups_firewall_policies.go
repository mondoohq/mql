// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// Instance groups

func (g *mqlGcpProjectComputeService) instanceGroups() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.InstanceGroups.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.InstanceGroupAggregatedList) error {
		for _, scoped := range page.Items {
			for _, ig := range scoped.InstanceGroups {
				namedPorts, _ := convert.JsonToDictSlice(ig.NamedPorts)

				mqlIG, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.instanceGroup", map[string]*llx.RawData{
					"id":          llx.StringData(strconv.FormatUint(ig.Id, 10)),
					"projectId":   llx.StringData(projectId),
					"name":        llx.StringData(ig.Name),
					"description": llx.StringData(ig.Description),
					"size":        llx.IntData(ig.Size),
					"namedPorts":  llx.ArrayData(namedPorts, types.Dict),
					"created":     llx.TimeDataPtr(parseTime(ig.CreationTimestamp)),
					"selfLink":    llx.StringData(ig.SelfLink),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlIG.(*mqlGcpProjectComputeServiceInstanceGroup)
				mqlRef.cacheZoneUrl = ig.Zone
				mqlRef.cacheNetworkUrl = ig.Network
				mqlIG.(*mqlGcpProjectComputeServiceInstanceGroup).cacheSubnetworkUrl = ig.Subnetwork
				res = append(res, mqlIG)
			}
		}
		return nil
	}); err != nil {
		if gerr, ok := err.(*googleapi.Error); ok && gerr.Code == 403 {
			log.Warn().Str("project", projectId).Err(err).Msg("could not list compute instance groups")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

type mqlGcpProjectComputeServiceInstanceGroupInternal struct {
	cacheSubnetworkUrl string
	cacheNetworkUrl    string
	cacheZoneUrl       string
}

func (g *mqlGcpProjectComputeServiceInstanceGroup) id() (string, error) {
	return "gcloud.compute.instanceGroup/" + g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceInstanceGroup) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	net, err := getNetworkByUrl(g.cacheNetworkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return net, nil
}

func (g *mqlGcpProjectComputeServiceInstanceGroup) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	subnet, err := getSubnetworkByUrl(g.cacheSubnetworkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		g.Subnetwork.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return subnet, nil
}

// Instance group managers

func (g *mqlGcpProjectComputeService) instanceGroupManagers() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.InstanceGroupManagers.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.InstanceGroupManagerAggregatedList) error {
		for _, scoped := range page.Items {
			for _, igm := range scoped.InstanceGroupManagers {
				currentActions, _ := convert.JsonToDict(igm.CurrentActions)
				statefulPolicy, _ := convert.JsonToDict(igm.StatefulPolicy)
				autoHealingPolicies, _ := convert.JsonToDictSlice(igm.AutoHealingPolicies)
				status, _ := convert.JsonToDict(igm.Status)

				mqlIGM, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.instanceGroupManager", map[string]*llx.RawData{
					"id":                  llx.StringData(strconv.FormatUint(igm.Id, 10)),
					"projectId":           llx.StringData(projectId),
					"name":                llx.StringData(igm.Name),
					"description":         llx.StringData(igm.Description),
					"instanceTemplateUrl": llx.StringData(igm.InstanceTemplate),
					"targetSize":          llx.IntData(igm.TargetSize),
					"currentActions":      llx.DictData(currentActions),
					"statefulPolicy":      llx.DictData(statefulPolicy),
					"autoHealingPolicies": llx.ArrayData(autoHealingPolicies, types.Dict),
					"instanceGroupUrl":    llx.StringData(igm.InstanceGroup),
					"status":              llx.DictData(status),
					"created":             llx.TimeDataPtr(parseTime(igm.CreationTimestamp)),
					"selfLink":            llx.StringData(igm.SelfLink),
					"baseInstanceName":    llx.StringData(igm.BaseInstanceName),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlIGM.(*mqlGcpProjectComputeServiceInstanceGroupManager)
				mqlRef.cacheZoneUrl = igm.Zone
				mqlRef.cacheRegionUrl = igm.Region
				templateUrl := igm.InstanceTemplate
				if templateUrl == "" {
					for _, v := range igm.Versions {
						if v.InstanceTemplate != "" {
							templateUrl = v.InstanceTemplate
							break
						}
					}
				}
				mqlIGM.(*mqlGcpProjectComputeServiceInstanceGroupManager).cacheInstanceTemplateUrl = templateUrl
				res = append(res, mqlIGM)
			}
		}
		return nil
	}); err != nil {
		if gerr, ok := err.(*googleapi.Error); ok && gerr.Code == 403 {
			log.Warn().Str("project", projectId).Err(err).Msg("could not list compute instance group managers")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

type mqlGcpProjectComputeServiceInstanceGroupManagerInternal struct {
	cacheInstanceTemplateUrl string
	cacheRegionUrl           string
	cacheZoneUrl             string
}

func (g *mqlGcpProjectComputeServiceInstanceGroupManager) id() (string, error) {
	return "gcloud.compute.instanceGroupManager/" + g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceInstanceGroupManager) instanceTemplate() (*mqlGcpProjectComputeServiceInstanceTemplate, error) {
	url := g.cacheInstanceTemplateUrl
	if url == "" {
		g.InstanceTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	name := url[strings.LastIndex(url, "/")+1:]

	obj, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.ProjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	svc := obj.(*mqlGcpProjectComputeService)
	tmpls := svc.GetInstanceTemplates()
	if tmpls.Error != nil {
		return nil, tmpls.Error
	}
	for _, t := range tmpls.Data {
		tmpl := t.(*mqlGcpProjectComputeServiceInstanceTemplate)
		n := tmpl.GetName()
		if n.Error != nil {
			return nil, n.Error
		}
		if n.Data == name {
			return tmpl, nil
		}
	}
	g.InstanceTemplate.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// Network firewall policies

func (g *mqlGcpProjectComputeService) firewallPolicies() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.NetworkFirewallPolicies.List(projectId)
	if err := req.Pages(ctx, func(page *compute.FirewallPolicyList) error {
		for _, fp := range page.Items {
			mqlFP, err := newMqlNetworkFirewallPolicy(g.MqlRuntime, projectId, fp)
			if err != nil {
				return err
			}
			res = append(res, mqlFP)
		}
		return nil
	}); err != nil {
		if gerr, ok := err.(*googleapi.Error); ok && gerr.Code == 403 {
			log.Warn().Str("project", projectId).Err(err).Msg("could not list compute network firewall policies")
			return nil, nil
		}
		return nil, err
	}

	regional, err := listRegionalNetworkFirewallPolicies(g.MqlRuntime, projectId)
	if err != nil {
		return nil, err
	}
	return append(res, regional...), nil
}

// listRegionalNetworkFirewallPolicies lists the regional network firewall
// policies of a project. The aggregated list also carries the global
// policies under the "global" scope; those are already listed by
// NetworkFirewallPolicies.List, so only the regional scopes are read here.
//
// A refused aggregated list, or a region reported unreachable, drops only the
// regional policies: the global ones stay (ADR 046 section 8).
func listRegionalNetworkFirewallPolicies(runtime *plugin.Runtime, projectId string) ([]any, error) {
	conn := runtime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := computeSvc.NetworkFirewallPolicies.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.NetworkFirewallPolicyAggregatedList) error {
		for _, u := range page.Unreachables {
			log.Warn().Str("project", projectId).Str("scope", u).Msg("could not list regional network firewall policies in an unreachable scope")
		}
		for scope, scoped := range page.Items {
			if !isRegionalScope(scope) {
				continue
			}
			for _, fp := range scoped.FirewallPolicies {
				if fp == nil || fp.Region == "" {
					continue
				}
				mqlFP, err := newMqlNetworkFirewallPolicy(runtime, projectId, fp)
				if err != nil {
					return err
				}
				res = append(res, mqlFP)
			}
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Warn().Str("project", projectId).Err(err).Msg("could not list regional network firewall policies")
			return []any{}, nil
		}
		return nil, err
	}
	return res, nil
}

// isRegionalScope reports whether a key of a Compute aggregated list names a
// region ("regions/us-central1") rather than the global scope or a zone.
func isRegionalScope(scope string) bool {
	return strings.HasPrefix(scope, "regions/") && len(scope) > len("regions/")
}

func newMqlNetworkFirewallPolicy(runtime *plugin.Runtime, projectId string, fp *compute.FirewallPolicy) (*mqlGcpProjectComputeServiceFirewallPolicy, error) {
	associations, _ := convert.JsonToDictSlice(fp.Associations)

	mqlFP, err := CreateResource(runtime, "gcp.project.computeService.firewallPolicy", map[string]*llx.RawData{
		"id":        llx.StringData(strconv.FormatUint(fp.Id, 10)),
		"projectId": llx.StringData(projectId),
		// ShortName and DisplayName are documented "not applicable to
		// network firewall policies" and always come back empty from
		// NetworkFirewallPolicies.List; Name carries the user-provided
		// name for this policy kind.
		"name":           llx.StringData(fp.Name),
		"displayName":    llx.StringData(fp.DisplayName),
		"description":    llx.StringData(fp.Description),
		"selfLink":       llx.StringData(fp.SelfLink),
		"ruleTupleCount": llx.IntData(fp.RuleTupleCount),
		"created":        llx.TimeDataPtr(parseTime(fp.CreationTimestamp)),
		"associations":   llx.ArrayData(associations, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	mqlPolicy := mqlFP.(*mqlGcpProjectComputeServiceFirewallPolicy)
	mqlPolicy.cacheRegionUrl = fp.Region
	mqlPolicy.cacheRules = fp.Rules
	return mqlPolicy, nil
}

type mqlGcpProjectComputeServiceFirewallPolicyInternal struct {
	cacheRules     []*compute.FirewallPolicyRule
	cacheRegionUrl string
}

// firewallPolicyCacheId returns the cache id of a network firewall policy.
//
// A global policy keeps the id it has always had. A regional policy is keyed
// by its self-link, which carries the region, so it can never share an id
// with a global policy.
func firewallPolicyCacheId(id, selfLink string) string {
	if isRegionalSelfLink(selfLink) {
		return "gcloud.compute.firewallPolicy/" + selfLink
	}
	return "gcloud.compute.firewallPolicy/" + id
}

// isRegionalSelfLink reports whether a Compute self-link addresses a regional
// resource.
func isRegionalSelfLink(selfLink string) bool {
	return strings.Contains(selfLink, "/regions/")
}

func (g *mqlGcpProjectComputeServiceFirewallPolicy) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return firewallPolicyCacheId(g.Id.Data, g.SelfLink.Data), nil
}

// ruleIdPrefix qualifies the ids of the policy's rules. Global policies keep
// their numeric id so their rule ids are unchanged; regional ones use the
// self-link, matching the policy's own cache id.
func (g *mqlGcpProjectComputeServiceFirewallPolicy) ruleIdPrefix() string {
	if isRegionalSelfLink(g.SelfLink.Data) {
		return g.SelfLink.Data
	}
	return g.Id.Data
}

func (g *mqlGcpProjectComputeServiceFirewallPolicy) fetchRules() ([]*compute.FirewallPolicyRule, error) {
	projectId := g.ProjectId.Data
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	if g.cacheRegionUrl != "" {
		region := RegionNameFromRegionUrl(g.cacheRegionUrl)
		policy, err := computeSvc.RegionNetworkFirewallPolicies.Get(projectId, region, name).Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		return policy.Rules, nil
	}

	policy, err := computeSvc.NetworkFirewallPolicies.Get(projectId, name).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return policy.Rules, nil
}

func (g *mqlGcpProjectComputeServiceFirewallPolicy) rules() ([]any, error) {
	if g.cacheRules == nil {
		// If the resource was resolved from cache rather than through the list,
		// fetch the policy from the API to get its rules.
		rules, err := g.fetchRules()
		if err != nil {
			return nil, err
		}
		g.cacheRules = rules
		if g.cacheRules == nil {
			return nil, nil
		}
	}
	return mqlFirewallPolicyRules(g.MqlRuntime, g.ruleIdPrefix(), g.cacheRules)
}

// mqlFirewallPolicyRules maps firewall policy rules onto MQL resources.
//
// Network firewall policies (attached to a project's network) and hierarchical
// firewall policies (attached to an organization or folder) carry the same rule
// type, so both share this mapping. policyId qualifies the generated rule ids so
// rules from two policies cannot collide in the resource cache.
func mqlFirewallPolicyRules(runtime *plugin.Runtime, policyId string, rules []*compute.FirewallPolicyRule) ([]any, error) {
	res := make([]any, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		match, _ := convert.JsonToDict(r.Match)

		var srcIpRanges, destIpRanges, srcAddressGroups, destAddressGroups []any
		var layer4Configs []any
		layer4Protocols := map[string]any{}
		srcSecureTags := map[string]any{}
		if r.Match != nil {
			layer4Protocols = layer4ProtocolPorts(r.Match.Layer4Configs)
			srcIpRanges = convert.SliceAnyToInterface(r.Match.SrcIpRanges)
			destIpRanges = convert.SliceAnyToInterface(r.Match.DestIpRanges)
			srcAddressGroups = convert.SliceAnyToInterface(r.Match.SrcAddressGroups)
			destAddressGroups = convert.SliceAnyToInterface(r.Match.DestAddressGroups)
			for _, l4 := range r.Match.Layer4Configs {
				if l4 == nil {
					continue
				}
				layer4Configs = append(layer4Configs, map[string]any{
					"ipProtocol": l4.IpProtocol,
					"ports":      convert.SliceAnyToInterface(l4.Ports),
				})
			}
			for _, t := range r.Match.SrcSecureTags {
				if t == nil || t.Name == "" {
					continue
				}
				srcSecureTags[t.Name] = t.State
			}
		}
		targetSecureTags := map[string]any{}
		for _, t := range r.TargetSecureTags {
			if t == nil || t.Name == "" {
				continue
			}
			targetSecureTags[t.Name] = t.State
		}

		mqlRule, err := CreateResource(runtime, "gcp.project.computeService.firewallPolicy.rule", map[string]*llx.RawData{
			"id":                    llx.StringData(fmt.Sprintf("%s/rule/%d", policyId, r.Priority)),
			"priority":              llx.IntData(int64(r.Priority)),
			"action":                llx.StringData(r.Action),
			"direction":             llx.StringData(r.Direction),
			"description":           llx.StringData(r.Description),
			"disabled":              llx.BoolData(r.Disabled),
			"enableLogging":         llx.BoolData(r.EnableLogging),
			"match":                 llx.DictData(match),
			"targetResources":       llx.ArrayData(convert.SliceAnyToInterface(r.TargetResources), types.String),
			"targetServiceAccounts": llx.ArrayData(convert.SliceAnyToInterface(r.TargetServiceAccounts), types.String),
			"ruleName":              llx.StringData(r.RuleName),
			"securityProfileGroup":  llx.StringData(r.SecurityProfileGroup),
			"srcIpRanges":           llx.ArrayData(srcIpRanges, types.String),
			"destIpRanges":          llx.ArrayData(destIpRanges, types.String),
			"layer4Configs":         llx.ArrayData(layer4Configs, types.Dict),
			"layer4Protocols":       llx.MapData(layer4Protocols, types.Array(types.String)),
			"srcSecureTags":         llx.MapData(srcSecureTags, types.String),
			"srcAddressGroups":      llx.ArrayData(srcAddressGroups, types.String),
			"destAddressGroups":     llx.ArrayData(destAddressGroups, types.String),
			"targetSecureTags":      llx.MapData(targetSecureTags, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceFirewallPolicyRule) id() (string, error) {
	return g.Id.Data, g.Id.Error
}
