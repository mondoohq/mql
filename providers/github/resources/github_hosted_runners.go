// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/google/go-github/v93/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// ---------- GitHub-hosted larger runners ----------

type mqlGithubHostedRunnerInternal struct {
	cacheOrg           *mqlGithubOrganization
	cacheRunnerGroupID *int64
}

func (g *mqlGithubHostedRunner) id() (string, error) {
	return g.__id, nil
}

// hostedRunnerPublicIPs formats the static public IP ranges of a runner in
// CIDR notation. A range GitHub reports as not enabled is not in use and is
// left out.
func hostedRunnerPublicIPs(ips []*github.HostedRunnerPublicIP) []any {
	res := []any{}
	for _, ip := range ips {
		if ip == nil || !ip.Enabled || ip.Prefix == "" {
			continue
		}
		res = append(res, ip.Prefix+"/"+strconv.Itoa(ip.Length))
	}
	return res
}

func hostedRunnerArgs(orgLogin string, h *github.HostedRunner) map[string]*llx.RawData {
	img := h.ImageDetails
	if img == nil {
		img = &github.HostedRunnerImageDetail{}
	}
	machineSize, cpuCores, memoryGb, storageGb := llx.NilData, llx.NilData, llx.NilData, llx.NilData
	if m := h.MachineSizeDetails; m != nil {
		machineSize = llx.StringData(m.ID)
		cpuCores = llx.IntData(int64(m.CPUCores))
		memoryGb = llx.IntData(int64(m.MemoryGB))
		storageGb = llx.IntData(int64(m.StorageGB))
	}
	return map[string]*llx.RawData{
		"__id":             llx.StringData("github.hostedRunner/" + orgLogin + "/" + strconv.FormatInt(h.GetID(), 10)),
		"id":               llx.IntDataPtr(h.ID),
		"name":             llx.StringDataPtr(h.Name),
		"platform":         llx.StringDataPtr(h.Platform),
		"status":           llx.StringDataPtr(h.Status),
		"imageId":          llx.StringDataPtr(img.ID),
		"imageDisplayName": llx.StringDataPtr(img.DisplayName),
		"imageSource":      llx.StringDataPtr(img.Source),
		"imageVersion":     llx.StringDataPtr(img.Version),
		"imageSizeGb":      llx.IntDataPtr(img.SizeGB),
		"imageGen":         llx.BoolDataPtr(h.ImageGen),
		"machineSize":      machineSize,
		"cpuCores":         cpuCores,
		"memoryGb":         memoryGb,
		"storageGb":        storageGb,
		"maximumRunners":   llx.IntDataPtr(h.MaximumRunners),
		"publicIpEnabled":  llx.BoolDataPtr(h.PublicIPEnabled),
		"publicIps":        llx.ArrayData(hostedRunnerPublicIPs(h.PublicIPs), types.String),
		"lastActiveOn":     llx.TimeDataPtr(githubTime(h.LastActiveOn)),
	}
}

func (g *mqlGithubOrganization) hostedRunners() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.HostedRunner, *github.Response, error) {
		page, resp, err := conn.Client().Actions.ListHostedRunners(conn.Context(), orgLogin, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Runners, resp, nil
	})
	if err != nil {
		if err := classifyReadErr(err, "hosted runners", orgLogin); err != nil {
			return nil, err
		}
		g.HostedRunners.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, h := range all {
		if h == nil || h.ID == nil {
			continue
		}
		r, err := CreateResource(g.MqlRuntime, "github.hostedRunner", hostedRunnerArgs(orgLogin, h))
		if err != nil {
			return nil, err
		}
		runner := r.(*mqlGithubHostedRunner)
		runner.cacheOrg = g
		runner.cacheRunnerGroupID = h.RunnerGroupID
		res = append(res, r)
	}
	return res, nil
}

// runnerGroup resolves the runner's group against the organization's runner
// group list, which is read once and shared by every runner.
func (g *mqlGithubHostedRunner) runnerGroup() (*mqlGithubOrganizationRunnerGroup, error) {
	if g.cacheOrg == nil || g.cacheRunnerGroupID == nil {
		g.RunnerGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	groups := g.cacheOrg.GetRunnerGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	for _, x := range groups.Data {
		group, ok := x.(*mqlGithubOrganizationRunnerGroup)
		if ok && group.Id.Error == nil && group.Id.Data == *g.cacheRunnerGroupID {
			return group, nil
		}
	}
	g.RunnerGroup.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ---------- Hosted compute network configurations ----------

func (g *mqlGithubNetworkConfiguration) id() (string, error) {
	return g.__id, nil
}

func newMqlNetworkConfiguration(runtime *plugin.Runtime, orgLogin string, n *github.NetworkConfiguration) (*mqlGithubNetworkConfiguration, error) {
	computeService := llx.NilData
	if n.ComputeService != nil {
		computeService = llx.StringData(string(*n.ComputeService))
	}
	r, err := CreateResource(runtime, "github.networkConfiguration", map[string]*llx.RawData{
		"__id":               llx.StringData("github.networkConfiguration/" + orgLogin + "/" + n.GetID()),
		"id":                 llx.StringDataPtr(n.ID),
		"name":               llx.StringDataPtr(n.Name),
		"computeService":     computeService,
		"networkSettingsIds": llx.ArrayData(convert.SliceAnyToInterface(n.NetworkSettingsIDs), types.String),
		"createdOn":          llx.TimeDataPtr(githubTime(n.CreatedOn)),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGithubNetworkConfiguration), nil
}

func (g *mqlGithubOrganization) networkConfigurations() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.NetworkConfiguration, *github.Response, error) {
		page, resp, err := conn.Client().Organizations.ListNetworkConfigurations(conn.Context(), orgLogin, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.NetworkConfigurations, resp, nil
	})
	if err != nil {
		if err := classifyReadErr(err, "network configurations", orgLogin); err != nil {
			return nil, err
		}
		g.NetworkConfigurations.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, n := range all {
		if n == nil || n.ID == nil {
			continue
		}
		r, err := newMqlNetworkConfiguration(g.MqlRuntime, orgLogin, n)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// networkConfiguration resolves the group's network configuration. The
// organization's list is read once and shared by every group; a configuration
// missing from it, such as one an enterprise group inherits, is read on its
// own.
func (g *mqlGithubOrganizationRunnerGroup) networkConfiguration() (*mqlGithubNetworkConfiguration, error) {
	if g.NetworkConfigurationId.Error != nil {
		return nil, g.NetworkConfigurationId.Error
	}
	wantID := g.NetworkConfigurationId.Data
	if wantID == "" {
		g.NetworkConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	if g.cacheOrg != nil {
		configs := g.cacheOrg.GetNetworkConfigurations()
		if configs.Error == nil {
			for _, x := range configs.Data {
				n, ok := x.(*mqlGithubNetworkConfiguration)
				if ok && n.Id.Error == nil && n.Id.Data == wantID {
					return n, nil
				}
			}
		}
	}

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	n, _, err := conn.Client().Organizations.GetNetworkConfiguration(conn.Context(), g.cacheOrgLogin, wantID)
	if err != nil {
		if err := classifyReadErr(err, "network configuration", g.cacheOrgLogin); err != nil {
			return nil, err
		}
		g.NetworkConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if n == nil || n.ID == nil {
		g.NetworkConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlNetworkConfiguration(g.MqlRuntime, g.cacheOrgLogin, n)
}
