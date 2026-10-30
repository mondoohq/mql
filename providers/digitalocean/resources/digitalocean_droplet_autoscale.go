// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

type mqlDigitaloceanDropletAutoscalePoolInternal struct {
	templateVpcUUID   string
	templateProjectID string
}

func (r *mqlDigitalocean) dropletAutoscalePools() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	pools, err := paginate(context.Background(), client.DropletAutoscale.List)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(pools))
	for _, p := range pools {
		if p == nil {
			continue
		}

		var minInstances, maxInstances, targetNumberInstances, cooldownMinutes int64
		var targetCPU, targetMem float64
		if p.Config != nil {
			minInstances = int64(p.Config.MinInstances)
			maxInstances = int64(p.Config.MaxInstances)
			targetNumberInstances = int64(p.Config.TargetNumberInstances)
			cooldownMinutes = int64(p.Config.CooldownMinutes)
			targetCPU = p.Config.TargetCPUUtilization
			targetMem = p.Config.TargetMemoryUtilization
		}

		var currentCPU, currentMem float64
		if p.CurrentUtilization != nil {
			currentCPU = p.CurrentUtilization.CPU
			currentMem = p.CurrentUtilization.Memory
		}

		template := map[string]any{}
		if t := p.DropletTemplate; t != nil {
			tags := make([]any, len(t.Tags))
			for i, tag := range t.Tags {
				tags[i] = tag
			}
			sshKeys := make([]any, len(t.SSHKeys))
			for i, k := range t.SSHKeys {
				sshKeys[i] = k
			}
			template = map[string]any{
				"size":             t.Size,
				"region":           t.Region,
				"image":            t.Image,
				"tags":             tags,
				"sshKeys":          sshKeys,
				"vpcUuid":          t.VpcUUID,
				"projectId":        t.ProjectID,
				"ipv6":             t.IPV6,
				"withDropletAgent": t.WithDropletAgent,
				"userData":         t.UserData,
			}
			if t.PublicNetworking != nil {
				template["publicNetworking"] = *t.PublicNetworking
			}
		}

		res, err := CreateResource(r.MqlRuntime, "digitalocean.dropletAutoscalePool", map[string]*llx.RawData{
			"id":                       llx.StringData(p.ID),
			"name":                     llx.StringData(p.Name),
			"status":                   llx.StringData(p.Status),
			"minInstances":             llx.IntData(minInstances),
			"maxInstances":             llx.IntData(maxInstances),
			"targetCpuUtilization":     llx.FloatData(targetCPU),
			"targetMemoryUtilization":  llx.FloatData(targetMem),
			"cooldownMinutes":          llx.IntData(cooldownMinutes),
			"targetNumberInstances":    llx.IntData(targetNumberInstances),
			"currentCpuUtilization":    llx.FloatData(currentCPU),
			"currentMemoryUtilization": llx.FloatData(currentMem),
			"dropletTemplate":          llx.DictData(template),
			"createdAt":                llx.TimeData(p.CreatedAt),
			"updatedAt":                llx.TimeData(p.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		mqlPool := res.(*mqlDigitaloceanDropletAutoscalePool)
		if t := p.DropletTemplate; t != nil {
			mqlPool.templateVpcUUID = t.VpcUUID
			mqlPool.templateProjectID = t.ProjectID
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanDropletAutoscalePool) id() (string, error) {
	return "digitalocean.dropletAutoscalePool/" + r.Id.Data, nil
}

func (r *mqlDigitaloceanDropletAutoscalePool) members() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	ctx := context.Background()

	var dropletIDs []any
	opt := &godo.ListOptions{PerPage: 200}
	for {
		members, resp, err := client.DropletAutoscale.ListMembers(ctx, r.Id.Data, opt)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			if m != nil {
				dropletIDs = append(dropletIDs, int64(m.DropletID))
			}
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}

	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return parent.dropletByIDs(dropletIDs)
}

func (r *mqlDigitaloceanDropletAutoscalePool) project() (*mqlDigitaloceanProject, error) {
	return projectRef(r.MqlRuntime, r.templateProjectID, &r.Project)
}

func (r *mqlDigitaloceanDropletAutoscalePool) vpc() (*mqlDigitaloceanVpc, error) {
	return resolveVpcRef(r.MqlRuntime, &r.Vpc, r.templateVpcUUID)
}
