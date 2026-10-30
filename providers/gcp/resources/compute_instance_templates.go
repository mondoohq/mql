// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

func (g *mqlGcpProjectComputeService) instanceTemplates() ([]any, error) {
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

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.InstanceTemplates.List(projectId)
	if err := req.Pages(ctx, func(page *compute.InstanceTemplateList) error {
		for _, tmpl := range page.Items {
			properties, err := convert.JsonToDict(tmpl.Properties)
			if err != nil {
				return err
			}

			templateID := "gcp.project.computeService.instanceTemplate/" + strconv.FormatUint(tmpl.Id, 10)
			vmProperties, err := newMqlInstanceTemplateProperties(g.MqlRuntime, templateID, tmpl.Properties)
			if err != nil {
				return err
			}

			mqlTmpl, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.instanceTemplate", map[string]*llx.RawData{
				"id":                llx.StringData(strconv.FormatUint(tmpl.Id, 10)),
				"name":              llx.StringData(tmpl.Name),
				"description":       llx.StringData(tmpl.Description),
				"selfLink":          llx.StringData(tmpl.SelfLink),
				"sourceInstance":    llx.StringData(tmpl.SourceInstance),
				"properties":        llx.DictData(properties),
				"vmProperties":      vmProperties,
				"creationTimestamp": llx.TimeDataPtr(parseTime(tmpl.CreationTimestamp)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlTmpl)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectComputeServiceInstanceTemplate) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return fmt.Sprintf("gcp.project.computeService.instanceTemplate/%s", id), nil
}

func (g *mqlGcpProjectComputeServiceInstanceTemplate) sourceInstanceRef() (*mqlGcpProjectComputeServiceInstance, error) {
	if g.SourceInstance.Error != nil {
		return nil, g.SourceInstance.Error
	}
	url := g.SourceInstance.Data
	if url == "" {
		g.SourceInstanceRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// URL format: https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{name}
	params := strings.TrimPrefix(url, "https://www.googleapis.com/compute/v1/")
	params = strings.TrimPrefix(params, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	if len(parts) < 6 || parts[0] != "projects" || parts[2] != "zones" || parts[4] != "instances" {
		g.SourceInstanceRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, zone, name := parts[1], parts[3], parts[5]

	res, err := NewResource(g.MqlRuntime, "gcp.project.computeService.instance", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"region":    llx.StringData(zone),
		"projectId": llx.StringData(project),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceInstance), nil
}

// newMqlInstanceTemplateProperties promotes the instance-properties block of an
// instance template into a resource. Returns llx.NilData when the template
// carries no properties, which the API only does for a malformed template.
//
// The flattened booleans come from optional nested messages
// (shieldedInstanceConfig, confidentialInstanceConfig, scheduling,
// advancedMachineFeatures). An absent message means the feature is off, so each
// one reports false rather than staying null: a Secure Boot audit has to be able
// to tell "off" from "not read".
func newMqlInstanceTemplateProperties(runtime *plugin.Runtime, templateID string, props *compute.InstanceProperties) (*llx.RawData, error) {
	if props == nil {
		return llx.NilData, nil
	}

	metadata := map[string]any{}
	if props.Metadata != nil {
		for _, item := range props.Metadata.Items {
			if item == nil || item.Value == nil {
				continue
			}
			metadata[item.Key] = *item.Value
		}
	}

	tags := []any{}
	if props.Tags != nil {
		for _, t := range props.Tags.Items {
			tags = append(tags, t)
		}
	}

	var enableSecureBoot, enableVtpm, enableIntegrityMonitoring bool
	if props.ShieldedInstanceConfig != nil {
		enableSecureBoot = props.ShieldedInstanceConfig.EnableSecureBoot
		enableVtpm = props.ShieldedInstanceConfig.EnableVtpm
		enableIntegrityMonitoring = props.ShieldedInstanceConfig.EnableIntegrityMonitoring
	}

	var enableConfidentialCompute bool
	var confidentialInstanceType string
	if props.ConfidentialInstanceConfig != nil {
		enableConfidentialCompute = props.ConfidentialInstanceConfig.EnableConfidentialCompute
		confidentialInstanceType = props.ConfidentialInstanceConfig.ConfidentialInstanceType
	}

	var preemptible bool
	var provisioningModel, instanceTerminationAction string
	if props.Scheduling != nil {
		preemptible = props.Scheduling.Preemptible
		provisioningModel = props.Scheduling.ProvisioningModel
		instanceTerminationAction = props.Scheduling.InstanceTerminationAction
	}

	var nestedVirtualizationEnabled bool
	if props.AdvancedMachineFeatures != nil {
		nestedVirtualizationEnabled = props.AdvancedMachineFeatures.EnableNestedVirtualization
	}

	serviceAccounts := []any{}
	for _, sa := range props.ServiceAccounts {
		if sa == nil {
			continue
		}
		mqlSa, err := CreateResource(runtime, "gcp.project.computeService.serviceaccount", map[string]*llx.RawData{
			"__id":   llx.StringData(templateID + "/serviceaccount/" + sa.Email),
			"email":  llx.StringData(sa.Email),
			"scopes": llx.ArrayData(convert.SliceAnyToInterface(sa.Scopes), types.String),
		})
		if err != nil {
			return nil, err
		}
		serviceAccounts = append(serviceAccounts, mqlSa)
	}

	disks, err := convert.JsonToDictSlice(props.Disks)
	if err != nil {
		return nil, err
	}
	networkInterfaces, err := convert.JsonToDictSlice(props.NetworkInterfaces)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.computeService.instanceTemplate.instanceProperties", map[string]*llx.RawData{
		"__id":                        llx.StringData(templateID + "/vmProperties"),
		"machineType":                 llx.StringData(props.MachineType),
		"canIpForward":                llx.BoolData(props.CanIpForward),
		"minCpuPlatform":              llx.StringData(props.MinCpuPlatform),
		"metadata":                    llx.MapData(metadata, types.String),
		"tags":                        llx.ArrayData(tags, types.String),
		"enableSecureBoot":            llx.BoolData(enableSecureBoot),
		"enableVtpm":                  llx.BoolData(enableVtpm),
		"enableIntegrityMonitoring":   llx.BoolData(enableIntegrityMonitoring),
		"enableConfidentialCompute":   llx.BoolData(enableConfidentialCompute),
		"confidentialInstanceType":    llx.StringData(confidentialInstanceType),
		"serviceAccounts":             llx.ArrayData(serviceAccounts, types.Resource("gcp.project.computeService.serviceaccount")),
		"preemptible":                 llx.BoolData(preemptible),
		"provisioningModel":           llx.StringData(provisioningModel),
		"instanceTerminationAction":   llx.StringData(instanceTerminationAction),
		"keyRevocationActionType":     llx.StringData(props.KeyRevocationActionType),
		"nestedVirtualizationEnabled": llx.BoolData(nestedVirtualizationEnabled),
		"labels":                      llx.MapData(convert.MapToInterfaceMap(props.Labels), types.String),
		"disks":                       llx.ArrayData(disks, types.Dict),
		"networkInterfaces":           llx.ArrayData(networkInterfaces, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.project.computeService.instanceTemplate.instanceProperties"), nil
}
