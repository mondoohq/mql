// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

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

type mqlGcpProjectComputeServiceMachineImageInternal struct {
	cacheSourceInstanceUrl string
	cacheKmsKeyName        string
}

func (g *mqlGcpProjectComputeServiceMachineImage) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "gcloud.compute.machineImage/" + g.Id.Data, nil
}

func (g *mqlGcpProjectComputeService) machineImages() ([]any, error) {
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

	res := []any{}
	if err := computeSvc.MachineImages.List(projectId).Pages(ctx, func(page *compute.MachineImageList) error {
		for _, mi := range page.Items {
			if mi == nil {
				continue
			}
			id := strconv.FormatUint(mi.Id, 10)
			encryption, err := newMqlCustomerEncryptionKey(g.MqlRuntime, "gcp.project.computeService.machineImage/"+id, "machineImageEncryption", mi.MachineImageEncryptionKey)
			if err != nil {
				return err
			}
			mqlMI, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.machineImage", map[string]*llx.RawData{
				"id":                     llx.StringData(id),
				"projectId":              llx.StringData(projectId),
				"name":                   llx.StringData(mi.Name),
				"description":            llx.StringData(mi.Description),
				"status":                 llx.StringData(mi.Status),
				"labels":                 llx.MapData(convert.MapToInterfaceMap(mi.Labels), types.String),
				"created":                llx.TimeDataPtr(parseTime(mi.CreationTimestamp)),
				"storageLocations":       llx.ArrayData(convert.SliceAnyToInterface(mi.StorageLocations), types.String),
				"guestFlush":             llx.BoolData(mi.GuestFlush),
				"totalStorageBytes":      llx.IntData(mi.TotalStorageBytes),
				"satisfiesPzi":           llx.BoolData(mi.SatisfiesPzi),
				"satisfiesPzs":           llx.BoolData(mi.SatisfiesPzs),
				"machineImageEncryption": encryption,
			})
			if err != nil {
				return err
			}
			mqlRef := mqlMI.(*mqlGcpProjectComputeServiceMachineImage)
			mqlRef.cacheSourceInstanceUrl = mi.SourceInstance
			if mi.MachineImageEncryptionKey != nil {
				mqlRef.cacheKmsKeyName = mi.MachineImageEncryptionKey.KmsKeyName
			}
			res = append(res, mqlMI)
		}
		return nil
	}); err != nil {
		return listRefusal(err, "could not list compute machine images", "compute.machineImages.list")
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceMachineImage) sourceInstance() (*mqlGcpProjectComputeServiceInstance, error) {
	instance, err := getInstanceByUrl(g.cacheSourceInstanceUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if instance == nil {
		// Empty for a machine image whose source instance was deleted, or
		// one that lives in a project this scan cannot list.
		g.SourceInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return instance, nil
}

func (g *mqlGcpProjectComputeServiceMachineImage) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectComputeServiceMachineImage) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	policy, err := svc.MachineImages.GetIamPolicy(projectId, name).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "compute.machineImages.getIamPolicy"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return computeIamBindingsToResources(g.MqlRuntime,
		"gcp.project.computeService.machineImage/"+projectId+"/"+name, policy.Bindings)
}

func (g *mqlGcpProjectComputeServiceMachineImage) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectComputeServiceMachineImage) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}
