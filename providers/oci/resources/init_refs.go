// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/core"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
)

// ociResolveByID matches an OCID against an already modelled collection and
// returns the populated resource, or a not-found error.
//
// The error matters. Without an Init, NewResource falls straight through to
// Create and builds the resource from the id alone, leaving every other field
// *unset* rather than null - which surfaces client-side as "encountered a
// primitive with no type information" with nothing pointing at the cause. Worse,
// the generated CreateResource caches that husk under the real OCID and returns
// it in place of a later fully-populated instance, so whether a query works
// depends on the order resources happen to be resolved in.
func ociResolveByID(args map[string]*llx.RawData, resourceName, id string, items []any) (map[string]*llx.RawData, plugin.Resource, error) {
	for _, raw := range items {
		res, ok := raw.(plugin.Resource)
		if !ok {
			continue
		}
		idField, ok := raw.(interface{ GetId() *plugin.TValue[string] })
		if ok && idField.GetId().Data == id {
			return args, res, nil
		}
	}
	return nil, nil, errors.New(resourceName + " not found: " + id)
}

// ociInitArgs handles the two argument shapes every singular init shares: an
// already-complete arg set, and a bare resource with no id (a valid empty
// state). It reports the id to resolve, or ok=false when the init should return
// the args untouched.
func ociInitArgs(args map[string]*llx.RawData) (id string, resolve bool) {
	if len(args) > 2 {
		return "", false
	}
	id = ociArgString(args, "id")
	if id == "" {
		return "", false
	}
	return id, true
}

// ociServiceCollection creates a service singleton and returns one of its
// collections, so the inits below reuse the listing path's auth, pagination and
// region fan-out rather than duplicating it.
func ociServiceCollection(runtime *plugin.Runtime, service string, list func(plugin.Resource) *plugin.TValue[[]any]) ([]any, error) {
	obj, err := CreateResource(runtime, service, nil)
	if err != nil {
		return nil, err
	}
	items := list(obj)
	if items.Error != nil {
		return nil, items.Error
	}
	return items.Data, nil
}

func initOciComputeInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.compute", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciCompute).GetInstances()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.compute.instance", id, items)
}

func initOciComputeImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.compute", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciCompute).GetImages()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.compute.image", id, items)
}

func initOciComputeBlockVolume(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.compute", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciCompute).GetBlockVolumes()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.compute.blockVolume", id, items)
}

func initOciComputeBootVolume(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.compute", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciCompute).GetBootVolumes()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.compute.bootVolume", id, items)
}

// initOciComputeVnic fetches the VNIC directly rather than scanning every
// instance's attachments: the region is recoverable from the OCID, so a single
// GetVnic is both cheaper and independent of which compartment the VNIC lives
// in.
func initOciComputeVnic(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	region := ociRegionFromOCID(id)
	if region == "" {
		return nil, nil, errors.New("could not determine region from vnic ocid: " + id)
	}

	conn := runtime.Connection.(*connection.OciConnection)
	svc, err := conn.NetworkClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := svc.GetVnic(context.Background(), core.GetVnicRequest{VnicId: new(id)})
	if err != nil {
		return nil, nil, err
	}

	vnic, err := ociVnicToMql(runtime, resp.Vnic)
	if err != nil {
		return nil, nil, err
	}
	return args, vnic, nil
}

func initOciDatabaseDbSystem(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.database", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDatabase).GetDbSystems()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.database.dbSystem", id, items)
}

func initOciDatabaseAutonomousDatabase(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.database", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDatabase).GetAutonomousDatabases()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.database.autonomousDatabase", id, items)
}

func initOciFileStorageFileSystem(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.fileStorage", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciFileStorage).GetFileSystems()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.fileStorage.fileSystem", id, items)
}

func initOciFileStorageExportSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.fileStorage", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciFileStorage).GetExportSets()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.fileStorage.exportSet", id, items)
}

func initOciFileStorageSnapshotPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.fileStorage", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciFileStorage).GetSnapshotPolicies()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.fileStorage.snapshotPolicy", id, items)
}

func initOciFileStorageOutboundConnector(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.fileStorage", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciFileStorage).GetOutboundConnectors()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.fileStorage.outboundConnector", id, items)
}

func initOciApigatewayGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.apigateway", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciApigateway).GetGateways()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.apigateway.gateway", id, items)
}

func initOciIdentityIdentityProvider(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.identity", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciIdentity).GetIdentityProviders()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.identity.identityProvider", id, items)
}

func initOciArtifactsContainerRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.artifacts", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciArtifacts).GetContainerRepositories()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.artifacts.containerRepository", id, items)
}

func initOciArtifactsContainerImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.artifacts", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciArtifacts).GetContainerImages()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.artifacts.containerImage", id, items)
}

func initOciArtifactsRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.artifacts", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciArtifacts).GetRepositories()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.artifacts.repository", id, items)
}

func initOciOperatorAccessControlControl(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.operatorAccessControl", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciOperatorAccessControl).GetControls()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.operatorAccessControl.control", id, items)
}

func initOciDelegateAccessControlDelegationControl(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.delegateAccessControl", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDelegateAccessControl).GetDelegationControls()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.delegateAccessControl.delegationControl", id, items)
}

func initOciDelegateAccessControlServiceProvider(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.delegateAccessControl", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciDelegateAccessControl).GetServiceProviders()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.delegateAccessControl.serviceProvider", id, items)
}

func initOciLockboxLockbox(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.lockbox", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciLockbox).GetLockboxes()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.lockbox.lockbox", id, items)
}

func initOciLockboxApprovalTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.lockbox", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciLockbox).GetApprovalTemplates()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.lockbox.approvalTemplate", id, items)
}

func initOciRegion(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOci).GetRegions()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.region", id, items)
}
