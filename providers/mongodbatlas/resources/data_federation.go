// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// mqlMongodbatlasDataFederationInternal carries the project the instance was
// listed under, the cloud provider access role it assumes, and the store
// definitions that arrived with the listing.
type mqlMongodbatlasDataFederationInternal struct {
	cacheProjectID string
	cacheRoleID    string
	cacheStores    []admin.DataLakeStoreSettings
}

// dataFederations lists the project's federated database instances. Each serves
// queries over data held outside the cluster, under a cloud provider access
// role, so it describes a path to and from the project that neither the cluster
// nor the network settings cover.
func (r *mqlMongodbatlas) dataFederations() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	// The data federation listing answers with every instance in the project
	// and takes no page parameters.
	tenants, httpResp, err := client.DataFederationAPI.ListDataFederation(ctx, pid).Execute()
	if err != nil {
		// An empty instance set is a real finding, so a denied read is null
		// rather than an empty list.
		if isAccessDenied(httpResp) {
			r.DataFederations.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	out := []any{}
	for i := range tenants {
		res, err := newMqlMongodbatlasDataFederation(r.MqlRuntime, pid, tenants[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlMongodbatlasDataFederation(runtime *plugin.Runtime, pid string, t admin.DataLakeTenant) (*mqlMongodbatlasDataFederation, error) {
	var cloudProvider, region *string
	if dpr, ok := t.GetDataProcessRegionOk(); ok {
		cloudProvider = &dpr.CloudProvider
		region = &dpr.Region
	}

	roleID := ""
	var testBucket *string
	if cfg, ok := t.GetCloudProviderConfigOk(); ok {
		if aws, ok := cfg.GetAwsOk(); ok {
			roleID = aws.GetRoleId()
			bucket := aws.GetTestS3Bucket()
			testBucket = &bucket
		}
	}

	endpoints := map[string]any{}
	for _, pe := range t.GetPrivateEndpointHostnames() {
		if host := pe.GetHostname(); host != "" {
			endpoints[host] = pe.GetPrivateEndpoint()
		}
	}

	res, err := CreateResource(runtime, "mongodbatlas.dataFederation", map[string]*llx.RawData{
		"__id":                     llx.StringData("mongodbatlas.dataFederation/" + pid + "/" + t.GetName()),
		"name":                     llx.StringDataPtr(t.Name),
		"state":                    llx.StringDataPtr(t.State),
		"hostnames":                llx.ArrayData(strSlice(t.GetHostnames()), types.String),
		"cloudProvider":            llx.StringDataPtr(cloudProvider),
		"region":                   llx.StringDataPtr(region),
		"awsTestS3Bucket":          llx.StringDataPtr(testBucket),
		"privateEndpointHostnames": llx.MapData(endpoints, types.String),
	})
	if err != nil {
		return nil, err
	}
	fed := res.(*mqlMongodbatlasDataFederation)
	fed.cacheProjectID = pid
	fed.cacheRoleID = roleID
	if storage, ok := t.GetStorageOk(); ok {
		fed.cacheStores = storage.GetStores()
	}
	return fed, nil
}

// cloudProviderAccessRole resolves the role the instance assumes to read its
// stores, which is the identity the customer's own cloud account grants. Null
// for an instance that reads no cloud storage under a role.
func (r *mqlMongodbatlasDataFederation) cloudProviderAccessRole() (*mqlMongodbatlasCloudProviderAccessRole, error) {
	if r.cacheRoleID == "" {
		r.CloudProviderAccessRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role, err := resolveCloudProviderAccessRole(r.MqlRuntime, r.cacheProjectID, r.cacheRoleID)
	if err != nil {
		return nil, err
	}
	if role == nil {
		r.CloudProviderAccessRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}

// stores expands the backing stores the instance reads. They arrive with the
// instance listing, so this costs no additional call.
func (r *mqlMongodbatlasDataFederation) stores() ([]any, error) {
	out := []any{}
	for i := range r.cacheStores {
		s := r.cacheStores[i]
		res, err := CreateResource(r.MqlRuntime, "mongodbatlas.dataFederation.store", map[string]*llx.RawData{
			// A store name is unique within its instance only, so the project
			// and the instance are both dimensions of the key.
			"__id":                     llx.StringData("mongodbatlas.dataFederation.store/" + r.cacheProjectID + "/" + r.Name.Data + "/" + s.GetName()),
			"name":                     llx.StringDataPtr(s.Name),
			"provider":                 llx.StringData(s.GetProvider()),
			"bucket":                   llx.StringDataPtr(s.Bucket),
			"containerName":            llx.StringDataPtr(s.ContainerName),
			"region":                   llx.StringDataPtr(s.Region),
			"prefix":                   llx.StringDataPtr(s.Prefix),
			"delimiter":                llx.StringDataPtr(s.Delimiter),
			"public":                   llx.BoolDataPtr(s.Public),
			"allowInsecure":            llx.BoolDataPtr(s.AllowInsecure),
			"defaultFormat":            llx.StringDataPtr(s.DefaultFormat),
			"urls":                     llx.ArrayData(strSlice(s.GetUrls()), types.String),
			"serviceUrl":               llx.StringDataPtr(s.ServiceURL),
			"includeTags":              llx.BoolDataPtr(s.IncludeTags),
			"clusterName":              llx.StringDataPtr(s.ClusterName),
			"additionalStorageClasses": llx.ArrayData(strSlice(s.GetAdditionalStorageClasses()), types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
