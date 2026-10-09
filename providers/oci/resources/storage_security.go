// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"strconv"

	"github.com/oracle/oci-go-sdk/v65/bastion"
	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// ---- bucket lifecycle and replication ----

func (o *mqlOciObjectStorageBucket) regionKey() string {
	if r := o.GetRegion(); r.Error == nil && r.Data != nil {
		return r.Data.Id.Data
	}
	return ""
}

func ociServiceStatus(err error) int {
	if f, ok := common.IsServiceError(err); ok {
		return f.GetHTTPStatusCode()
	}
	return 0
}

func (o *mqlOciObjectStorageBucket) lifecycleRules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.ObjectStorageClient(o.regionKey())
	if err != nil {
		return nil, err
	}
	resp, err := svc.GetObjectLifecyclePolicy(context.Background(), objectstorage.GetObjectLifecyclePolicyRequest{
		NamespaceName: common.String(o.Namespace.Data),
		BucketName:    common.String(o.Name.Data),
	})
	// A bucket without a lifecycle policy answers 404: no rules.
	if ociServiceStatus(err) == http.StatusNotFound {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(resp.Items))
	for i, rule := range resp.Items {
		args := lifecycleRuleArgs(rule)
		args["__id"] = llx.StringData(ociBucketCacheKey(o.Namespace.Data, o.Name.Data) + "/lifecycle/" + strconv.Itoa(i))
		m, err := CreateResource(o.MqlRuntime, "oci.objectStorage.bucket.lifecycleRule", args)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func lifecycleRuleArgs(r objectstorage.ObjectLifecycleRule) map[string]*llx.RawData {
	var prefixes []string
	if r.ObjectNameFilter != nil {
		prefixes = r.ObjectNameFilter.InclusionPrefixes
	}
	return map[string]*llx.RawData{
		"name":              llx.StringDataPtr(r.Name),
		"action":            llx.StringDataPtr(r.Action),
		"target":            llx.StringData(stringValue(r.Target)),
		"timeAmount":        llx.IntDataPtr(r.TimeAmount),
		"timeUnit":          llx.StringData(string(r.TimeUnit)),
		"isEnabled":         llx.BoolData(r.IsEnabled != nil && *r.IsEnabled),
		"inclusionPrefixes": llx.ArrayData(stringsToAny(prefixes), types.String),
	}
}

func (o *mqlOciObjectStorageBucket) replicationPolicies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.ObjectStorageClient(o.regionKey())
	if err != nil {
		return nil, err
	}
	policies, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]objectstorage.ReplicationPolicySummary, *string, error) {
		resp, err := svc.ListReplicationPolicies(ctx, objectstorage.ListReplicationPoliciesRequest{
			NamespaceName: common.String(o.Namespace.Data),
			BucketName:    common.String(o.Name.Data),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(policies))
	for i, p := range policies {
		m, err := CreateResource(o.MqlRuntime, "oci.objectStorage.bucket.replicationPolicy", map[string]*llx.RawData{
			"__id":                  llx.StringData(ociBucketCacheKey(o.Namespace.Data, o.Name.Data) + "/replication/" + rowKey(stringValue(p.Id), i)),
			"id":                    llx.StringDataPtr(p.Id),
			"name":                  llx.StringDataPtr(p.Name),
			"destinationRegion":     llx.StringDataPtr(p.DestinationRegionName),
			"destinationBucketName": llx.StringDataPtr(p.DestinationBucketName),
			"status":                llx.StringData(string(p.Status)),
			"statusMessage":         llx.StringData(stringValue(p.StatusMessage)),
			"created":               sdkTimeData(p.TimeCreated),
			"lastSync":              sdkTimeData(p.TimeLastSync),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- vault replication and external key manager ----

func (o *mqlOciKmsVault) vaultDetail() (*keymanagement.Vault, error) {
	return o.detail.get(func() (*keymanagement.Vault, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.KmsVaultClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetVault(context.Background(), keymanagement.GetVaultRequest{VaultId: common.String(o.Id.Data)})
		if err != nil {
			return nil, err
		}
		return &resp.Vault, nil
	})
}

func (o *mqlOciKmsVault) isPrimary() (bool, error) {
	v, err := o.vaultDetail()
	if err != nil {
		return false, err
	}
	return boolValue(v.IsPrimary), nil
}

func (o *mqlOciKmsVault) isVaultReplicable() (bool, error) {
	v, err := o.vaultDetail()
	if err != nil {
		return false, err
	}
	return boolValue(v.IsVaultReplicable), nil
}

func (o *mqlOciKmsVault) externalVaultEndpointUrl() (string, error) {
	v, err := o.vaultDetail()
	if err != nil || v.ExternalKeyManagerMetadataSummary == nil {
		return "", err
	}
	return stringValue(v.ExternalKeyManagerMetadataSummary.ExternalVaultEndpointUrl), nil
}

func (o *mqlOciKmsVault) externalKeyManagerVendor() (string, error) {
	v, err := o.vaultDetail()
	if err != nil || v.ExternalKeyManagerMetadataSummary == nil {
		return "", err
	}
	return stringValue(v.ExternalKeyManagerMetadataSummary.Vendor), nil
}

func (o *mqlOciKmsVault) replicas() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.KmsVaultClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}
	replicas, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]keymanagement.VaultReplicaSummary, *string, error) {
		resp, err := svc.ListVaultReplicas(ctx, keymanagement.ListVaultReplicasRequest{VaultId: common.String(o.Id.Data), Page: page})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(replicas))
	for i, r := range replicas {
		m, err := CreateResource(o.MqlRuntime, "oci.kms.vault.replica", map[string]*llx.RawData{
			"__id":               llx.StringData(o.Id.Data + "/replica/" + rowKey(stringValue(r.Region), i)),
			"region":             llx.StringDataPtr(r.Region),
			"status":             llx.StringData(string(r.Status)),
			"cryptoEndpoint":     llx.StringData(stringValue(r.CryptoEndpoint)),
			"managementEndpoint": llx.StringData(stringValue(r.ManagementEndpoint)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- Cloud Guard target recipes and managed lists ----

func (o *mqlOciCloudGuardTarget) targetDetail() (*cloudguard.Target, error) {
	return o.detail.get(func() (*cloudguard.Target, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.CloudGuardClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetTarget(context.Background(), cloudguard.GetTargetRequest{TargetId: common.String(o.Id.Data)})
		if err != nil {
			return nil, err
		}
		return &resp.Target, nil
	})
}

func ociCloudGuardService(runtime *plugin.Runtime) (*mqlOciCloudGuard, error) {
	res, err := CreateResource(runtime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciCloudGuard), nil
}

// targetRecipeIDs returns the source recipe of each recipe a target applies:
// a target holds its own copies, which name the recipe they were made from.
func targetRecipeIDs(t *cloudguard.Target) (detector, responder []string) {
	for _, r := range t.TargetDetectorRecipes {
		if id := stringValue(r.DetectorRecipeId); id != "" {
			detector = append(detector, id)
		}
	}
	for _, r := range t.TargetResponderRecipes {
		if id := stringValue(r.ResponderRecipeId); id != "" {
			responder = append(responder, id)
		}
	}
	return detector, responder
}

func (o *mqlOciCloudGuardTarget) detectorRecipes() ([]any, error) {
	t, err := o.targetDetail()
	if err != nil {
		return nil, err
	}
	cg, err := ociCloudGuardService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ids, _ := targetRecipeIDs(t)
	return pickListed(cg.GetDetectorRecipes(), ids)
}

func (o *mqlOciCloudGuardTarget) responderRecipes() ([]any, error) {
	t, err := o.targetDetail()
	if err != nil {
		return nil, err
	}
	cg, err := ociCloudGuardService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	_, ids := targetRecipeIDs(t)
	return pickListed(cg.GetResponderRecipes(), ids)
}

func (o *mqlOciCloudGuardTarget) inheritedByCompartments() ([]any, error) {
	t, err := o.targetDetail()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(t.InheritedByCompartments))
	for _, id := range t.InheritedByCompartments {
		var field plugin.TValue[*mqlOciCompartment]
		c, err := resolveOciCompartment(o.MqlRuntime, id, &field)
		if err != nil {
			ociLogSkippedRef("compartment", id, err)
			continue
		}
		if c != nil {
			out = append(out, c)
		}
	}
	return out, nil
}

type mqlOciCloudGuardManagedListInternal struct {
	ociCompartmentRef
}

func (o *mqlOciCloudGuardManagedList) id() (string, error) {
	return "oci.cloudGuard.managedList/" + o.Id.Data, nil
}

func (o *mqlOciCloudGuardManagedList) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// managedLists is one subtree call for the whole tenancy, narrowed to the
// compartments the filters admit.
func (o *mqlOciCloudGuard) managedLists() ([]any, error) {
	items, err := o.listManagedLists()
	return ociKeepAdmitted(o.MqlRuntime, items, err)
}

func (o *mqlOciCloudGuard) listManagedLists() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	serviceRegion, err := o.getServiceRegion()
	if err != nil {
		return nil, err
	}
	client, err := conn.CloudGuardClient(serviceRegion)
	if err != nil {
		return nil, err
	}
	lists, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]cloudguard.ManagedListSummary, *string, error) {
		resp, err := client.ListManagedLists(ctx, cloudguard.ListManagedListsRequest{
			CompartmentId:          common.String(conn.TenantID()),
			CompartmentIdInSubtree: common.Bool(true),
			AccessLevel:            cloudguard.ListManagedListsAccessLevelAccessible,
			Page:                   page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		if ociCloudGuardNotSubscribed(err) {
			return []any{}, nil
		}
		return nil, err
	}
	out := make([]any, 0, len(lists))
	for _, l := range lists {
		m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.managedList", stringValue(l.CompartmentId), map[string]*llx.RawData{
			"id":           llx.StringDataPtr(l.Id),
			"name":         llx.StringDataPtr(l.DisplayName),
			"description":  llx.StringData(stringValue(l.Description)),
			"listType":     llx.StringData(string(l.ListType)),
			"feedProvider": llx.StringData(string(l.FeedProvider)),
			"listItems":    llx.ArrayData(stringsToAny(l.ListItems), types.String),
			"isEditable":   llx.BoolData(boolValue(l.IsEditable)),
			"state":        llx.StringData(string(l.LifecycleState)),
			"created":      sdkTimeData(l.TimeCreated),
			"freeformTags": llx.MapData(strMapToAny(l.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(l.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- Bastion sessions ----

type mqlOciBastionSessionInternal struct {
	cacheTargetInstanceID string
}

func (o *mqlOciBastionSession) id() (string, error) {
	return "oci.bastion.session/" + o.Id.Data, nil
}

func (o *mqlOciBastionInstance) sessions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.BastionClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}
	sessions, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]bastion.SessionSummary, *string, error) {
		resp, err := svc.ListSessions(ctx, bastion.ListSessionsRequest{BastionId: common.String(o.Id.Data), Page: page})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(sessions))
	for _, s := range sessions {
		args, instanceID := bastionSessionArgs(s)
		m, err := CreateResource(o.MqlRuntime, "oci.bastion.session", args)
		if err != nil {
			return nil, err
		}
		m.(*mqlOciBastionSession).cacheTargetInstanceID = instanceID
		out = append(out, m)
	}
	return out, nil
}

// bastionSessionArgs maps a session and its target, whose shape depends on
// the session type.
func bastionSessionArgs(s bastion.SessionSummary) (map[string]*llx.RawData, string) {
	args := map[string]*llx.RawData{
		"id":              llx.StringDataPtr(s.Id),
		"name":            llx.StringData(stringValue(s.DisplayName)),
		"sessionType":     llx.StringData(""),
		"state":           llx.StringData(string(s.LifecycleState)),
		"ttlInSeconds":    intPtrData(s.SessionTtlInSeconds),
		"targetPrivateIp": llx.StringData(""),
		"targetPort":      llx.NilData,
		"targetUser":      llx.StringData(""),
		"created":         sdkTimeData(s.TimeCreated),
	}
	instanceID := ""
	switch t := s.TargetResourceDetails.(type) {
	case bastion.ManagedSshSessionTargetResourceDetails:
		args["sessionType"] = llx.StringData("MANAGED_SSH")
		args["targetPrivateIp"] = llx.StringData(stringValue(t.TargetResourcePrivateIpAddress))
		args["targetPort"] = intPtrData(t.TargetResourcePort)
		args["targetUser"] = llx.StringData(stringValue(t.TargetResourceOperatingSystemUserName))
		instanceID = stringValue(t.TargetResourceId)
	case bastion.PortForwardingSessionTargetResourceDetails:
		args["sessionType"] = llx.StringData("PORT_FORWARDING")
		args["targetPrivateIp"] = llx.StringData(stringValue(t.TargetResourcePrivateIpAddress))
		args["targetPort"] = intPtrData(t.TargetResourcePort)
		instanceID = stringValue(t.TargetResourceId)
	case bastion.DynamicPortForwardingSessionTargetResourceDetails:
		args["sessionType"] = llx.StringData("DYNAMIC_PORT_FORWARDING")
	}
	return args, instanceID
}

func (o *mqlOciBastionSession) targetInstance() (*mqlOciComputeInstance, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.GetInstances(), o.cacheTargetInstanceID, &o.TargetInstance)
}
