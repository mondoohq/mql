// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

const onPremDirectorySyncPermission = "OnPremDirectorySynchronization.Read.All"

type mqlMicrosoftOnPremisesSynchronizationInternal struct {
	cacheApplicationId string
}

// onPremisesSynchronization reads the tenant's on-premises directory
// synchronization settings. The v1.0 model carries only accidental deletion
// prevention in its configuration, so the beta endpoint is used to read the
// interval, client, export and writeback settings as well.
func (a *mqlMicrosoftTenant) onPremisesSynchronization() (*mqlMicrosoftOnPremisesSynchronization, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Directory().OnPremisesSynchronization().Get(ctx, nil)
	if err == nil {
		var syncs []betamodels.OnPremisesDirectorySynchronizationable
		syncs, err = iterate[betamodels.OnPremisesDirectorySynchronizationable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateOnPremisesDirectorySynchronizationCollectionResponseFromDiscriminatorValue)
		if err == nil {
			return a.onPremisesSynchronizationFrom(selectOnPremisesSync(syncs, a.Id.Data))
		}
	}
	return nil, a.onPremisesSynchronizationError(err)
}

// onPremisesSynchronizationError classifies a failed read. A not-found answer
// is how some cloud-only tenants say nothing is configured, so it reads null
// rather than as an error.
func (a *mqlMicrosoftTenant) onPremisesSynchronizationError(err error) error {
	if isOnPremisesSyncNotConfigured(err) {
		a.OnPremisesSynchronization.State = plugin.StateIsSet | plugin.StateIsNull
		return nil
	}
	return classifyGraphError(err, onPremDirectorySyncPermission)
}

// isOnPremisesSyncNotConfigured reports whether Graph answered that the
// tenant has no synchronization object.
func isOnPremisesSyncNotConfigured(err error) bool {
	return graphStatusCode(err) == 404 || isResourceNotFound(err)
}

// selectOnPremisesSync picks the synchronization object for the tenant. Graph
// keys it by tenant ID, so a match on the ID wins; otherwise the first non-nil
// entry is used. Nil when the collection holds none, as on a cloud-only tenant.
func selectOnPremisesSync(syncs []betamodels.OnPremisesDirectorySynchronizationable, tenantId string) betamodels.OnPremisesDirectorySynchronizationable {
	var first betamodels.OnPremisesDirectorySynchronizationable
	for _, s := range syncs {
		if s == nil {
			continue
		}
		if id := s.GetId(); id != nil && *id == tenantId {
			return s
		}
		if first == nil {
			first = s
		}
	}
	return first
}

func (a *mqlMicrosoftTenant) onPremisesSynchronizationFrom(sync betamodels.OnPremisesDirectorySynchronizationable) (*mqlMicrosoftOnPremisesSynchronization, error) {
	if sync == nil {
		a.OnPremisesSynchronization.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	args, appId := onPremisesSyncArgs(sync, a.Id.Data)
	res, err := CreateResource(a.MqlRuntime, "microsoft.onPremisesSynchronization", args)
	if err != nil {
		return nil, err
	}
	mqlSync := res.(*mqlMicrosoftOnPremisesSynchronization)
	mqlSync.cacheApplicationId = appId
	return mqlSync, nil
}

// onPremisesSyncArgs maps the Graph synchronization object onto the resource
// fields, and returns the synchronization client's application ID separately
// for the service principal accessor. Every value Graph leaves out reads null.
func onPremisesSyncArgs(sync betamodels.OnPremisesDirectorySynchronizationable, tenantId string) (map[string]*llx.RawData, string) {
	id := tenantId
	if sync.GetId() != nil && *sync.GetId() != "" {
		id = *sync.GetId()
	}

	args := map[string]*llx.RawData{
		"__id": llx.StringData("microsoft.onPremisesSynchronization/" + id),
		"id":   llx.StringData(id),

		"accidentalDeletionPreventionType":         llx.NilData,
		"accidentalDeletionAlertThreshold":         llx.NilData,
		"anchorAttribute":                          llx.NilData,
		"synchronizationClientVersion":             llx.NilData,
		"synchronizationInterval":                  llx.NilData,
		"customerRequestedSynchronizationInterval": llx.NilData,
		"exportClientMachineName":                  llx.NilData,
		"exportServiceAccount":                     llx.NilData,
		"exportPendingObjectsAddition":             llx.NilData,
		"exportPendingObjectsDeletion":             llx.NilData,
		"exportPendingObjectsUpdate":               llx.NilData,
		"exportSuccessfulLinksProvisioningCount":   llx.NilData,
		"exportSuccessfulObjectsProvisioningCount": llx.NilData,
		"exportTotalConnectorSpaceObjects":         llx.NilData,
		"unifiedGroupWritebackContainer":           llx.NilData,
		"userWritebackContainer":                   llx.NilData,
	}

	appId := ""
	if cfg := sync.GetConfiguration(); cfg != nil {
		if adp := cfg.GetAccidentalDeletionPrevention(); adp != nil {
			if t := adp.GetSynchronizationPreventionType(); t != nil {
				args["accidentalDeletionPreventionType"] = llx.StringData(t.String())
			}
			args["accidentalDeletionAlertThreshold"] = int32Data(adp.GetAlertThreshold())
		}
		args["anchorAttribute"] = llx.StringDataPtr(cfg.GetAnchorAttribute())
		args["synchronizationClientVersion"] = llx.StringDataPtr(cfg.GetSynchronizationClientVersion())
		if d := cfg.GetSynchronizationInterval(); d != nil {
			args["synchronizationInterval"] = llx.StringData(d.String())
		}
		if d := cfg.GetCustomerRequestedSynchronizationInterval(); d != nil {
			args["customerRequestedSynchronizationInterval"] = llx.StringData(d.String())
		}
		if v := cfg.GetApplicationId(); v != nil {
			appId = *v
		}
		if exp := cfg.GetCurrentExportData(); exp != nil {
			args["exportClientMachineName"] = llx.StringDataPtr(exp.GetClientMachineName())
			args["exportServiceAccount"] = llx.StringDataPtr(exp.GetServiceAccount())
			args["exportPendingObjectsAddition"] = int32Data(exp.GetPendingObjectsAddition())
			args["exportPendingObjectsDeletion"] = int32Data(exp.GetPendingObjectsDeletion())
			args["exportPendingObjectsUpdate"] = int32Data(exp.GetPendingObjectsUpdate())
			args["exportSuccessfulLinksProvisioningCount"] = llx.IntDataPtr(exp.GetSuccessfulLinksProvisioningCount())
			args["exportSuccessfulObjectsProvisioningCount"] = int32Data(exp.GetSuccessfulObjectsProvisioningCount())
			args["exportTotalConnectorSpaceObjects"] = int32Data(exp.GetTotalConnectorSpaceObjects())
		}
		if wb := cfg.GetWritebackConfiguration(); wb != nil {
			args["unifiedGroupWritebackContainer"] = llx.StringDataPtr(wb.GetUnifiedGroupContainer())
			args["userWritebackContainer"] = llx.StringDataPtr(wb.GetUserContainer())
		}
	}

	f := sync.GetFeatures()
	type featureable = betamodels.OnPremisesDirectorySynchronizationFeatureable
	feature := func(get func(featureable) *bool) *llx.RawData {
		if f == nil {
			return llx.NilData
		}
		return llx.BoolDataPtr(get(f))
	}
	args["allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled"] = feature(featureable.GetAllowOnPremUpdateOfOnPremisesObjectIdentifierEnabled)
	args["blockCloudObjectTakeoverThroughHardMatchEnabled"] = feature(featureable.GetBlockCloudObjectTakeoverThroughHardMatchEnabled)
	args["blockSoftMatchEnabled"] = feature(featureable.GetBlockSoftMatchEnabled)
	args["bypassDirSyncOverridesEnabled"] = feature(featureable.GetBypassDirSyncOverridesEnabled)
	args["cloudPasswordPolicyForPasswordSyncedUsersEnabled"] = feature(featureable.GetCloudPasswordPolicyForPasswordSyncedUsersEnabled)
	args["concurrentCredentialUpdateEnabled"] = feature(featureable.GetConcurrentCredentialUpdateEnabled)
	args["concurrentOrgIdProvisioningEnabled"] = feature(featureable.GetConcurrentOrgIdProvisioningEnabled)
	args["deviceWritebackEnabled"] = feature(featureable.GetDeviceWritebackEnabled)
	args["directoryExtensionsEnabled"] = feature(featureable.GetDirectoryExtensionsEnabled)
	args["fopeConflictResolutionEnabled"] = feature(featureable.GetFopeConflictResolutionEnabled)
	args["groupWriteBackEnabled"] = feature(featureable.GetGroupWriteBackEnabled)
	args["passwordSyncEnabled"] = feature(featureable.GetPasswordSyncEnabled)
	args["passwordWritebackEnabled"] = feature(featureable.GetPasswordWritebackEnabled)
	args["quarantineUponProxyAddressesConflictEnabled"] = feature(featureable.GetQuarantineUponProxyAddressesConflictEnabled)
	args["quarantineUponUpnConflictEnabled"] = feature(featureable.GetQuarantineUponUpnConflictEnabled)
	args["softMatchOnUpnEnabled"] = feature(featureable.GetSoftMatchOnUpnEnabled)
	args["synchronizeUpnForManagedUsersEnabled"] = feature(featureable.GetSynchronizeUpnForManagedUsersEnabled)
	args["unifiedGroupWritebackEnabled"] = feature(featureable.GetUnifiedGroupWritebackEnabled)
	args["userForcePasswordChangeOnLogonEnabled"] = feature(featureable.GetUserForcePasswordChangeOnLogonEnabled)
	args["userWritebackEnabled"] = feature(featureable.GetUserWritebackEnabled)

	return args, appId
}

// int32Data widens an optional 32-bit count, keeping an absent value null.
func int32Data(v *int32) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.IntData(int64(*v))
}

func (m *mqlMicrosoftOnPremisesSynchronization) id() (string, error) {
	return m.Id.Data, nil
}

// servicePrincipal resolves the synchronization client's application ID
// through the tenant's cached service principal list.
func (m *mqlMicrosoftOnPremisesSynchronization) servicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	if m.cacheApplicationId == "" {
		m.ServicePrincipal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "microsoft.serviceprincipal", map[string]*llx.RawData{
		"appId": llx.StringData(m.cacheApplicationId),
	})
	if err != nil {
		if errors.Is(err, errServicePrincipalNotFound) {
			log.Debug().Str("appId", m.cacheApplicationId).Msg("ms365> no service principal for the directory synchronization client application")
			m.ServicePrincipal.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlMicrosoftServiceprincipal), nil
}
