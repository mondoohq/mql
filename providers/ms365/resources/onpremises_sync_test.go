// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	betaodataerrors "github.com/microsoftgraph/msgraph-beta-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Shape of GET /beta/directory/onPremisesSynchronization/{id}, every count
// distinct so a field mapped from the wrong getter reads a wrong number.
const onPremisesSyncJSON = `{
  "id": "11111111-2222-3333-4444-555555555555",
  "configuration": {
    "accidentalDeletionPrevention": {
      "synchronizationPreventionType": "enabledForCount",
      "alertThreshold": 500
    },
    "anchorAttribute": "mS-DS-ConsistencyGuid",
    "applicationId": "cb1056e2-e479-49de-ae31-7812af012ed8",
    "synchronizationClientVersion": "2.4.18.0",
    "synchronizationInterval": "PT30M",
    "customerRequestedSynchronizationInterval": "PT1H",
    "currentExportData": {
      "clientMachineName": "SYNC01",
      "serviceAccount": "Sync_SYNC01_abcdef@example.onmicrosoft.com",
      "pendingObjectsAddition": 1,
      "pendingObjectsDeletion": 2,
      "pendingObjectsUpdate": 3,
      "successfulLinksProvisioningCount": 4000000000,
      "successfulObjectsProvisioningCount": 5,
      "totalConnectorSpaceObjects": 6
    },
    "writebackConfiguration": {
      "unifiedGroupContainer": "OU=Groups,DC=example,DC=com",
      "userContainer": "OU=Users,DC=example,DC=com"
    }
  },
  "features": {
    "allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled": false,
    "blockCloudObjectTakeoverThroughHardMatchEnabled": true,
    "blockSoftMatchEnabled": true,
    "bypassDirSyncOverridesEnabled": false,
    "cloudPasswordPolicyForPasswordSyncedUsersEnabled": true,
    "concurrentCredentialUpdateEnabled": false,
    "concurrentOrgIdProvisioningEnabled": true,
    "deviceWritebackEnabled": false,
    "directoryExtensionsEnabled": true,
    "fopeConflictResolutionEnabled": false,
    "groupWriteBackEnabled": true,
    "passwordSyncEnabled": true,
    "passwordWritebackEnabled": false,
    "quarantineUponProxyAddressesConflictEnabled": true,
    "quarantineUponUpnConflictEnabled": false,
    "softMatchOnUpnEnabled": true,
    "synchronizeUpnForManagedUsersEnabled": false,
    "unifiedGroupWritebackEnabled": true,
    "userForcePasswordChangeOnLogonEnabled": false,
    "userWritebackEnabled": true
  }
}`

func parseOnPremisesSync(t *testing.T, payload string) betamodels.OnPremisesDirectorySynchronizationable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateOnPremisesDirectorySynchronizationFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(betamodels.OnPremisesDirectorySynchronizationable)
}

func TestOnPremisesSyncArgs_Decode(t *testing.T) {
	args, appId := onPremisesSyncArgs(parseOnPremisesSync(t, onPremisesSyncJSON), "other-tenant")

	assert.Equal(t, "cb1056e2-e479-49de-ae31-7812af012ed8", appId)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", args["id"].Value)
	assert.Equal(t, "microsoft.onPremisesSynchronization/11111111-2222-3333-4444-555555555555", args["__id"].Value)

	want := map[string]any{
		"accidentalDeletionPreventionType":         "enabledForCount",
		"accidentalDeletionAlertThreshold":         int64(500),
		"anchorAttribute":                          "mS-DS-ConsistencyGuid",
		"synchronizationClientVersion":             "2.4.18.0",
		"synchronizationInterval":                  "PT30M",
		"customerRequestedSynchronizationInterval": "PT1H",
		"exportClientMachineName":                  "SYNC01",
		"exportServiceAccount":                     "Sync_SYNC01_abcdef@example.onmicrosoft.com",
		"exportPendingObjectsAddition":             int64(1),
		"exportPendingObjectsDeletion":             int64(2),
		"exportPendingObjectsUpdate":               int64(3),
		"exportSuccessfulLinksProvisioningCount":   int64(4000000000),
		"exportSuccessfulObjectsProvisioningCount": int64(5),
		"exportTotalConnectorSpaceObjects":         int64(6),
		"unifiedGroupWritebackContainer":           "OU=Groups,DC=example,DC=com",
		"userWritebackContainer":                   "OU=Users,DC=example,DC=com",

		"allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled": false,
		"blockCloudObjectTakeoverThroughHardMatchEnabled":      true,
		"blockSoftMatchEnabled":                                true,
		"bypassDirSyncOverridesEnabled":                        false,
		"cloudPasswordPolicyForPasswordSyncedUsersEnabled":     true,
		"concurrentCredentialUpdateEnabled":                    false,
		"concurrentOrgIdProvisioningEnabled":                   true,
		"deviceWritebackEnabled":                               false,
		"directoryExtensionsEnabled":                           true,
		"fopeConflictResolutionEnabled":                        false,
		"groupWriteBackEnabled":                                true,
		"passwordSyncEnabled":                                  true,
		"passwordWritebackEnabled":                             false,
		"quarantineUponProxyAddressesConflictEnabled":          true,
		"quarantineUponUpnConflictEnabled":                     false,
		"softMatchOnUpnEnabled":                                true,
		"synchronizeUpnForManagedUsersEnabled":                 false,
		"unifiedGroupWritebackEnabled":                         true,
		"userForcePasswordChangeOnLogonEnabled":                false,
		"userWritebackEnabled":                                 true,
	}
	for field, value := range want {
		require.Contains(t, args, field)
		assert.Equal(t, value, args[field].Value, field)
	}
}

func TestOnPremisesSyncArgs_AbsentIsNull(t *testing.T) {
	// An object with neither configuration nor features must read null on
	// every field, not false or zero: nothing was read.
	args, appId := onPremisesSyncArgs(parseOnPremisesSync(t, `{"id": ""}`), "tenant-1")

	assert.Equal(t, "", appId)
	assert.Equal(t, "tenant-1", args["id"].Value)
	for field, v := range args {
		if field == "id" || field == "__id" {
			continue
		}
		assert.Nil(t, v.Value, field)
	}
}

func TestOnPremisesSyncArgs_PartialFeaturesKeepFalse(t *testing.T) {
	args, _ := onPremisesSyncArgs(parseOnPremisesSync(t, `{
	  "id": "t",
	  "configuration": {"accidentalDeletionPrevention": {"synchronizationPreventionType": "disabled"}},
	  "features": {"blockSoftMatchEnabled": false}
	}`), "t")

	assert.Equal(t, false, args["blockSoftMatchEnabled"].Value)
	assert.Nil(t, args["blockCloudObjectTakeoverThroughHardMatchEnabled"].Value)
	assert.Equal(t, "disabled", args["accidentalDeletionPreventionType"].Value)
	assert.Nil(t, args["accidentalDeletionAlertThreshold"].Value)
}

func TestSelectOnPremisesSync(t *testing.T) {
	a := parseOnPremisesSync(t, `{"id": "a"}`)
	b := parseOnPremisesSync(t, `{"id": "b"}`)

	assert.Nil(t, selectOnPremisesSync(nil, "a"))
	assert.Nil(t, selectOnPremisesSync([]betamodels.OnPremisesDirectorySynchronizationable{nil}, "a"))
	assert.Same(t, b, selectOnPremisesSync([]betamodels.OnPremisesDirectorySynchronizationable{nil, a, b}, "b"))
	assert.Same(t, a, selectOnPremisesSync([]betamodels.OnPremisesDirectorySynchronizationable{nil, a, b}, "z"))
}

func graphErrWithStatus(status int) error {
	e := betaodataerrors.NewODataError()
	e.ResponseStatusCode = status
	return fmt.Errorf("get: %w", e)
}

func TestOnPremisesSyncError(t *testing.T) {
	tenant := &mqlMicrosoftTenant{}

	err := tenant.onPremisesSynchronizationError(graphErrWithStatus(403))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	var lerr *llx.Error
	require.True(t, errors.As(err, &lerr))
	assert.Equal(t, []string{"OnPremDirectorySynchronization.Read.All"}, lerr.Permissions)

	// a transport failure or a server error is neither a refusal nor absence
	err = tenant.onPremisesSynchronizationError(errors.New("connection reset"))
	require.Error(t, err)
	assert.NotEqual(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	err = tenant.onPremisesSynchronizationError(graphErrWithStatus(500))
	require.Error(t, err)
	assert.NotEqual(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))

	// a cloud-only tenant answering 404 reads null, not an error
	assert.NoError(t, tenant.onPremisesSynchronizationError(graphErrWithStatus(404)))
	assert.True(t, tenant.OnPremisesSynchronization.IsNull())
}
