// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciKms) id() (string, error) {
	return "oci.kms", nil
}

func (o *mqlOciKms) vaults() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Vaults are almost always created in the compartment of the service they
	// encrypt, and ListVaults answers for one compartment with no way to recurse.
	// A root-only listing therefore came back empty, and every typed vault
	// reference from a database, bucket, or stream pool then had nothing to
	// resolve against.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci kms with region %s", region)

			svc, err := conn.KmsVaultClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			vaults, err := o.getVaultsForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range vaults {
				vault := vaults[i]

				var created *time.Time
				if vault.TimeCreated != nil {
					created = &vault.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.kms.vault", stringValue(vault.CompartmentId), map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(vault.Id),
					"name":               llx.StringDataPtr(vault.DisplayName),
					"vaultType":          llx.StringData(string(vault.VaultType)),
					"state":              llx.StringData(string(vault.LifecycleState)),
					"managementEndpoint": llx.StringDataPtr(vault.ManagementEndpoint),
					"created":            llx.TimeDataPtr(created),
					"freeformTags":       llx.MapData(strMapToAny(vault.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(vault.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlInstance.(*mqlOciKmsVault).cacheRegion = region
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (o *mqlOciKms) getVaultsForRegion(ctx context.Context, client *keymanagement.KmsVaultClient, compartmentID string) ([]keymanagement.VaultSummary, error) {
	entries, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]keymanagement.VaultSummary, *string, error) {
		request := keymanagement.ListVaultsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := client.ListVaults(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

type mqlOciKmsVaultInternal struct {
	ociCompartmentRef
	cacheRegion string

	// The vault's detail record, read once for the fields the listing lacks.
	detail ociRetryLazy[*keymanagement.Vault]
}

func initOciKmsVault(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.kms.vault")
	}

	obj, err := CreateResource(runtime, "oci.kms", nil)
	if err != nil {
		return nil, nil, err
	}
	kms := obj.(*mqlOciKms)

	rawVaults := kms.GetVaults()
	if rawVaults.Error != nil {
		return nil, nil, rawVaults.Error
	}

	for _, raw := range rawVaults.Data {
		vault := raw.(*mqlOciKmsVault)
		if vault.Id.Data == idVal {
			return args, vault, nil
		}
	}

	return nil, nil, errors.New("oci.kms.vault not found: " + idVal)
}

func (o *mqlOciKmsVault) id() (string, error) {
	return "oci.kms.vault/" + o.Id.Data, nil
}

func (o *mqlOciKmsVault) keys() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	managementEndpoint := o.ManagementEndpoint.Data
	if managementEndpoint == "" {
		return []any{}, nil
	}

	svc, err := conn.KmsManagementClient(managementEndpoint)
	if err != nil {
		return nil, err
	}

	keys, err := o.getKeysForVault(ctx, svc, o.cacheCompartmentID)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range keys {
		key := keys[i]

		var created *time.Time
		if key.TimeCreated != nil {
			created = &key.TimeCreated.Time
		}

		algorithm := string(key.Algorithm)

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.kms.key", stringValue(key.CompartmentId), map[string]*llx.RawData{
			"id":                    llx.StringDataPtr(key.Id),
			"name":                  llx.StringDataPtr(key.DisplayName),
			"algorithm":             llx.StringData(algorithm),
			"protectionMode":        llx.StringData(string(key.ProtectionMode)),
			"state":                 llx.StringData(string(key.LifecycleState)),
			"isAutoRotationEnabled": llx.BoolDataPtr(key.IsAutoRotationEnabled),
			"created":               llx.TimeDataPtr(created),
			"freeformTags":          llx.MapData(strMapToAny(key.FreeformTags), types.String),
			"definedTags":           llx.MapData(definedTagsToAny(key.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlKey := mqlInstance.(*mqlOciKmsKey)
		mqlKey.cacheManagementEndpoint = managementEndpoint
		mqlKey.cacheVaultID = stringValue(key.VaultId)
		res = append(res, mqlKey)
	}

	return res, nil
}

func (o *mqlOciKmsVault) getKeysForVault(ctx context.Context, client *keymanagement.KmsManagementClient, compartmentID string) ([]keymanagement.KeySummary, error) {
	entries, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]keymanagement.KeySummary, *string, error) {
		request := keymanagement.ListKeysRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := client.ListKeys(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func initOciKmsKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.kms.key")
	}

	obj, err := CreateResource(runtime, "oci.kms", nil)
	if err != nil {
		return nil, nil, err
	}
	kms := obj.(*mqlOciKms)

	rawVaults := kms.GetVaults()
	if rawVaults.Error != nil {
		return nil, nil, rawVaults.Error
	}

	for _, rawVault := range rawVaults.Data {
		vault := rawVault.(*mqlOciKmsVault)
		rawKeys := vault.GetKeys()
		if rawKeys.Error != nil {
			continue
		}
		for _, rawKey := range rawKeys.Data {
			key := rawKey.(*mqlOciKmsKey)
			if key.Id.Data == idVal {
				return args, key, nil
			}
		}
	}

	return nil, nil, errors.New("oci.kms.key not found: " + idVal)
}

type mqlOciKmsKeyInternal struct {
	ociCompartmentRef
	cacheVaultID            string
	cacheManagementEndpoint string

	keyDetailOnce sync.Once
	keyDetail     *keymanagement.Key
	keyDetailErr  error
}

func (o *mqlOciKmsKey) id() (string, error) {
	return "oci.kms.key/" + o.Id.Data, nil
}

// getKeyDetail lazily fetches the key record, which carries the shape, the
// rotation schedule, and the replication state that the ListKeys summary
// omits. The result is cached, so every field reading from it shares one
// GetKey call rather than issuing one apiece.
func (o *mqlOciKmsKey) getKeyDetail() (*keymanagement.Key, error) {
	o.keyDetailOnce.Do(func() {
		if o.cacheManagementEndpoint == "" || o.Id.Data == "" {
			return
		}
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.KmsManagementClient(o.cacheManagementEndpoint)
		if err != nil {
			o.keyDetailErr = err
			return
		}
		resp, err := svc.GetKey(context.Background(), keymanagement.GetKeyRequest{
			KeyId: common.String(o.Id.Data),
		})
		if err != nil {
			o.keyDetailErr = err
			return
		}
		key := resp.Key
		o.keyDetail = &key
	})
	return o.keyDetail, o.keyDetailErr
}

// getKeyShape reports the key's shape from the cached key record.
func (o *mqlOciKmsKey) getKeyShape() (*keymanagement.KeyShape, error) {
	key, err := o.getKeyDetail()
	if err != nil || key == nil {
		return nil, err
	}
	return key.KeyShape, nil
}

// getKeyRotation reports the key's automatic rotation schedule, or nil when it
// carries none.
func (o *mqlOciKmsKey) getKeyRotation() (*keymanagement.AutoKeyRotationDetails, error) {
	key, err := o.getKeyDetail()
	if err != nil || key == nil {
		return nil, err
	}
	return key.AutoKeyRotationDetails, nil
}

func (o *mqlOciKmsKey) length() (int64, error) {
	shape, err := o.getKeyShape()
	if err != nil {
		return 0, err
	}
	if shape == nil || shape.Length == nil {
		return 0, nil
	}
	// The SDK reports length in bytes; expose bits for legibility.
	return int64(*shape.Length) * 8, nil
}

func (o *mqlOciKmsKey) curveId() (string, error) {
	shape, err := o.getKeyShape()
	if err != nil {
		return "", err
	}
	if shape == nil {
		return "", nil
	}
	return string(shape.CurveId), nil
}

// rotationIntervalInDays reports how often the key rotates automatically.
//
// Null when the key carries no schedule: a key that never rotates has no
// interval, and reporting zero days would read as one rotating constantly.
func (o *mqlOciKmsKey) rotationIntervalInDays() (int64, error) {
	rotation, err := o.getKeyRotation()
	if err != nil {
		return 0, err
	}
	if rotation == nil || rotation.RotationIntervalInDays == nil {
		o.RotationIntervalInDays.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*rotation.RotationIntervalInDays), nil
}

// lastRotationTime reports when automatic rotation last ran, or null when it
// never has.
func (o *mqlOciKmsKey) lastRotationTime() (*time.Time, error) {
	rotation, err := o.getKeyRotation()
	if err != nil {
		return nil, err
	}
	if rotation == nil || rotation.TimeOfLastRotation == nil {
		o.LastRotationTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := rotation.TimeOfLastRotation.Time
	return &t, nil
}

// nextRotationTime reports the next estimated automatic rotation, or null when
// the key carries no schedule.
func (o *mqlOciKmsKey) nextRotationTime() (*time.Time, error) {
	rotation, err := o.getKeyRotation()
	if err != nil {
		return nil, err
	}
	if rotation == nil || rotation.TimeOfNextRotation == nil {
		o.NextRotationTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := rotation.TimeOfNextRotation.Time
	return &t, nil
}

// lastRotationStatus reports the outcome of the most recent automatic
// rotation. Empty when rotation has never run for the key.
func (o *mqlOciKmsKey) lastRotationStatus() (string, error) {
	rotation, err := o.getKeyRotation()
	if err != nil {
		return "", err
	}
	if rotation == nil {
		return "", nil
	}
	return string(rotation.LastRotationStatus), nil
}

// isPrimary reports whether the key lives in the primary vault rather than in
// a replica of it. Null when the service does not say.
func (o *mqlOciKmsKey) isPrimary() (bool, error) {
	key, err := o.getKeyDetail()
	if err != nil {
		return false, err
	}
	if key == nil || key.IsPrimary == nil {
		o.IsPrimary.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *key.IsPrimary, nil
}

// replicationId reports the replication that copied the key across regions.
// Empty when the key's material has not left the region it was created in.
func (o *mqlOciKmsKey) replicationId() (string, error) {
	key, err := o.getKeyDetail()
	if err != nil {
		return "", err
	}
	if key == nil || key.ReplicaDetails == nil {
		return "", nil
	}
	return stringValue(key.ReplicaDetails.ReplicationId), nil
}

func (o *mqlOciKmsKey) keyVersions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	if o.cacheManagementEndpoint == "" {
		return []any{}, nil
	}

	svc, err := conn.KmsManagementClient(o.cacheManagementEndpoint)
	if err != nil {
		return nil, err
	}

	versions, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]keymanagement.KeyVersionSummary, *string, error) {
		response, err := svc.ListKeyVersions(ctx, keymanagement.ListKeyVersionsRequest{
			KeyId: common.String(o.Id.Data),
			Page:  page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(versions))
	for i := range versions {
		v := versions[i]

		var created *time.Time
		if v.TimeCreated != nil {
			created = &v.TimeCreated.Time
		}
		var timeOfDeletion *time.Time
		if v.TimeOfDeletion != nil {
			timeOfDeletion = &v.TimeOfDeletion.Time
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.kms.keyVersion", stringValue(v.CompartmentId), map[string]*llx.RawData{
			"id":             llx.StringDataPtr(v.Id),
			"keyId":          llx.StringDataPtr(v.KeyId),
			"origin":         llx.StringData(string(v.Origin)),
			"state":          llx.StringData(string(v.LifecycleState)),
			"isAutoRotated":  llx.BoolDataPtr(v.IsAutoRotated),
			"created":        llx.TimeDataPtr(created),
			"timeOfDeletion": llx.TimeDataPtr(timeOfDeletion),
		})
		if err != nil {
			return nil, err
		}
		mqlInstance.(*mqlOciKmsKeyVersion).cacheVaultID = stringValue(v.VaultId)
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciKmsKeyVersion) id() (string, error) {
	return "oci.kms.keyVersion/" + o.Id.Data, nil
}
