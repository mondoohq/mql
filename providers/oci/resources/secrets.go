// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciVault) id() (string, error) {
	return "oci.vault", nil
}

func (o *mqlOciVault) secrets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Secrets sit in the compartment of the application that consumes them, and
	// ListSecrets accepts one compartment with no recursion. Asking only about
	// the tenancy root left rotation status, expiry, and auto-generation checks
	// with nothing to evaluate, which looked like a tenancy with no secrets
	// rather than a scan that never reached them.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci vault secrets with region %s", region)

			svc, err := conn.VaultsClient(region)
			if err != nil {
				return nil, err
			}

			secrets, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]vault.SecretSummary, *string, error) {
				response, err := svc.ListSecrets(ctx, vault.ListSecretsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range secrets {
				s := secrets[i]

				if conn.Filters.IsFilteredOutByTags(s.FreeformTags, s.DefinedTags) {
					continue
				}

				var created *time.Time
				if s.TimeCreated != nil {
					created = &s.TimeCreated.Time
				}
				var lastRotation *time.Time
				if s.LastRotationTime != nil {
					lastRotation = &s.LastRotationTime.Time
				}
				var nextRotation *time.Time
				if s.NextRotationTime != nil {
					nextRotation = &s.NextRotationTime.Time
				}

				replication := ociReadSecretReplication(s)

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.vault.secret", stringValue(s.CompartmentId), map[string]*llx.RawData{
					"id":                               llx.StringDataPtr(s.Id),
					"name":                             llx.StringDataPtr(s.SecretName),
					"description":                      llx.StringDataPtr(s.Description),
					"state":                            llx.StringData(string(s.LifecycleState)),
					"rotationStatus":                   llx.StringData(string(s.RotationStatus)),
					"lastRotationTime":                 llx.TimeDataPtr(lastRotation),
					"nextRotationTime":                 llx.TimeDataPtr(nextRotation),
					"isAutoGenerationEnabled":          llx.BoolDataPtr(s.IsAutoGenerationEnabled),
					"isReplica":                        llx.BoolDataPtr(s.IsReplica),
					"isReplicationWriteForwardEnabled": llx.BoolDataPtr(replication.WriteForwardEnabled),
					"sourceRegionName":                 llx.StringDataPtr(replication.SourceRegion),
					"created":                          llx.TimeDataPtr(created),
					"freeformTags":                     llx.MapData(strMapToAny(s.FreeformTags), types.String),
					"definedTags":                      llx.MapData(definedTagsToAny(s.DefinedTags), types.Any),
					"systemTags":                       llx.MapData(definedTagsToAny(s.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlS := mqlInstance.(*mqlOciVaultSecret)
				mqlS.cacheKeyID = stringValue(s.KeyId)
				mqlS.cacheVaultID = stringValue(s.VaultId)
				mqlS.cacheRegion = region
				mqlS.cacheReplicationTargets = replication.Targets
				mqlS.cacheSourceVaultID = replication.SourceVaultID
				mqlS.cacheSourceKeyID = replication.SourceKeyID
				if s.RotationConfig != nil {
					mqlS.cacheRotationInterval = stringValue(s.RotationConfig.RotationInterval)
					mqlS.cacheIsScheduledRotationEnabled = s.RotationConfig.IsScheduledRotationEnabled
				}
				if s.TimeOfCurrentVersionExpiry != nil {
					t := s.TimeOfCurrentVersionExpiry.Time
					mqlS.cacheTimeOfCurrentVersionExpiry = &t
				}
				res = append(res, mqlS)
			}

			return res, nil
		})
}

// ociSecretReplication is what a secret summary says about where its material
// has been copied to, and where it was copied from.
type ociSecretReplication struct {
	// WriteForwardEnabled stays a pointer so a secret with no replication
	// configuration reports null rather than false. "Write forwarding is off"
	// and "there is nothing to forward to" are different answers, and MQL
	// treats a fabricated false as a read one.
	WriteForwardEnabled *bool
	// SourceRegion is the full region name of the source secret, for a secret
	// that is itself a replica. Nil otherwise.
	SourceRegion  *string
	Targets       []vault.ReplicationTarget
	SourceVaultID string
	SourceKeyID   string
}

// ociReadSecretReplication reads the replication facts off a secret summary,
// leaving every one of them empty or nil when the service reported no
// replication for the secret.
func ociReadSecretReplication(s vault.SecretSummary) ociSecretReplication {
	res := ociSecretReplication{}
	if s.ReplicationConfig != nil {
		res.WriteForwardEnabled = s.ReplicationConfig.IsWriteForwardEnabled
		res.Targets = s.ReplicationConfig.ReplicationTargets
	}
	if s.SourceRegionInformation != nil {
		res.SourceRegion = s.SourceRegionInformation.SourceRegion
		res.SourceVaultID = stringValue(s.SourceRegionInformation.SourceVaultId)
		res.SourceKeyID = stringValue(s.SourceRegionInformation.SourceKeyId)
	}
	return res
}

type mqlOciVaultSecretInternal struct {
	ociCompartmentRef
	cacheKeyID   string
	cacheVaultID string
	cacheRegion  string

	// Rotation config fields from SecretSummary.RotationConfig
	cacheRotationInterval           string
	cacheIsScheduledRotationEnabled *bool
	cacheTimeOfCurrentVersionExpiry *time.Time

	// Replication fields from SecretSummary.ReplicationConfig and
	// SecretSummary.SourceRegionInformation. Held rather than turned into
	// resources at list time so the vaults and keys they name are only
	// resolved for a query that asks for them.
	cacheReplicationTargets []vault.ReplicationTarget
	cacheSourceVaultID      string
	cacheSourceKeyID        string
}

// replicationTargets reports the regions the secret's material is copied into.
//
// Each target names a vault and a key in the destination region. Those are
// resolved on read rather than here, so a query that only asks which regions
// a secret reached does not pay for the vault listings of all of them.
func (o *mqlOciVaultSecret) replicationTargets() ([]any, error) {
	res := make([]any, 0, len(o.cacheReplicationTargets))
	for i := range o.cacheReplicationTargets {
		target := o.cacheReplicationTargets[i]
		regionName := stringValue(target.TargetRegion)

		// A secret can be replicated into several regions but only once into
		// each, so the region is what makes a target unique under its secret.
		mqlTarget, err := CreateResource(o.MqlRuntime, "oci.vault.secret.replicationTarget", map[string]*llx.RawData{
			"__id":       llx.StringData(o.Id.Data + "/" + regionName),
			"regionName": llx.StringData(regionName),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlTarget.(*mqlOciVaultSecretReplicationTarget)
		typed.cacheVaultID = stringValue(target.TargetVaultId)
		typed.cacheKeyID = stringValue(target.TargetKeyId)
		res = append(res, typed)
	}
	return res, nil
}

// sourceVault resolves the vault holding the secret this replica was copied
// from. Null when the secret is not a replica.
func (o *mqlOciVaultSecret) sourceVault() (*mqlOciKmsVault, error) {
	return resolveOciVault(o.MqlRuntime, o.cacheSourceVaultID, &o.SourceVault)
}

// sourceKey resolves the key encrypting the secret this replica was copied
// from. Null when the secret is not a replica.
func (o *mqlOciVaultSecret) sourceKey() (*mqlOciKmsKey, error) {
	return resolveOciKmsKey(o.MqlRuntime, o.cacheSourceKeyID, &o.SourceKey)
}

type mqlOciVaultSecretReplicationTargetInternal struct {
	cacheVaultID string
	cacheKeyID   string
}

// region resolves the target region from its name.
func (o *mqlOciVaultSecretReplicationTarget) region() (*mqlOciRegion, error) {
	return resolveOciRegionByName(o.MqlRuntime, o.RegionName.Data, &o.Region)
}

// vault resolves the vault in the target region that holds the replica.
func (o *mqlOciVaultSecretReplicationTarget) vault() (*mqlOciKmsVault, error) {
	return resolveOciVault(o.MqlRuntime, o.cacheVaultID, &o.Vault)
}

// key resolves the key in the target region that encrypts the replica.
func (o *mqlOciVaultSecretReplicationTarget) key() (*mqlOciKmsKey, error) {
	return resolveOciKmsKey(o.MqlRuntime, o.cacheKeyID, &o.Key)
}

func (o *mqlOciVaultSecret) id() (string, error) {
	return "oci.vault.secret/" + o.Id.Data, nil
}

// initOciVaultSecret resolves a single secret from the scan asset's PlatformId
// when policies reference `oci.vault.secret` on a discovered oci-vault-secret
// asset. Explicit id takes precedence.
func initOciVaultSecret(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		conn := runtime.Connection.(*connection.OciConnection)
		if conn.Conf == nil || conn.Conf.PlatformId == "" {
			return args, nil, nil
		}
		parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId)
		if !ok || parsed.service != "vault" || parsed.objectType != "secret" {
			return args, nil, nil
		}
		idVal = parsed.id
	}

	obj, err := CreateResource(runtime, "oci.vault", nil)
	if err != nil {
		return nil, nil, err
	}
	vaultSvc := obj.(*mqlOciVault)

	secrets := vaultSvc.GetSecrets()
	if secrets.Error != nil {
		return nil, nil, secrets.Error
	}

	for _, raw := range secrets.Data {
		s := raw.(*mqlOciVaultSecret)
		if s.Id.Data == idVal {
			return args, s, nil
		}
	}

	return nil, nil, errors.New("oci.vault.secret not found: " + idVal)
}

func (o *mqlOciVaultSecret) kmsVault() (*mqlOciKmsVault, error) {
	if o.cacheVaultID == "" {
		o.KmsVault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVault, err := NewResource(o.MqlRuntime, "oci.kms.vault", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVaultID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVault.(*mqlOciKmsVault), nil
}

func (o *mqlOciVaultSecret) kmsKey() (*mqlOciKmsKey, error) {
	if o.cacheKeyID == "" {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKeyID),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlOciKmsKey), nil
}

func (o *mqlOciVaultSecret) rotationInterval() (string, error) {
	return o.cacheRotationInterval, nil
}

func (o *mqlOciVaultSecret) isScheduledRotationEnabled() (bool, error) {
	return boolValue(o.cacheIsScheduledRotationEnabled), nil
}

func (o *mqlOciVaultSecret) timeOfCurrentVersionExpiry() (*time.Time, error) {
	if o.cacheTimeOfCurrentVersionExpiry == nil {
		o.TimeOfCurrentVersionExpiry.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return o.cacheTimeOfCurrentVersionExpiry, nil
}

func (o *mqlOciVaultSecret) secretVersions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	svc, err := conn.VaultsClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	versions, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]vault.SecretVersionSummary, *string, error) {
		response, err := svc.ListSecretVersions(ctx, vault.ListSecretVersionsRequest{
			SecretId: new(o.Id.Data),
			Page:     page,
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
		var timeOfExpiry *time.Time
		if v.TimeOfExpiry != nil {
			timeOfExpiry = &v.TimeOfExpiry.Time
		}
		var timeOfDeletion *time.Time
		if v.TimeOfDeletion != nil {
			timeOfDeletion = &v.TimeOfDeletion.Time
		}

		stages := make([]any, 0, len(v.Stages))
		for _, s := range v.Stages {
			stages = append(stages, string(s))
		}

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.vault.secretVersion", map[string]*llx.RawData{
			"secretId":               llx.StringDataPtr(v.SecretId),
			"versionNumber":          llx.IntData(int64Value(v.VersionNumber)),
			"name":                   llx.StringDataPtr(v.Name),
			"contentType":            llx.StringData(string(v.ContentType)),
			"stages":                 llx.ArrayData(stages, types.String),
			"isContentAutoGenerated": llx.BoolDataPtr(v.IsContentAutoGenerated),
			"created":                llx.TimeDataPtr(created),
			"timeOfExpiry":           llx.TimeDataPtr(timeOfExpiry),
			"timeOfDeletion":         llx.TimeDataPtr(timeOfDeletion),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciVaultSecretVersion) id() (string, error) {
	return "oci.vault.secretVersion/" + o.SecretId.Data + "/" + strconv.FormatInt(o.VersionNumber.Data, 10), nil
}
