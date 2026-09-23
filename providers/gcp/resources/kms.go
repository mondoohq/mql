// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/cloud/location"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (g *mqlGcpProjectKmsService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.kmsService", projectId), nil
}

func initGcpProjectKmsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

func initGcpProjectKmsServiceKeyring(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["location"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// The keyring is matched by (name, location, projectId); without all three we
	// can't do the lookup. This has to run before the parent kmsService is built:
	// a missing projectId reaches CreateResource as a nil *llx.RawData and the
	// generated setter dereferences it, panicking before any later guard runs.
	if args["name"] == nil || args["location"] == nil || args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.kmsService.keyring requires name, location, and projectId")
	}

	// Create the parent KMS service and find the specific keyring
	obj, err := CreateResource(runtime, "gcp.project.kmsService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	kmsSvc := obj.(*mqlGcpProjectKmsService)
	keyrings := kmsSvc.GetKeyrings()
	if keyrings.Error != nil {
		return nil, nil, keyrings.Error
	}

	// Find the matching keyring
	for _, kr := range keyrings.Data {
		keyring := kr.(*mqlGcpProjectKmsServiceKeyring)
		name := keyring.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		location := keyring.GetLocation()
		if location.Error != nil {
			return nil, nil, location.Error
		}
		projectId := keyring.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if name.Data == args["name"].Value && location.Data == args["location"].Value && projectId.Data == args["projectId"].Value {
			return args, keyring, nil
		}
	}

	return nil, nil, errors.New("KMS keyring not found")
}

type mqlGcpProjectKmsServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) kms() (*mqlGcpProjectKmsService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.kmsService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_kms)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectKmsService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_kms).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func (g *mqlGcpProjectKmsServiceKeyring) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

func (g *mqlGcpProjectKmsServiceKeyring) project() (*mqlGcpProject, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	proj, err := projectRefById(g.MqlRuntime, g.ProjectId.Data)
	if err != nil {
		return nil, err
	}
	if proj == nil {
		g.Project.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return proj, nil
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokey) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func initGcpProjectKmsServiceKeyringCryptokey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	resourcePathRaw, ok := args["resourcePath"]
	if !ok || resourcePathRaw == nil {
		return nil, nil, errors.New(`gcp.project.kmsService.keyring.cryptokey requires a "resourcePath" argument`)
	}
	resourcePath, ok := resourcePathRaw.Value.(string)
	if !ok || resourcePath == "" {
		return nil, nil, errors.New(`gcp.project.kmsService.keyring.cryptokey requires a non-empty "resourcePath" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}
	defer kmsSvc.Close()

	k, err := kmsSvc.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: resourcePath})
	if err != nil {
		return nil, nil, err
	}

	var mqlPrimary plugin.Resource
	if k.Primary != nil {
		mqlPrimary, err = cryptoKeyVersionToMql(runtime, k.Primary)
		if err != nil {
			return nil, nil, err
		}
	}

	type mqlVersionTemplate struct {
		ProtectionLevel string `json:"protectionLevel"`
		Algorithm       string `json:"algorithm"`
	}

	var versionTemplate map[string]any
	if k.VersionTemplate != nil {
		versionTemplate, err = convert.JsonToDict(mqlVersionTemplate{
			ProtectionLevel: k.VersionTemplate.ProtectionLevel.String(),
			Algorithm:       k.VersionTemplate.Algorithm.String(),
		})
		if err != nil {
			return nil, nil, err
		}
	}

	var mqlRotationPeriod *time.Time
	rotationPeriod := k.GetRotationPeriod()
	if rotationPeriod != nil {
		v := llx.DurationToTime(rotationPeriod.Seconds)
		mqlRotationPeriod = &v
	}

	var mqlDestroyScheduledDuration *time.Time
	if k.DestroyScheduledDuration != nil {
		v := llx.DurationToTime(k.DestroyScheduledDuration.Seconds)
		mqlDestroyScheduledDuration = &v
	}

	var primaryState string
	if k.Primary != nil {
		primaryState = k.Primary.State.String()
	}

	args["resourcePath"] = llx.StringData(k.Name)
	args["name"] = llx.StringData(parseResourceName(k.Name))
	args["primary"] = llx.ResourceData(mqlPrimary, "gcp.project.kmsService.keyring.cryptokey.version")
	args["primaryState"] = llx.StringData(primaryState)
	args["purpose"] = llx.StringData(k.Purpose.String())
	args["created"] = llx.TimeDataPtr(timestampAsTimePtr(k.CreateTime))
	args["nextRotation"] = llx.TimeDataPtr(timestampAsTimePtr(k.NextRotationTime))
	args["rotationPeriod"] = llx.TimeDataPtr(mqlRotationPeriod)
	args["versionTemplate"] = llx.DictData(versionTemplate)
	args["labels"] = llx.MapData(convert.MapToInterfaceMap(k.Labels), types.String)
	args["importOnly"] = llx.BoolData(k.ImportOnly)
	args["destroyScheduledDuration"] = llx.TimeDataPtr(mqlDestroyScheduledDuration)
	args["cryptoKeyBackend"] = llx.StringData(k.CryptoKeyBackend)

	return args, nil, nil
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokey) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokeyVersion) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokeyVersionAttestation) id() (string, error) {
	if g.CryptoKeyVersionName.Error != nil {
		return "", g.CryptoKeyVersionName.Error
	}
	name := g.CryptoKeyVersionName.Data
	return fmt.Sprintf("%s/attestation", name), nil
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokeyVersionExternalProtectionLevelOptions) id() (string, error) {
	if g.CryptoKeyVersionName.Error != nil {
		return "", g.CryptoKeyVersionName.Error
	}
	name := g.CryptoKeyVersionName.Data
	return fmt.Sprintf("%s/externalProtectionLevelOptions", name), nil
}

type mqlGcpProjectKmsServiceKeyringCryptokeyVersionExternalProtectionLevelOptionsInternal struct {
	cacheEkmConnectionBackendOverride string
}

// ekmConnectionBackendOverride resolves the version's EKM connection override
// (projects/*/locations/*/ekmConnections/*) against the owning project's EKM
// connection list.
func (g *mqlGcpProjectKmsServiceKeyringCryptokeyVersionExternalProtectionLevelOptions) ekmConnectionBackendOverride() (*mqlGcpProjectKmsServiceEkmConnection, error) {
	path := g.cacheEkmConnectionBackendOverride
	if path == "" {
		g.EkmConnectionBackendOverride.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	projectId := parseProjectFromPath(path)
	if projectId == "" {
		return nil, fmt.Errorf("invalid EKM connection resource name %q", path)
	}
	svc, err := NewResource(g.MqlRuntime, "gcp.project.kmsService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	conns := svc.(*mqlGcpProjectKmsService).GetEkmConnections()
	if conns.Error != nil {
		return nil, conns.Error
	}
	if ec := ekmConnectionByResourcePath(conns.Data, path); ec != nil {
		return ec, nil
	}
	return nil, fmt.Errorf("gcp.project.kmsService.ekmConnection %q not found", path)
}

// ekmConnectionByResourcePath returns the EKM connection whose full resource
// path equals path, or nil when none matches.
func ekmConnectionByResourcePath(conns []any, path string) *mqlGcpProjectKmsServiceEkmConnection {
	for _, c := range conns {
		ec, ok := c.(*mqlGcpProjectKmsServiceEkmConnection)
		if !ok {
			continue
		}
		if ec.ResourcePath.Data == path {
			return ec
		}
	}
	return nil
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokeyVersionAttestationCertificatechains) id() (string, error) {
	if g.CryptoKeyVersionName.Error != nil {
		return "", g.CryptoKeyVersionName.Error
	}
	name := g.CryptoKeyVersionName.Data
	return fmt.Sprintf("%s/attestation/certchains", name), nil
}

func (g *mqlGcpProjectKmsService) locations() ([]any, error) {
	enabled, err := g.isEnabled()
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

	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer kmsSvc.Close()

	var locations []any
	it := kmsSvc.ListLocations(ctx, &location.ListLocationsRequest{Name: fmt.Sprintf("projects/%s", projectId)})
	for {
		l, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		locations = append(locations, l.LocationId)
	}
	return locations, nil
}

func (g *mqlGcpProjectKmsService) keyrings() ([]any, error) {
	enabled, err := g.isEnabled()
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

	locations := g.GetLocations()
	if locations.Error != nil {
		return nil, locations.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer kmsSvc.Close()

	var keyrings []any
	var wg sync.WaitGroup
	wg.Add(len(locations.Data))
	mux := &sync.Mutex{}

	for _, location := range locations.Data {
		go func(svc *kms.KeyManagementClient, project string, location string) {
			defer wg.Done()
			it := kmsSvc.ListKeyRings(ctx,
				&kmspb.ListKeyRingsRequest{Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, location)})
			for {
				k, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					log.Error().Err(err).Str("location", location).Msg("could not list kms keyrings")
					return
				}

				created := k.CreateTime.AsTime()
				mqlKeyring, err := CreateResource(g.MqlRuntime, "gcp.project.kmsService.keyring", map[string]*llx.RawData{
					"projectId":    llx.StringData(projectId),
					"resourcePath": llx.StringData(k.Name),
					"name":         llx.StringData(parseResourceName(k.Name)),
					"created":      llx.TimeData(created),
					"location":     llx.StringData(location),
				})
				if err != nil {
					log.Error().Err(err).Str("location", location).Msg("could not create kms keyring resource")
					return
				}
				mux.Lock()
				keyrings = append(keyrings, mqlKeyring)
				mux.Unlock()
			}
		}(kmsSvc, projectId, location.(string))
	}
	wg.Wait()
	return keyrings, nil
}

func (g *mqlGcpProjectKmsServiceKeyring) cryptokeys() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	keyring := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer kmsSvc.Close()

	var keys []any

	it := kmsSvc.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{
		Parent: keyring,
	})

	type mqlVersionTemplate struct {
		ProtectionLevel string `json:"protectionLevel"`
		Algorithm       string `json:"algorithm"`
	}
	for {
		k, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var mqlPrimary plugin.Resource
		if k.Primary != nil {
			mqlPrimary, err = cryptoKeyVersionToMql(g.MqlRuntime, k.Primary)
			if err != nil {
				return nil, err
			}
		}

		var versionTemplate map[string]any
		if k.VersionTemplate != nil {
			versionTemplate, err = convert.JsonToDict(mqlVersionTemplate{
				ProtectionLevel: k.VersionTemplate.ProtectionLevel.String(),
				Algorithm:       k.VersionTemplate.Algorithm.String(),
			})
			if err != nil {
				return nil, err
			}
		}

		var mqlRotationPeriod *time.Time
		rotationPeriod := k.GetRotationPeriod()
		if rotationPeriod != nil {
			v := llx.DurationToTime(rotationPeriod.Seconds)
			mqlRotationPeriod = &v
		}

		var mqlDestroyScheduledDuration *time.Time
		if k.DestroyScheduledDuration != nil {
			v := llx.DurationToTime(k.DestroyScheduledDuration.Seconds)
			mqlDestroyScheduledDuration = &v
		}

		kajpDict, err := protoToDict(k.KeyAccessJustificationsPolicy)
		if err != nil {
			return nil, err
		}
		var primaryState string
		if k.Primary != nil {
			primaryState = k.Primary.State.String()
		}
		mqlKey, err := CreateResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey", map[string]*llx.RawData{
			"resourcePath":                  llx.StringData(k.Name),
			"name":                          llx.StringData(parseResourceName(k.Name)),
			"primary":                       llx.ResourceData(mqlPrimary, "gcp.project.kmsService.keyring.cryptokey.version"),
			"primaryState":                  llx.StringData(primaryState),
			"purpose":                       llx.StringData(k.Purpose.String()),
			"created":                       llx.TimeDataPtr(timestampAsTimePtr(k.CreateTime)),
			"nextRotation":                  llx.TimeDataPtr(timestampAsTimePtr(k.NextRotationTime)),
			"rotationPeriod":                llx.TimeDataPtr(mqlRotationPeriod),
			"versionTemplate":               llx.DictData(versionTemplate),
			"labels":                        llx.MapData(convert.MapToInterfaceMap(k.Labels), types.String),
			"importOnly":                    llx.BoolData(k.ImportOnly),
			"destroyScheduledDuration":      llx.TimeDataPtr(mqlDestroyScheduledDuration),
			"cryptoKeyBackend":              llx.StringData(k.CryptoKeyBackend),
			"keyAccessJustificationsPolicy": llx.DictData(kajpDict),
		})
		if err != nil {
			return nil, err
		}

		keys = append(keys, mqlKey)
	}
	return keys, nil
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokey) versions() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	cryptokey := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer kmsSvc.Close()

	var versions []any

	it := kmsSvc.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: cryptokey,
	})

	for {
		v, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		mqlVersion, err := cryptoKeyVersionToMql(g.MqlRuntime, v)
		if err != nil {
			return nil, err
		}
		versions = append(versions, mqlVersion)
	}
	return versions, nil
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokey) rotationEnabled() (bool, error) {
	v := g.GetRotationPeriod()
	if v.Error != nil {
		return false, v.Error
	}
	return v.Data != nil, nil
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokey) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectKmsServiceKeyringCryptokey) iamPolicy() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	cryptokey := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer kmsSvc.Close()

	// Request policy schema version 3 so conditional bindings aren't silently
	// stripped from the result.
	policy, err := kmsSvc.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: cryptokey,
		Options:  &iampb.GetPolicyOptions{RequestedPolicyVersion: 3},
	})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			return nil, nil
		}
		return nil, err
	}
	return iampbBindingsToMql(g.MqlRuntime, cryptokey, policy.Bindings)
}

// newKmsCryptoKeyRef returns a typed gcp.project.kmsService.keyring.cryptokey
// reference for the given Cloud KMS key resource name, or a null-set reference
// when the name is empty. Centralizes the kmsKey() accessor pattern used across
// the provider to resolve a customer-managed key from its resource name.
func newKmsCryptoKeyRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectKmsServiceKeyringCryptokey], keyName string) (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if keyName == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(keyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectKmsServiceKeyring) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectKmsServiceKeyring) iamPolicy() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	keyring := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer kmsSvc.Close()

	// Request policy schema version 3 so conditional bindings (e.g. a
	// condition-scoped allUsers grant) aren't silently stripped from the result.
	policy, err := kmsSvc.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: keyring,
		Options:  &iampb.GetPolicyOptions{RequestedPolicyVersion: 3},
	})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			return nil, nil
		}
		return nil, err
	}
	return iampbBindingsToMql(g.MqlRuntime, keyring, policy.Bindings)
}

func cryptoKeyVersionToMql(runtime *plugin.Runtime, v *kmspb.CryptoKeyVersion) (plugin.Resource, error) {
	var mqlAttestation plugin.Resource
	if v.Attestation != nil {
		mqlAttestationCertChains, err := CreateResource(runtime, "gcp.project.kmsService.keyring.cryptokey.version.attestation.certificatechains", map[string]*llx.RawData{
			"cryptoKeyVersionName": llx.StringData(v.Name),
			"caviumCerts":          llx.ArrayData(convert.SliceAnyToInterface(v.Attestation.GetCertChains().GetCaviumCerts()), types.String),
			"googleCardCerts":      llx.ArrayData(convert.SliceAnyToInterface(v.Attestation.GetCertChains().GetGoogleCardCerts()), types.String),
			"googlePartitionCerts": llx.ArrayData(convert.SliceAnyToInterface(v.Attestation.GetCertChains().GetGooglePartitionCerts()), types.String),
		})
		if err != nil {
			return nil, err
		}

		mqlAttestation, err = CreateResource(runtime, "gcp.project.kmsService.keyring.cryptokey.version.attestation", map[string]*llx.RawData{
			"cryptoKeyVersionName": llx.StringData(v.Name),
			"format":               llx.StringData(v.Attestation.Format.String()),
			"certificateChains":    llx.ResourceData(mqlAttestationCertChains, "gcp.project.kmsService.keyring.cryptokey.version.attestation.certificatechains"),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlExtProtOpts plugin.Resource
	var err error
	if v.ExternalProtectionLevelOptions != nil {
		mqlExtProtOpts, err = CreateResource(runtime, "gcp.project.kmsService.keyring.cryptokey.version.externalProtectionLevelOptions", map[string]*llx.RawData{
			"cryptoKeyVersionName": llx.StringData(v.Name),
			"externalKeyUri":       llx.StringData(v.ExternalProtectionLevelOptions.ExternalKeyUri),
			"ekmConnectionKeyPath": llx.StringData(v.ExternalProtectionLevelOptions.EkmConnectionKeyPath),
		})
		if err != nil {
			return nil, err
		}
		mqlExtProtOpts.(*mqlGcpProjectKmsServiceKeyringCryptokeyVersionExternalProtectionLevelOptions).cacheEkmConnectionBackendOverride = v.ExternalProtectionLevelOptions.EkmConnectionBackendOverride
	}
	return CreateResource(runtime, "gcp.project.kmsService.keyring.cryptokey.version", map[string]*llx.RawData{
		"resourcePath":                     llx.StringData(v.Name),
		"name":                             llx.StringData(parseResourceName(v.Name)),
		"state":                            llx.StringData(v.State.String()),
		"protectionLevel":                  llx.StringData(v.ProtectionLevel.String()),
		"algorithm":                        llx.StringData(v.Algorithm.String()),
		"attestation":                      llx.ResourceData(mqlAttestation, "gcp.project.kmsService.keyring.cryptokey.version.attestation"),
		"created":                          llx.TimeDataPtr(timestampAsTimePtr(v.CreateTime)),
		"generated":                        llx.TimeDataPtr(timestampAsTimePtr(v.GenerateTime)),
		"destroyed":                        llx.TimeDataPtr(timestampAsTimePtr(v.DestroyTime)),
		"destroyEventTime":                 llx.TimeDataPtr(timestampAsTimePtr(v.DestroyEventTime)),
		"importJob":                        llx.StringData(v.ImportJob),
		"importTime":                       llx.TimeDataPtr(timestampAsTimePtr(v.ImportTime)),
		"importFailureReason":              llx.StringData(v.ImportFailureReason),
		"generationFailureReason":          llx.StringData(v.GenerationFailureReason),
		"externalDestructionFailureReason": llx.StringData(v.ExternalDestructionFailureReason),
		"externalProtectionLevelOptions":   llx.ResourceData(mqlExtProtOpts, "gcp.project.kmsService.keyring.cryptokey.version.externalProtectionLevelOptions"),
		"reimportEligible":                 llx.BoolData(v.ReimportEligible),
		"trustedWrappingEnabled":           llx.BoolData(v.TrustedWrappingEnabled),
		"hsmTrusted":                       llx.BoolData(v.HsmTrusted),
	})
}

func (g *mqlGcpProjectKmsServiceRetiredResource) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectKmsService) retiredResources() ([]any, error) {
	enabled, err := g.isEnabled()
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

	locations := g.GetLocations()
	if locations.Error != nil {
		return nil, locations.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer kmsSvc.Close()

	var res []any
	for _, loc := range locations.Data {
		locStr, ok := loc.(string)
		if !ok {
			continue
		}
		it := kmsSvc.ListRetiredResources(ctx, &kmspb.ListRetiredResourcesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, locStr),
		})
		for {
			rr, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Warn().Str("location", locStr).Err(err).Msg("could not list retired KMS resources")
				break
			}

			mqlRR, err := CreateResource(g.MqlRuntime, "gcp.project.kmsService.retiredResource", map[string]*llx.RawData{
				"name":             llx.StringData(rr.Name),
				"originalResource": llx.StringData(rr.OriginalResource),
				"resourceType":     llx.StringData(rr.ResourceType),
				"deleteTime":       llx.TimeDataPtr(timestampAsTimePtr(rr.DeleteTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRR)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectKmsServiceEkmConnection) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

func (g *mqlGcpProjectKmsService) ekmConnections() ([]any, error) {
	enabled, err := g.isEnabled()
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

	locations := g.GetLocations()
	if locations.Error != nil {
		return nil, locations.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	ekmSvc, err := kms.NewEkmClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer ekmSvc.Close()

	var res []any
	var mux sync.Mutex
	var wg sync.WaitGroup
	wg.Add(len(locations.Data))

	for _, loc := range locations.Data {
		go func(locStr string) {
			defer wg.Done()
			it := ekmSvc.ListEkmConnections(ctx, &kmspb.ListEkmConnectionsRequest{
				Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, locStr),
			})
			for {
				ec, err := it.Next()
				if err == iterator.Done {
					return
				}
				if err != nil {
					log.Warn().Str("location", locStr).Err(err).Msg("could not list EKM connections")
					return
				}

				resolvers := make([]any, 0, len(ec.ServiceResolvers))
				for _, sr := range ec.ServiceResolvers {
					d, err := protoToDict(sr)
					if err != nil {
						log.Warn().Err(err).Msg("could not convert EKM service resolver")
						continue
					}
					resolvers = append(resolvers, d)
				}

				mqlEc, err := CreateResource(g.MqlRuntime, "gcp.project.kmsService.ekmConnection", map[string]*llx.RawData{
					"projectId":         llx.StringData(projectId),
					"resourcePath":      llx.StringData(ec.Name),
					"name":              llx.StringData(parseResourceName(ec.Name)),
					"location":          llx.StringData(locStr),
					"created":           llx.TimeDataPtr(timestampAsTimePtr(ec.CreateTime)),
					"etag":              llx.StringData(ec.Etag),
					"keyManagementMode": llx.StringData(ec.KeyManagementMode.String()),
					"cryptoSpacePath":   llx.StringData(ec.CryptoSpacePath),
					"serviceResolvers":  llx.ArrayData(resolvers, types.Dict),
				})
				if err != nil {
					log.Warn().Err(err).Msg("could not create EKM connection resource")
					return
				}
				mux.Lock()
				res = append(res, mqlEc)
				mux.Unlock()
			}
		}(loc.(string))
	}
	wg.Wait()
	return res, nil
}

func (g *mqlGcpProjectKmsServiceKeyringImportJob) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

func (g *mqlGcpProjectKmsServiceKeyring) importJobs() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	keyringPath := g.ResourcePath.Data

	projectId := g.ProjectId.Data
	location := g.Location.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(kms.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	kmsSvc, err := kms.NewKeyManagementClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer kmsSvc.Close()

	var res []any
	it := kmsSvc.ListImportJobs(ctx, &kmspb.ListImportJobsRequest{Parent: keyringPath})
	for {
		ij, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var attestation map[string]any
		if ij.Attestation != nil {
			attestation, err = protoToDict(ij.Attestation)
			if err != nil {
				return nil, err
			}
		}

		mqlIj, err := CreateResource(g.MqlRuntime, "gcp.project.kmsService.keyring.importJob", map[string]*llx.RawData{
			"projectId":        llx.StringData(projectId),
			"resourcePath":     llx.StringData(ij.Name),
			"name":             llx.StringData(parseResourceName(ij.Name)),
			"location":         llx.StringData(location),
			"importMethod":     llx.StringData(ij.ImportMethod.String()),
			"protectionLevel":  llx.StringData(ij.ProtectionLevel.String()),
			"state":            llx.StringData(ij.State.String()),
			"created":          llx.TimeDataPtr(timestampAsTimePtr(ij.CreateTime)),
			"generated":        llx.TimeDataPtr(timestampAsTimePtr(ij.GenerateTime)),
			"expireTime":       llx.TimeDataPtr(timestampAsTimePtr(ij.ExpireTime)),
			"expireEventTime":  llx.TimeDataPtr(timestampAsTimePtr(ij.ExpireEventTime)),
			"attestation":      llx.DictData(attestation),
			"cryptoKeyBackend": llx.StringData(ij.CryptoKeyBackend),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIj)
	}
	return res, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectKmsService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_kms)
}
