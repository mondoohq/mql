// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"
	"sync/atomic"

	iaas "github.com/stackitcloud/stackit-sdk-go/services/iaas/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ------------------------- servers -------------------------

func (r *mqlStackit) servers() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	// Details(true) so the response includes nics, security groups, and volumes;
	// without it the API returns servers with those fields empty.
	resp, err := client.DefaultAPI.ListServers(bgctx(), c.ProjectID(), c.Region()).Details(true).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildServer(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// mqlStackitServerInternal caches data the server GET returns inline that is no
// longer exposed as schema fields: the service-account mail addresses that
// serviceAccounts() resolves into typed references, and the per-interface
// summaries that securityGroups() and exposure() read. Keeping the summaries
// here avoids a ListServerNICs call per server just to answer those two.
type mqlStackitServerInternal struct {
	cacheServiceAccountMails []string
	cacheNics                []any
	// cacheBootVolumeID is the volume the server boots from, resolved by
	// bootVolume(). Empty when the server boots straight from an image.
	cacheBootVolumeID string
}

// bootVolume resolves the volume that holds the server's root disk, so a
// check can ask about the OS disk specifically (its encryption key, its
// image, whether it is a clone) rather than about the undifferentiated set
// in volumes. Null when the server boots straight from an image, or when
// the volume no longer exists.
func (r *mqlStackitServer) bootVolume() (*mqlStackitVolume, error) {
	return refByKey(r.MqlRuntime, "stackit.volume", "id", r.cacheBootVolumeID, &r.BootVolume)
}

// serverAgentProvisioned reports whether the STACKIT server agent is
// provisioned on the server, or nil when the API says nothing about it.
//
// The agent is the precondition for the Server Backup and Server Update
// services: without it neither collects anything, so an empty backups() or
// updates() describes the server rather than the backup configuration. The
// API omits the setting when provisioning follows the boot image's own
// default, and that outcome is not readable from the server object. Nil there
// keeps "the agent is off" apart from "we cannot tell" instead of folding
// both into a false the API never reported.
func serverAgentProvisioned(s *iaas.Server) *bool {
	if s == nil {
		return nil
	}
	agent, ok := s.GetAgentOk()
	if !ok || agent == nil {
		return nil
	}
	provisioned, ok := agent.GetProvisionedOk()
	if !ok {
		return nil
	}
	return provisioned
}

// serverBootVolumeDeleteOnTermination reports whether the boot volume is
// deleted along with the server, or nil when the server has no boot volume or
// the API reports no setting for it.
//
// A server booted straight from an image carries no boot volume at all and the
// question does not apply to it. Both that case and an unreported setting
// yield nil rather than false, so a server whose disk retention is unknown
// does not read as one that keeps its disk.
func serverBootVolumeDeleteOnTermination(s *iaas.Server) *bool {
	if s == nil {
		return nil
	}
	boot, ok := s.GetBootVolumeOk()
	if !ok || boot == nil {
		return nil
	}
	deleteOnTermination, ok := boot.GetDeleteOnTerminationOk()
	if !ok {
		return nil
	}
	return deleteOnTermination
}

func buildServer(runtime *plugin.Runtime, s *iaas.Server) (plugin.Resource, error) {
	nics := []any{}
	if v, ok := s.GetNicsOk(); ok {
		for _, n := range v {
			allowed := []any{}
			for _, a := range n.GetAllowedAddresses() {
				if a.String != nil {
					allowed = append(allowed, *a.String)
				}
			}
			nics = append(nics, map[string]any{
				"nicId":            n.GetNicId(),
				"networkId":        n.GetNetworkId(),
				"networkName":      n.GetNetworkName(),
				"ipv4":             n.GetIpv4(),
				"ipv6":             n.GetIpv6(),
				"mac":              n.GetMac(),
				"securityGroups":   strSlice(n.GetSecurityGroups()),
				"allowedAddresses": allowed,
				"publicIp":         n.GetPublicIp(),
				"nicSecurity":      n.GetNicSecurity(),
			})
		}
	}

	createdAt, ok1 := s.GetCreatedAtOk()
	launchedAt, ok2 := s.GetLaunchedAtOk()
	updatedAt, ok3 := s.GetUpdatedAtOk()

	args := map[string]*llx.RawData{
		"id":               llx.StringData(s.GetId()),
		"name":             llx.StringData(s.GetName()),
		"status":           llx.StringData(s.GetStatus()),
		"powerStatus":      llx.StringData(s.GetPowerStatus()),
		"machineType":      llx.StringData(s.GetMachineType()),
		"availabilityZone": llx.StringData(s.GetAvailabilityZone()),
		"createdAt":        llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
		"launchedAt":       llx.TimeDataPtr(timeOrNil(launchedAt, ok2)),
		"updatedAt":        llx.TimeDataPtr(timeOrNil(updatedAt, ok3)),
		"errorMessage":     llx.StringData(s.GetErrorMessage()),
		"configDrive":      llx.BoolData(s.GetConfigDrive()),
		"keypairName":      llx.StringData(s.GetKeypairName()),
		"imageId":          llx.StringData(s.GetImageId()),
		"volumeIds":        strSliceData(s.GetVolumes()),
		"securityGroupIds": strSliceData(s.GetSecurityGroups()),
		"agentProvisioned": llx.BoolDataPtr(serverAgentProvisioned(s)),
		"bootVolumeDeleteOnTermination": llx.BoolDataPtr(
			serverBootVolumeDeleteOnTermination(s)),
		"userData": llx.StringData(string(s.GetUserData())),
		"labels":   labelData(s.GetLabels()),
		"metadata": metadataData(s.GetMetadata()),
	}
	res, err := CreateResource(runtime, "stackit.server", args)
	if err != nil {
		return nil, err
	}
	mqlServer := res.(*mqlStackitServer)
	if boot, ok := s.GetBootVolumeOk(); ok && boot != nil {
		mqlServer.cacheBootVolumeID = boot.GetId()
	}
	mqlServer.cacheServiceAccountMails = s.GetServiceAccountMails()
	mqlServer.cacheNics = nics
	return res, nil
}

func (r *mqlStackitServer) id() (string, error) {
	return "stackit.server/" + r.Id.Data, nil
}

func initStackitServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		id, ok = conn(runtime).AssetObjectID("compute")
	}
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.IaaS()
	if err != nil {
		return nil, nil, err
	}
	s, err := client.DefaultAPI.GetServer(bgctx(), c.ProjectID(), c.Region(), id).Details(true).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildServer(runtime, s)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlStackitServer) image() (*mqlStackitImage, error) {
	return refByKey(r.MqlRuntime, "stackit.image", "id", r.ImageId.Data, &r.Image)
}

func (r *mqlStackitServer) keyPair() (*mqlStackitKeyPair, error) {
	return refByKey(r.MqlRuntime, "stackit.keyPair", "name", r.KeypairName.Data, &r.KeyPair)
}

func (r *mqlStackitServer) volumes() ([]any, error) {
	ids := make([]string, 0, len(r.VolumeIds.Data))
	for _, raw := range r.VolumeIds.Data {
		if id, ok := raw.(string); ok {
			ids = append(ids, id)
		}
	}
	return volumeRefs(r.MqlRuntime, ids)
}

func (r *mqlStackitServer) securityGroups() ([]any, error) {
	// Collect security-group ids from the server-level list and, since STACKIT
	// attaches security groups per network interface (the server-level list is
	// usually empty), from each NIC as well. Deduplicate while preserving order.
	seen := map[string]struct{}{}
	ids := []string{}
	add := func(id string) {
		if id == "" {
			return
		}
		if _, dup := seen[id]; dup {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	for _, raw := range r.SecurityGroupIds.Data {
		if id, ok := raw.(string); ok {
			add(id)
		}
	}
	for _, raw := range r.cacheNics {
		nic, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		sgs, ok := nic["securityGroups"].([]any)
		if !ok {
			continue
		}
		for _, s := range sgs {
			if id, ok := s.(string); ok {
				add(id)
			}
		}
	}

	out := make([]any, 0, len(ids))
	for _, id := range ids {
		sg, err := NewResource(r.MqlRuntime, "stackit.securityGroup", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, sg)
	}
	return out, nil
}

// serviceAccounts resolves the service accounts attached to the server from
// the mail addresses carried on the server object.
func (r *mqlStackitServer) serviceAccounts() ([]any, error) {
	out := make([]any, 0, len(r.cacheServiceAccountMails))
	for _, mail := range r.cacheServiceAccountMails {
		if mail == "" {
			continue
		}
		sa, err := NewResource(r.MqlRuntime, "stackit.serviceAccount", map[string]*llx.RawData{
			"email": llx.StringData(mail),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	return out, nil
}

// ------------------------- volumes -------------------------

func (r *mqlStackit) volumes() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListVolumes(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildVolume(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// classifyVolumeSource maps a volume's source type onto the correct
// typed-reference field. VolumeSource.Type is one of image, volume, snapshot,
// or backup. Snapshots and backups are distinct STACKIT resources, so their
// UUIDs must not be conflated: a backup UUID surfaced as sourceSnapshotId would
// resolve against the snapshot API and 404. A "volume" source is a clone of
// another volume; an unknown type yields all-empty IDs.
func classifyVolumeSource(sourceType, sourceID string) (imageID, snapshotID, backupID, volumeID string) {
	switch sourceType {
	case "image":
		imageID = sourceID
	case "snapshot":
		snapshotID = sourceID
	case "backup":
		backupID = sourceID
	case "volume":
		volumeID = sourceID
	}
	return
}

type mqlStackitVolumeInternal struct {
	// cacheSourceVolumeID is the volume this one was cloned from, resolved by
	// sourceVolume(). Held internally rather than as a raw id field.
	cacheSourceVolumeID string
	// cacheEncryption is the customer-managed-key reference the volume
	// carries, resolved by the encryptionKey* accessors.
	cacheEncryption volumeEncryption
}

// volumeEncryption is the customer-managed key-encryption-key reference on a
// volume: which KMS key and version wrap the data-encryption key, the ring
// that holds the key, the project that owns it (empty when the API leaves it
// out, meaning the volume's own project), and the service account the
// platform uses to unwrap with it.
type volumeEncryption struct {
	keyID          string
	keyVersion     int64
	keyRingID      string
	projectID      string
	serviceAccount string
}

// volumeEncryptionOf extracts the key-encryption-key reference from a volume.
// The whole block is absent on a platform-managed volume, and every field
// reads empty then.
func volumeEncryptionOf(v *iaas.Volume) volumeEncryption {
	var enc volumeEncryption
	if v == nil {
		return enc
	}
	ep, ok := v.GetEncryptionParametersOk()
	if !ok || ep == nil {
		return enc
	}
	enc.keyID = ep.GetKekKeyId()
	enc.keyVersion = ep.GetKekKeyVersion()
	enc.keyRingID = ep.GetKekKeyringId()
	enc.serviceAccount = ep.GetServiceAccount()
	if p, ok := ep.GetKekProjectIdOk(); ok && p != nil {
		enc.projectID = *p
	}
	return enc
}

// crossProject reports whether the key lives in a project other than the
// one this connection reads, in which case neither the ring nor the service
// account can be resolved here.
func (e volumeEncryption) crossProject(ownProjectID string) bool {
	return e.projectID != "" && e.projectID != ownProjectID
}

func buildVolume(runtime *plugin.Runtime, v *iaas.Volume) (plugin.Resource, error) {
	var imageID, snapshotID, backupID, sourceVolumeID string
	if src, ok := v.GetSourceOk(); ok {
		imageID, snapshotID, backupID, sourceVolumeID = classifyVolumeSource(src.GetType(), src.GetId())
	}
	serverID := v.GetServerId()
	enc := volumeEncryptionOf(v)
	kekKeyID := enc.keyID
	kekKeyVersion := enc.keyVersion

	createdAt, ok1 := v.GetCreatedAtOk()
	updatedAt, ok2 := v.GetUpdatedAtOk()

	args := map[string]*llx.RawData{
		"id":                     llx.StringData(v.GetId()),
		"name":                   llx.StringData(v.GetName()),
		"description":            llx.StringData(v.GetDescription()),
		"size":                   llx.IntData(int64(v.GetSize())),
		"status":                 llx.StringData(v.GetStatus()),
		"availabilityZone":       llx.StringData(v.GetAvailabilityZone()),
		"performanceClass":       llx.StringData(v.GetPerformanceClass()),
		"bootable":               llx.BoolData(v.GetBootable()),
		"imageId":                llx.StringData(imageID),
		"sourceSnapshotId":       llx.StringData(snapshotID),
		"sourceBackupId":         llx.StringData(backupID),
		"serverId":               llx.StringData(serverID),
		"encrypted":              llx.BoolData(v.GetEncrypted()),
		"encryptionKeyId":        llx.StringData(kekKeyID),
		"encryptionKeyVersion":   llx.IntData(kekKeyVersion),
		"createdAt":              llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
		"updatedAt":              llx.TimeDataPtr(timeOrNil(updatedAt, ok2)),
		"labels":                 labelData(v.GetLabels()),
		"encryptionKeyProjectId": llx.StringData(enc.projectID),
	}
	res, err := CreateResource(runtime, "stackit.volume", args)
	if err != nil {
		return nil, err
	}
	mqlVolume := res.(*mqlStackitVolume)
	mqlVolume.cacheSourceVolumeID = sourceVolumeID
	mqlVolume.cacheEncryption = enc
	return res, nil
}

// encryptionKeyRing resolves the key ring that holds the volume's
// key-encryption key. Null for a platform-managed volume, and null when the
// key lives in another project, whose rings this connection cannot read.
func (r *mqlStackitVolume) encryptionKeyRing() (*mqlStackitKmsKeyRing, error) {
	enc := r.cacheEncryption
	if enc.crossProject(conn(r.MqlRuntime).ProjectID()) {
		return markNull[mqlStackitKmsKeyRing](&r.EncryptionKeyRing)
	}
	return kmsKeyRingRef(r.MqlRuntime, enc.keyRingID, &r.EncryptionKeyRing)
}

// encryptionKeyServiceAccount resolves the service account the platform uses
// to unwrap the volume's data-encryption key with the customer-managed key.
// Null for a platform-managed volume, and null when the key and its service
// account belong to another project.
func (r *mqlStackitVolume) encryptionKeyServiceAccount() (*mqlStackitServiceAccount, error) {
	enc := r.cacheEncryption
	if enc.crossProject(conn(r.MqlRuntime).ProjectID()) {
		return markNull[mqlStackitServiceAccount](&r.EncryptionKeyServiceAccount)
	}
	return serviceAccountRef(r.MqlRuntime, enc.serviceAccount, &r.EncryptionKeyServiceAccount)
}

func (r *mqlStackitVolume) id() (string, error) {
	return "stackit.volume/" + r.Id.Data, nil
}

func (r *mqlStackitVolume) sourceVolume() (*mqlStackitVolume, error) {
	return refByKey(r.MqlRuntime, "stackit.volume", "id", r.cacheSourceVolumeID, &r.SourceVolume)
}

func initStackitVolume(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.IaaS()
	if err != nil {
		return nil, nil, err
	}
	v, err := client.DefaultAPI.GetVolume(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildVolume(runtime, v)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlStackitVolume) image() (*mqlStackitImage, error) {
	return refByKey(r.MqlRuntime, "stackit.image", "id", r.ImageId.Data, &r.Image)
}

func (r *mqlStackitVolume) server() (*mqlStackitServer, error) {
	return refByKey(r.MqlRuntime, "stackit.server", "id", r.ServerId.Data, &r.Server)
}

func (r *mqlStackitVolume) sourceSnapshot() (*mqlStackitSnapshot, error) {
	return refByKey(r.MqlRuntime, "stackit.snapshot", "id", r.SourceSnapshotId.Data, &r.SourceSnapshot)
}

func (r *mqlStackitVolume) sourceBackup() (*mqlStackitBackup, error) {
	return refByKey(r.MqlRuntime, "stackit.backup", "id", r.SourceBackupId.Data, &r.SourceBackup)
}

// encryptionKey resolves the customer-managed key that wraps the volume's
// data-encryption key. Null for a platform-managed volume, and null when the
// key lives in another project. The volume names the ring that holds the
// key, so the lookup reads that one ring instead of walking every ring.
func (r *mqlStackitVolume) encryptionKey() (*mqlStackitKmsKey, error) {
	enc := r.cacheEncryption
	if enc.crossProject(conn(r.MqlRuntime).ProjectID()) {
		return markNull[mqlStackitKmsKey](&r.EncryptionKey)
	}
	return kmsKeyInRingRef(r.MqlRuntime, enc.keyRingID, r.EncryptionKeyId.Data, &r.EncryptionKey)
}

// encryptionKeyVersionRef resolves the exact generation of key material the
// volume is pinned to, so a check can read that version's state rather than the
// key's newest one. Version numbers start at 1, so 0 means nothing is pinned.
func (r *mqlStackitVolume) encryptionKeyVersionRef() (*mqlStackitKmsKeyVersion, error) {
	field := &r.EncryptionKeyVersionRef
	number := r.EncryptionKeyVersion.Data
	if number == 0 {
		return markNull[mqlStackitKmsKeyVersion](field)
	}
	key := r.GetEncryptionKey()
	if key.Error != nil {
		return nil, key.Error
	}
	if key.Data == nil {
		return markNull[mqlStackitKmsKeyVersion](field)
	}
	versions := key.Data.GetVersions()
	if versions.Error != nil {
		return nil, versions.Error
	}
	v := findKmsKeyVersion(versions.Data, number)
	if v == nil {
		return markNull[mqlStackitKmsKeyVersion](field)
	}
	return v, nil
}

// ------------------------- snapshots -------------------------

func (r *mqlStackit) snapshots() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListSnapshotsInProject(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildSnapshot(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildSnapshot(runtime *plugin.Runtime, s *iaas.Snapshot) (plugin.Resource, error) {
	createdAt, ok1 := s.GetCreatedAtOk()
	updatedAt, ok2 := s.GetUpdatedAtOk()
	args := map[string]*llx.RawData{
		"id":               llx.StringData(s.GetId()),
		"name":             llx.StringData(s.GetName()),
		"status":           llx.StringData(s.GetStatus()),
		"size":             llx.IntData(int64(s.GetSize())),
		"availabilityZone": llx.StringData(s.GetAvailabilityZone()),
		"volumeId":         llx.StringData(s.GetVolumeId()),
		"createdAt":        llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
		"updatedAt":        llx.TimeDataPtr(timeOrNil(updatedAt, ok2)),
		"labels":           labelData(s.GetLabels()),
	}
	return CreateResource(runtime, "stackit.snapshot", args)
}

func (r *mqlStackitSnapshot) id() (string, error) {
	return "stackit.snapshot/" + r.Id.Data, nil
}

func initStackitSnapshot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.IaaS()
	if err != nil {
		return nil, nil, err
	}
	s, err := client.DefaultAPI.GetSnapshot(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildSnapshot(runtime, s)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlStackitSnapshot) volume() (*mqlStackitVolume, error) {
	return refByKey(r.MqlRuntime, "stackit.volume", "id", r.VolumeId.Data, &r.Volume)
}

// ------------------------- images -------------------------

func (r *mqlStackit) images() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListImages(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildImage(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildImage(runtime *plugin.Runtime, img *iaas.Image) (plugin.Resource, error) {
	var checksum map[string]any
	if cs, ok := img.GetChecksumOk(); ok {
		checksum = map[string]any{
			"algorithm": cs.GetAlgorithm(),
			"digest":    cs.GetDigest(),
		}
	}
	var config map[string]any
	if cfg, ok := img.GetConfigOk(); ok {
		config = map[string]any{
			"bootMenu":               cfg.GetBootMenu(),
			"cdromBus":               cfg.GetCdromBus(),
			"diskBus":                cfg.GetDiskBus(),
			"nicModel":               cfg.GetNicModel(),
			"operatingSystem":        cfg.GetOperatingSystem(),
			"operatingSystemDistro":  cfg.GetOperatingSystemDistro(),
			"operatingSystemVersion": cfg.GetOperatingSystemVersion(),
			"rescueBus":              cfg.GetRescueBus(),
			"rescueDevice":           cfg.GetRescueDevice(),
			"secureBoot":             cfg.GetSecureBoot(),
			"uefi":                   cfg.GetUefi(),
			"videoModel":             cfg.GetVideoModel(),
			"virtioScsi":             cfg.GetVirtioScsi(),
		}
	}
	createdAt, ok1 := img.GetCreatedAtOk()
	updatedAt, ok2 := img.GetUpdatedAtOk()

	args := map[string]*llx.RawData{
		"id":          llx.StringData(img.GetId()),
		"name":        llx.StringData(img.GetName()),
		"status":      llx.StringData(img.GetStatus()),
		"diskFormat":  llx.StringData(img.GetDiskFormat()),
		"minDiskSize": llx.IntData(int64(img.GetMinDiskSize())),
		"minRam":      llx.IntData(int64(img.GetMinRam())),
		"protected":   llx.BoolData(img.GetProtected()),
		"owner":       llx.StringData(img.GetOwner()),
		"scope":       llx.StringData(img.GetScope()),
		"checksum":    llx.DictData(checksum),
		"config":      llx.DictData(config),
		"createdAt":   llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
		"updatedAt":   llx.TimeDataPtr(timeOrNil(updatedAt, ok2)),
		"labels":      labelData(img.GetLabels()),
	}
	return CreateResource(runtime, "stackit.image", args)
}

func (r *mqlStackitImage) id() (string, error) {
	return "stackit.image/" + r.Id.Data, nil
}

// mqlStackitImageInternal caches the image's share record so the two sharing
// fields share one API call.
type mqlStackitImageInternal struct {
	shareFetched atomic.Bool
	share        *iaas.ImageShare
	shareLock    sync.Mutex
}

// fetchShare loads the image's share record. An image that has never been
// shared has no share record at all and the API answers 404, which is a
// legitimate "not shared" rather than an error.
func (r *mqlStackitImage) fetchShare() (*iaas.ImageShare, error) {
	if r.shareFetched.Load() {
		return r.share, nil
	}
	r.shareLock.Lock()
	defer r.shareLock.Unlock()
	if r.shareFetched.Load() {
		return r.share, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetImageShare(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) || isNotFound(err) {
			r.shareFetched.Store(true)
			return nil, nil
		}
		return nil, err
	}
	r.share = resp
	r.shareFetched.Store(true)
	return r.share, nil
}

func (r *mqlStackitImage) sharedWithProjects() ([]any, error) {
	s, err := r.fetchShare()
	if err != nil || s == nil {
		return []any{}, err
	}
	return strSlice(s.GetProjects()), nil
}

func (r *mqlStackitImage) sharedWithOrganization() (bool, error) {
	s, err := r.fetchShare()
	if err != nil || s == nil {
		return false, err
	}
	return s.GetParentOrganization(), nil
}

func initStackitImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.IaaS()
	if err != nil {
		return nil, nil, err
	}
	img, err := client.DefaultAPI.GetImage(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildImage(runtime, img)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// ------------------------- networks -------------------------

func (r *mqlStackit) networks() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListNetworks(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildNetwork(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildNetwork(runtime *plugin.Runtime, n *iaas.Network) (plugin.Resource, error) {
	var (
		ipv4Gateway    string
		ipv4Nameserv   []string
		ipv4Prefixes   []string
		ipv4PrefixSing string
		ipv4PublicIp   string
		ipv6Gateway    string
		ipv6Nameserv   []string
		ipv6Prefixes   []string
		ipv6PrefixSing string
	)
	if ipv4 := n.GetIpv4(); !iaasNetworkIPv4Empty(ipv4) {
		ipv4Gateway = ipv4.GetGateway()
		ipv4Nameserv = ipv4.GetNameservers()
		ipv4Prefixes = ipv4.GetPrefixes()
		ipv4PublicIp = ipv4.GetPublicIp()
		if len(ipv4Prefixes) > 0 {
			ipv4PrefixSing = ipv4Prefixes[0]
		}
	}
	if ipv6 := n.GetIpv6(); !iaasNetworkIPv6Empty(ipv6) {
		ipv6Gateway = ipv6.GetGateway()
		ipv6Nameserv = ipv6.GetNameservers()
		ipv6Prefixes = ipv6.GetPrefixes()
		if len(ipv6Prefixes) > 0 {
			ipv6PrefixSing = ipv6Prefixes[0]
		}
	}

	createdAt, okCreated := n.GetCreatedAtOk()
	updatedAt, okUpdated := n.GetUpdatedAtOk()

	args := map[string]*llx.RawData{
		"id":              llx.StringData(n.GetId()),
		"name":            llx.StringData(n.GetName()),
		"routed":          llx.BoolData(n.GetRouted()),
		"dhcp":            llx.BoolData(n.GetDhcp()),
		"createdAt":       llx.TimeDataPtr(timeOrNil(createdAt, okCreated)),
		"updatedAt":       llx.TimeDataPtr(timeOrNil(updatedAt, okUpdated)),
		"ipv4Prefix":      llx.StringData(ipv4PrefixSing),
		"ipv4Gateway":     llx.StringData(ipv4Gateway),
		"ipv4Nameservers": strSliceData(ipv4Nameserv),
		"ipv4Prefixes":    strSliceData(ipv4Prefixes),
		"ipv4PublicIp":    llx.StringData(ipv4PublicIp),
		"ipv6Prefix":      llx.StringData(ipv6PrefixSing),
		"ipv6Gateway":     llx.StringData(ipv6Gateway),
		"ipv6Nameservers": strSliceData(ipv6Nameserv),
		"ipv6Prefixes":    strSliceData(ipv6Prefixes),
		"state":           llx.StringData(n.GetStatus()),
		"labels":          labelData(n.GetLabels()),
	}
	res, err := CreateResource(runtime, "stackit.network", args)
	if err != nil {
		return nil, err
	}
	res.(*mqlStackitNetwork).cacheRoutingTableId = n.GetRoutingTableId()
	return res, nil
}

// mqlStackitNetworkInternal carries the routing table ID off the network
// payload. The table itself lives on a network area, so resolving it needs a
// separate walk that only runs when a query asks for it.
type mqlStackitNetworkInternal struct {
	cacheRoutingTableId string
}

func (r *mqlStackitNetwork) routingTable() (*mqlStackitRoutingTable, error) {
	if r.cacheRoutingTableId == "" {
		return markNull[mqlStackitRoutingTable](&r.RoutingTable)
	}
	tables, err := conn(r.MqlRuntime).NetworkAreaRoutingTables(bgctx())
	if err != nil {
		return nil, err
	}
	table, ok := tables[r.cacheRoutingTableId]
	if !ok {
		// The network names a table on an area this credential cannot read, so
		// report no table rather than inventing an empty one.
		return markNull[mqlStackitRoutingTable](&r.RoutingTable)
	}
	return buildRoutingTable(r.MqlRuntime, &table)
}

func buildRoutingTable(runtime *plugin.Runtime, t *iaas.RoutingTable) (*mqlStackitRoutingTable, error) {
	createdAt, okCreated := t.GetCreatedAtOk()
	updatedAt, okUpdated := t.GetUpdatedAtOk()

	res, err := CreateResource(runtime, "stackit.routingTable", map[string]*llx.RawData{
		"id":            llx.StringData(t.GetId()),
		"name":          llx.StringData(t.GetName()),
		"description":   llx.StringData(t.GetDescription()),
		"isDefault":     llx.BoolData(t.GetDefault()),
		"dynamicRoutes": llx.BoolData(t.GetDynamicRoutes()),
		"systemRoutes":  llx.BoolData(t.GetSystemRoutes()),
		"createdAt":     llx.TimeDataPtr(timeOrNil(createdAt, okCreated)),
		"updatedAt":     llx.TimeDataPtr(timeOrNil(updatedAt, okUpdated)),
		"labels":        labelData(t.GetLabels()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitRoutingTable), nil
}

func (r *mqlStackitRoutingTable) id() (string, error) {
	return "stackit.routingTable/" + r.Id.Data, nil
}

func (r *mqlStackitNetwork) id() (string, error) {
	return "stackit.network/" + r.Id.Data, nil
}

func initStackitNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.IaaS()
	if err != nil {
		return nil, nil, err
	}
	n, err := client.DefaultAPI.GetNetwork(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildNetwork(runtime, n)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// iaasNetworkIPv4Empty / iaasNetworkIPv6Empty: the SDK's GetIpv4()/GetIpv6()
// always return a (possibly zero-value) struct, so check the inner pointers
// for "set"-ness instead.
func iaasNetworkIPv4Empty(v iaas.NetworkIPv4) bool {
	return !v.Gateway.IsSet() && v.Nameservers == nil && v.Prefixes == nil && v.PublicIp == nil
}

func iaasNetworkIPv6Empty(v iaas.NetworkIPv6) bool {
	return !v.Gateway.IsSet() && v.Nameservers == nil && v.Prefixes == nil
}

// ------------------------- public IPs -------------------------

func (r *mqlStackit) publicIps() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListPublicIPs(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildPublicIp(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildPublicIp(runtime *plugin.Runtime, ip *iaas.PublicIp) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"id":                 llx.StringData(ip.GetId()),
		"ip":                 llx.StringData(ip.GetIp()),
		"networkInterfaceId": llx.StringData(ip.GetNetworkInterface()),
		"labels":             labelData(ip.GetLabels()),
	}
	return CreateResource(runtime, "stackit.publicIp", args)
}

func (r *mqlStackitPublicIp) id() (string, error) {
	return "stackit.publicIp/" + r.Id.Data, nil
}

func initStackitPublicIp(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.IaaS()
	if err != nil {
		return nil, nil, err
	}
	ip, err := client.DefaultAPI.GetPublicIP(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildPublicIp(runtime, ip)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// ------------------------- security groups -------------------------

func (r *mqlStackit) securityGroups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListSecurityGroups(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildSecurityGroup(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

type mqlStackitSecurityGroupInternal struct {
	// cacheRules holds the rules the group response carried inline, so that
	// rules() does not spend a ListSecurityGroupRules call per group. The
	// exposure walk reads every group's rules for every server, so that call
	// multiplied. cacheRulesSet distinguishes "the API sent an empty rule
	// list" (nothing to fetch) from "the API omitted the field" (fetch).
	cacheRules    []iaas.SecurityGroupRule
	cacheRulesSet bool
}

func buildSecurityGroup(runtime *plugin.Runtime, sg *iaas.SecurityGroup) (plugin.Resource, error) {
	createdAt, ok1 := sg.GetCreatedAtOk()
	updatedAt, ok2 := sg.GetUpdatedAtOk()
	args := map[string]*llx.RawData{
		"id":          llx.StringData(sg.GetId()),
		"name":        llx.StringData(sg.GetName()),
		"description": llx.StringData(sg.GetDescription()),
		"stateful":    llx.BoolData(sg.GetStateful()),
		"createdAt":   llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
		"updatedAt":   llx.TimeDataPtr(timeOrNil(updatedAt, ok2)),
		"labels":      labelData(sg.GetLabels()),
	}
	res, err := CreateResource(runtime, "stackit.securityGroup", args)
	if err != nil {
		return nil, err
	}
	if rules, ok := sg.GetRulesOk(); ok {
		mqlSg := res.(*mqlStackitSecurityGroup)
		mqlSg.cacheRules = rules
		mqlSg.cacheRulesSet = true
	}
	return res, nil
}

func (r *mqlStackitSecurityGroup) id() (string, error) {
	return "stackit.securityGroup/" + r.Id.Data, nil
}

func initStackitSecurityGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.IaaS()
	if err != nil {
		return nil, nil, err
	}
	sg, err := client.DefaultAPI.GetSecurityGroup(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildSecurityGroup(runtime, sg)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlStackitSecurityGroup) rules() ([]any, error) {
	items := r.cacheRules
	if !r.cacheRulesSet {
		c := conn(r.MqlRuntime)
		client, err := c.IaaS()
		if err != nil {
			return nil, err
		}
		resp, err := client.DefaultAPI.ListSecurityGroupRules(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
		if err != nil {
			if isAccessDenied(err) {
				return []any{}, nil
			}
			return nil, err
		}
		items, _ = resp.GetItemsOk()
	}
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.securityGroup.rule", securityGroupRuleArgs(r.Id.Data, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// securityGroupRuleArgs maps one SDK rule onto the stackit.securityGroup.rule
// fields. It serves both the rules the group response carries inline and the
// ones ListSecurityGroupRules returns, which share the SecurityGroupRule model.
func securityGroupRuleArgs(securityGroupID string, rule *iaas.SecurityGroupRule) map[string]*llx.RawData {
	// icmpType/icmpCode are nullable in the schema: leave them nil (MQL null)
	// for non-ICMP rules rather than emitting 0, which is a valid ICMP type.
	var icmpType, icmpCode *int64
	if icmp, ok := rule.GetIcmpParametersOk(); ok {
		t := icmp.GetType()
		code := icmp.GetCode()
		icmpType = &t
		icmpCode = &code
	}
	var portMin, portMax int64
	if pr, ok := rule.GetPortRangeOk(); ok {
		portMin = int64(pr.GetMin())
		portMax = int64(pr.GetMax())
	}
	var protocol string
	if p, ok := rule.GetProtocolOk(); ok {
		n, okNum := p.GetNumberOk()
		protocol = protocolLabel(p.GetName(), derefInt64(n), okNum && n != nil)
	}

	createdAt, okCreated := rule.GetCreatedAtOk()

	return map[string]*llx.RawData{
		"id":                    llx.StringData(rule.GetId()),
		"securityGroupId":       llx.StringData(securityGroupID),
		"direction":             llx.StringData(rule.GetDirection()),
		"ethertype":             llx.StringData(rule.GetEthertype()),
		"protocol":              llx.StringData(protocol),
		"description":           llx.StringData(rule.GetDescription()),
		"icmpType":              llx.IntDataPtr(icmpType),
		"icmpCode":              llx.IntDataPtr(icmpCode),
		"portRangeMin":          llx.IntData(portMin),
		"portRangeMax":          llx.IntData(portMax),
		"ipRange":               llx.StringData(rule.GetIpRange()),
		"remoteSecurityGroupId": llx.StringData(rule.GetRemoteSecurityGroupId()),
		"createdAt":             llx.TimeDataPtr(timeOrNil(createdAt, okCreated)),
	}
}

// protocolLabel renders a security-group rule protocol as its name, falling
// back to the numeric protocol id when the API returns only a number (for
// example GRE as 47), or "" when neither is set. The API populates exactly one
// of the two, so a numeric-only protocol would otherwise render empty.
func protocolLabel(name string, number int64, hasNumber bool) string {
	if name != "" {
		return name
	}
	if hasNumber {
		return strconv.FormatInt(number, 10)
	}
	return ""
}

func (r *mqlStackitSecurityGroupRule) id() (string, error) {
	return "stackit.securityGroup.rule/" + r.SecurityGroupId.Data + "/" + r.Id.Data, nil
}

// ------------------------- key pairs -------------------------

func (r *mqlStackit) keyPairs() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListKeyPairs(bgctx()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildKeyPair(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildKeyPair(runtime *plugin.Runtime, kp *iaas.Keypair) (plugin.Resource, error) {
	createdAt, ok1 := kp.GetCreatedAtOk()
	updatedAt, ok2 := kp.GetUpdatedAtOk()
	args := map[string]*llx.RawData{
		"name":        llx.StringData(kp.GetName()),
		"fingerprint": llx.StringData(kp.GetFingerprint()),
		"publicKey":   llx.StringData(kp.GetPublicKey()),
		"createdAt":   llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
		"updatedAt":   llx.TimeDataPtr(timeOrNil(updatedAt, ok2)),
		"labels":      labelData(kp.GetLabels()),
	}
	return CreateResource(runtime, "stackit.keyPair", args)
}

func (r *mqlStackitKeyPair) id() (string, error) {
	return "stackit.keyPair/" + r.Name.Data, nil
}

func initStackitKeyPair(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	v, ok := args["name"]
	if !ok || v == nil {
		return args, nil, nil
	}
	name, ok := v.Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.IaaS()
	if err != nil {
		return nil, nil, err
	}
	kp, err := client.DefaultAPI.GetKeyPair(bgctx(), name).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildKeyPair(runtime, kp)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}
