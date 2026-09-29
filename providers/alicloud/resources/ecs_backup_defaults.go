// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	ecsclient "github.com/alibabacloud-go/ecs-20140526/v7/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// ecsAutoSnapshotPolicyPageSize is the largest page DescribeAutoSnapshotPolicyEx
// accepts.
const ecsAutoSnapshotPolicyPageSize = 100

// mqlAlicloudEcsInternal memoizes the automatic snapshot policies of each
// region, so every disk resolving its policy shares one listing per region
// rather than making a lookup per disk. A failed listing is memoized too: with
// hundreds of disks in a region the credential cannot read, an uncached error
// would cost one failed call per disk.
type mqlAlicloudEcsInternal struct {
	policyLock sync.Mutex
	policies   map[string][]*mqlAlicloudEcsAutoSnapshotPolicy
	policyErrs map[string]error
}

func ecsResource(runtime *plugin.Runtime) (*mqlAlicloudEcs, error) {
	res, err := CreateResource(runtime, "alicloud.ecs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudEcs), nil
}

// autoSnapshotPoliciesIn lists the automatic snapshot policies of one region,
// once, memoizing the outcome whether it succeeded or failed.
func (r *mqlAlicloudEcs) autoSnapshotPoliciesIn(region string) ([]*mqlAlicloudEcsAutoSnapshotPolicy, error) {
	r.policyLock.Lock()
	defer r.policyLock.Unlock()
	if cached, ok := r.policies[region]; ok {
		return cached, nil
	}
	if err, ok := r.policyErrs[region]; ok {
		return nil, err
	}
	res, err := r.listAutoSnapshotPolicies(region)
	if err != nil {
		if r.policyErrs == nil {
			r.policyErrs = map[string]error{}
		}
		r.policyErrs[region] = err
		return nil, err
	}
	if r.policies == nil {
		r.policies = map[string][]*mqlAlicloudEcsAutoSnapshotPolicy{}
	}
	r.policies[region] = res
	return res, nil
}

// listAutoSnapshotPolicies walks every page of a region's automatic snapshot
// policies.
func (r *mqlAlicloudEcs) listAutoSnapshotPolicies(region string) ([]*mqlAlicloudEcsAutoSnapshotPolicy, error) {

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EcsClient(region)
	if err != nil {
		return nil, err
	}

	res := []*mqlAlicloudEcsAutoSnapshotPolicy{}
	page := int32(1)
	for {
		resp, err := client.DescribeAutoSnapshotPolicyEx(&ecsclient.DescribeAutoSnapshotPolicyExRequest{
			RegionId:   tea.String(region),
			PageNumber: tea.Int32(page),
			PageSize:   tea.Int32(ecsAutoSnapshotPolicyPageSize),
		})
		if err != nil {
			return nil, classifyAlicloudError(err, "ecs:DescribeAutoSnapshotPolicyEx")
		}
		if resp == nil || resp.Body == nil || resp.Body.AutoSnapshotPolicies == nil {
			break
		}
		items := resp.Body.AutoSnapshotPolicies.AutoSnapshotPolicy
		for _, p := range items {
			if p == nil || tea.StringValue(p.AutoSnapshotPolicyId) == "" {
				continue
			}
			policy, err := newEcsAutoSnapshotPolicy(r.MqlRuntime, region, p)
			if err != nil {
				return nil, err
			}
			res = append(res, policy)
		}
		if ecsPageDone(len(items), page, ecsAutoSnapshotPolicyPageSize, resp.Body.TotalCount) {
			break
		}
		page++
	}
	return res, nil
}

// ecsPageDone reports whether a page-numbered listing is complete: the page came
// back short or empty, or every item the total announces has been read.
func ecsPageDone(itemCount int, pageNumber int32, pageSize int32, total *int32) bool {
	if itemCount == 0 || itemCount < int(pageSize) {
		return true
	}
	if total != nil && int64(pageNumber)*int64(pageSize) >= int64(*total) {
		return true
	}
	return false
}

func newEcsAutoSnapshotPolicy(runtime *plugin.Runtime, region string, p *ecsclient.DescribeAutoSnapshotPolicyExResponseBodyAutoSnapshotPoliciesAutoSnapshotPolicy) (*mqlAlicloudEcsAutoSnapshotPolicy, error) {
	tags := map[string]any{}
	if p.Tags != nil {
		for _, t := range p.Tags.Tag {
			if t == nil || tea.StringValue(t.TagKey) == "" {
				continue
			}
			tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
		}
	}
	copyEncrypted := false
	if p.CopyEncryptionConfiguration != nil {
		copyEncrypted = tea.BoolValue(p.CopyEncryptionConfiguration.Encrypted)
	}

	res, err := CreateResource(runtime, "alicloud.ecs.autoSnapshotPolicy", map[string]*llx.RawData{
		"__id":                         llx.StringData(region + "/" + tea.StringValue(p.AutoSnapshotPolicyId)),
		"regionId":                     llx.StringData(region),
		"autoSnapshotPolicyId":         llx.StringDataPtr(p.AutoSnapshotPolicyId),
		"name":                         llx.StringDataPtr(p.AutoSnapshotPolicyName),
		"status":                       llx.StringDataPtr(p.Status),
		"type":                         llx.StringDataPtr(p.Type),
		"timePoints":                   llx.ArrayData(parseJSONIntList(p.TimePoints), types.Int),
		"repeatWeekdays":               llx.ArrayData(parseJSONIntList(p.RepeatWeekdays), types.Int),
		"retentionDays":                llx.IntDataPtr(p.RetentionDays),
		"diskCount":                    llx.IntDataPtr(p.DiskNums),
		"volumeCount":                  llx.IntDataPtr(p.VolumeNums),
		"crossRegionCopyEnabled":       llx.BoolData(tea.BoolValue(p.EnableCrossRegionCopy)),
		"targetCopyRegions":            llx.ArrayData(stringsToAny(parseJSONStringList(p.TargetCopyRegions)), types.String),
		"copiedSnapshotsRetentionDays": llx.IntDataPtr(p.CopiedSnapshotsRetentionDays),
		"copyEncrypted":                llx.BoolData(copyEncrypted),
		"creationTime":                 llx.TimeDataPtr(parseEcsTime(p.CreationTime)),
		"resourceGroupId":              llx.StringDataPtr(p.ResourceGroupId),
		"tags":                         llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudEcsAutoSnapshotPolicy), nil
}

func (r *mqlAlicloudEcs) autoSnapshotPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		policies, err := r.autoSnapshotPoliciesIn(region)
		if err != nil {
			// a denied or unavailable region is a partial result; keep the others
			logSkippedRegion(err, "ECS automatic snapshot policy", region)
			continue
		}
		for _, p := range policies {
			res = append(res, p)
		}
	}
	return res, nil
}

func (r *mqlAlicloudEcsAutoSnapshotPolicy) id() (string, error) {
	return r.RegionId.Data + "/" + r.AutoSnapshotPolicyId.Data, nil
}

func (r *mqlAlicloudEcsAutoSnapshotPolicy) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// autoSnapshotPolicy resolves the automatic snapshot policy applied to the disk
// from the region's memoized policy list. A disk with no policy reads null.
func (r *mqlAlicloudEcsDisk) autoSnapshotPolicy() (*mqlAlicloudEcsAutoSnapshotPolicy, error) {
	if r.cacheAutoSnapshotPolicyID == "" {
		r.AutoSnapshotPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ecs, err := ecsResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	policies, err := ecs.autoSnapshotPoliciesIn(r.cacheRegion)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		if p.AutoSnapshotPolicyId.Data == r.cacheAutoSnapshotPolicyID {
			return p, nil
		}
	}
	log.Debug().Str("autoSnapshotPolicyId", r.cacheAutoSnapshotPolicyID).Str("region", r.cacheRegion).
		Msg("alicloud> automatic snapshot policy named by a disk was not found")
	r.AutoSnapshotPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// mqlAlicloudEcsDiskEncryptionDefaultInternal caches the region's default KMS
// key id, read alongside the encryption-by-default status.
type mqlAlicloudEcsDiskEncryptionDefaultInternal struct {
	cacheKmsKeyID string
}

func (r *mqlAlicloudEcs) diskEncryptionDefaults() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.EcsClient(region)
		if err != nil {
			return nil, err
		}
		status, err := client.DescribeDiskEncryptionByDefaultStatus(&ecsclient.DescribeDiskEncryptionByDefaultStatusRequest{
			RegionId: tea.String(region),
		})
		if err != nil {
			// a denied or unavailable region is a partial result; keep the others
			logSkippedRegion(err, "ECS disk encryption default", region)
			continue
		}
		if status == nil || status.Body == nil || status.Body.Encrypted == nil {
			continue
		}

		// The default key is optional: without it the region uses the
		// service-managed key, so a failure to read it leaves the key null
		// rather than dropping the region's encryption status.
		kmsKeyID := ""
		keyResp, err := client.DescribeDiskDefaultKMSKeyId(&ecsclient.DescribeDiskDefaultKMSKeyIdRequest{
			RegionId: tea.String(region),
		})
		if err != nil {
			log.Debug().Err(err).Str("region", region).
				Msg("alicloud> could not read the default disk KMS key")
		} else if keyResp != nil && keyResp.Body != nil {
			kmsKeyID = tea.StringValue(keyResp.Body.KMSKeyId)
		}

		resource, err := CreateResource(r.MqlRuntime, "alicloud.ecs.diskEncryptionDefault", map[string]*llx.RawData{
			"__id":     llx.StringData("alicloud.ecs.diskEncryptionDefault/" + region),
			"regionId": llx.StringData(region),
			"enabled":  llx.BoolData(*status.Body.Encrypted),
		})
		if err != nil {
			return nil, err
		}
		def := resource.(*mqlAlicloudEcsDiskEncryptionDefault)
		def.cacheKmsKeyID = kmsKeyID
		res = append(res, def)
	}
	return res, nil
}

func (r *mqlAlicloudEcsDiskEncryptionDefault) kmsKey() (*mqlAlicloudKmsKey, error) {
	if r.cacheKmsKeyID == "" {
		r.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	key, err := resolveKmsKey(r.MqlRuntime, r.RegionId.Data, r.cacheKmsKeyID)
	if err != nil || key == nil {
		log.Debug().Err(err).Str("keyId", r.cacheKmsKeyID).Str("region", r.RegionId.Data).
			Msg("alicloud> could not resolve the default disk KMS key")
		r.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return key, nil
}
