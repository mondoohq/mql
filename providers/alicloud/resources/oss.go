// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	tea "github.com/alibabacloud-go/tea/tea"
	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

func (r *mqlAlicloudOss) id() (string, error) {
	return "alicloud.oss", nil
}

// buckets lists every bucket owned by the account. ListBuckets returns buckets
// from all regions in a single (paginated) call, so it is issued once against
// the connection's default-region client.
func (r *mqlAlicloudOss) buckets() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.OssClient(conn.Region())
	if err != nil {
		return nil, err
	}

	res := []any{}
	var marker *string
	for {
		resp, err := client.ListBuckets(context.Background(), &oss.ListBucketsRequest{
			Marker:  marker,
			MaxKeys: 1000,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil {
			break
		}

		for i := range resp.Buckets {
			bucket, err := newOssBucket(r.MqlRuntime, conn, resp.Buckets[i])
			if err != nil {
				return nil, err
			}
			// bucket tags cost a GetBucketTags call each, so only read them when
			// a tag filter is actually set
			if conn.Filters.General.HasTags() {
				tags := bucket.GetTags()
				if tags.Error != nil {
					return nil, tags.Error
				}
				if filteredOutByTags(conn, tags.Data) {
					continue
				}
			}
			res = append(res, bucket)
		}

		if !resp.IsTruncated || resp.NextMarker == nil {
			break
		}
		marker = resp.NextMarker
	}

	return res, nil
}

// newOssBucket builds a fully populated alicloud.oss.bucket from a ListBuckets
// item. It is shared by the buckets list accessor and the by-name init so both
// produce identical resources.
func newOssBucket(runtime *plugin.Runtime, conn *connection.AlicloudConnection, b oss.BucketProperties) (*mqlAlicloudOssBucket, error) {
	name := tea.StringValue(b.Name)
	region := tea.StringValue(b.Region)
	// When ListBuckets does not populate Region, derive it from the Location
	// (for example oss-cn-hangzhou -> cn-hangzhou) so the per-bucket detail
	// client addresses the bucket's own region rather than the connection's
	// default, which would make every detail call fail for cross-region buckets.
	if region == "" {
		region = strings.TrimPrefix(tea.StringValue(b.Location), "oss-")
	}
	if region == "" {
		region = conn.Region()
	}

	bucket, err := CreateResource(runtime, "alicloud.oss.bucket", map[string]*llx.RawData{
		"__id":             llx.StringData(name),
		"name":             llx.StringData(name),
		"region":           llx.StringData(region),
		"location":         llx.StringDataPtr(b.Location),
		"storageClass":     llx.StringDataPtr(b.StorageClass),
		"creationDate":     llx.TimeDataPtr(b.CreationDate),
		"intranetEndpoint": llx.StringDataPtr(b.IntranetEndpoint),
		"extranetEndpoint": llx.StringDataPtr(b.ExtranetEndpoint),
		"resourceGroupId":  llx.StringDataPtr(b.ResourceGroupId),
	})
	if err != nil {
		return nil, err
	}
	return bucket.(*mqlAlicloudOssBucket), nil
}

// resolveOssBucket returns the typed bucket for a name, or (nil, nil) when name
// is empty. It backs the ActionTrail ossBucket() reference.
func resolveOssBucket(runtime *plugin.Runtime, name string) (*mqlAlicloudOssBucket, error) {
	if name == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.oss.bucket", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudOssBucket), nil
}

// initAlicloudOssBucket resolves a bucket by name, reusing an already-listed
// bucket from the resource cache and otherwise listing buckets (a single global
// call) to find and fully populate the match.
func initAlicloudOssBucket(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	// on a discovered bucket asset, resolve the bucket the asset is scoped to
	args = scopedInitIDArgs(runtime, args, connection.OptionOssBucket, "name")

	name, err := requiredStringArg(args, "name", "alicloud.oss.bucket")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.oss.bucket\x00" + name); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.OssClient(conn.Region())
	if err != nil {
		return nil, nil, err
	}
	var marker *string
	for {
		resp, err := client.ListBuckets(context.Background(), &oss.ListBucketsRequest{
			Marker:  marker,
			MaxKeys: 1000,
		})
		if err != nil {
			return nil, nil, err
		}
		if resp == nil {
			break
		}
		for i := range resp.Buckets {
			if tea.StringValue(resp.Buckets[i].Name) != name {
				continue
			}
			res, err := newOssBucket(runtime, conn, resp.Buckets[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
		if !resp.IsTruncated || resp.NextMarker == nil {
			break
		}
		marker = resp.NextMarker
	}
	return nil, nil, fmt.Errorf("alicloud.oss.bucket %q not found", name)
}

// mqlAlicloudOssBucketInternal caches the values needed to build a per-bucket
// OSS client and memoizes the two detail calls (GetBucketInfo and
// GetBucketEncryption) that back more than one accessor.
type mqlAlicloudOssBucketInternal struct {
	infoLock   sync.Mutex
	infoLoaded atomic.Bool
	info       *oss.BucketInfo

	encLock   sync.Mutex
	encLoaded atomic.Bool
	encRule   *oss.ApplyServerSideEncryptionByDefault

	// Each of the four below backs several accessors, so the result is memoized
	// to keep a query that selects all of them to one call per configuration.
	httpsLock   sync.Mutex
	httpsLoaded atomic.Bool
	httpsTLS    *oss.TLS

	wormLock   sync.Mutex
	wormLoaded atomic.Bool
	wormConfig *oss.WormConfiguration

	refererLock   sync.Mutex
	refererLoaded atomic.Bool
	refererConfig *oss.RefererConfiguration

	websiteLock   sync.Mutex
	websiteLoaded atomic.Bool
	websiteConfig *oss.WebsiteConfiguration
}

func (a *mqlAlicloudOssBucket) id() (string, error) {
	return a.Name.Data, nil
}

// ossClient builds an OSS client bound to the bucket's own region so the
// per-bucket detail APIs address the correct endpoint.
func (a *mqlAlicloudOssBucket) ossClient() (*oss.Client, error) {
	conn := a.MqlRuntime.Connection.(*connection.AlicloudConnection)
	return conn.OssClient(a.Region.Data)
}

func (a *mqlAlicloudOssBucket) acl() (string, error) {
	client, err := a.ossClient()
	if err != nil {
		return "", err
	}
	resp, err := client.GetBucketAcl(context.Background(), &oss.GetBucketAclRequest{Bucket: &a.Name.Data})
	if err != nil {
		// tolerate access-denied / transient errors on this optional detail call
		return "", nil
	}
	if resp == nil || resp.ACL == nil {
		return "", nil
	}
	return *resp.ACL, nil
}

func (a *mqlAlicloudOssBucket) versioning() (string, error) {
	client, err := a.ossClient()
	if err != nil {
		return "", err
	}
	resp, err := client.GetBucketVersioning(context.Background(), &oss.GetBucketVersioningRequest{Bucket: &a.Name.Data})
	if err != nil {
		return "", nil
	}
	if resp == nil || resp.VersionStatus == nil {
		return "", nil
	}
	return *resp.VersionStatus, nil
}

// fetchEncryption memoizes the default server-side encryption rule. A missing
// rule (no encryption configured) or an access error both resolve to a cached
// nil so encryption and sseAlgorithm agree and neither re-calls the API.
func (a *mqlAlicloudOssBucket) fetchEncryption() (*oss.ApplyServerSideEncryptionByDefault, error) {
	if a.encLoaded.Load() {
		return a.encRule, nil
	}
	a.encLock.Lock()
	defer a.encLock.Unlock()
	if a.encLoaded.Load() {
		return a.encRule, nil
	}

	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketEncryption(context.Background(), &oss.GetBucketEncryptionRequest{Bucket: &a.Name.Data})
	if err != nil {
		// no encryption rule configured, or access denied
		a.encRule = nil
		a.encLoaded.Store(true)
		return nil, nil
	}
	if resp != nil && resp.ServerSideEncryptionRule != nil {
		a.encRule = resp.ServerSideEncryptionRule.ApplyServerSideEncryptionByDefault
	}
	a.encLoaded.Store(true)
	return a.encRule, nil
}

func (a *mqlAlicloudOssBucket) encryption() (any, error) {
	rule, err := a.fetchEncryption()
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, nil
	}
	return convert.JsonToDict(rule)
}

func (a *mqlAlicloudOssBucket) sseAlgorithm() (string, error) {
	rule, err := a.fetchEncryption()
	if err != nil {
		return "", err
	}
	if rule == nil || rule.SSEAlgorithm == nil {
		return "", nil
	}
	return *rule.SSEAlgorithm, nil
}

// kmsKey resolves the customer master key named by the bucket's default
// encryption rule. Returns null when the bucket has no default encryption or
// uses the built-in AES256/SM4 keys rather than a specific KMS key.
func (a *mqlAlicloudOssBucket) kmsKey() (*mqlAlicloudKmsKey, error) {
	rule, err := a.fetchEncryption()
	if err != nil {
		return nil, err
	}
	if rule == nil || rule.KMSMasterKeyID == nil || *rule.KMSMasterKeyID == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	key, err := resolveKmsKey(a.MqlRuntime, a.Region.Data, *rule.KMSMasterKeyID)
	if err != nil || key == nil {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return key, nil
}

func (a *mqlAlicloudOssBucket) logging() (any, error) {
	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketLogging(context.Background(), &oss.GetBucketLoggingRequest{Bucket: &a.Name.Data})
	if err != nil {
		return nil, nil
	}
	if resp == nil || resp.BucketLoggingStatus == nil || resp.BucketLoggingStatus.LoggingEnabled == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.BucketLoggingStatus.LoggingEnabled)
}

func (a *mqlAlicloudOssBucket) policy() (string, error) {
	client, err := a.ossClient()
	if err != nil {
		return "", err
	}
	resp, err := client.GetBucketPolicy(context.Background(), &oss.GetBucketPolicyRequest{Bucket: &a.Name.Data})
	if err != nil {
		// most buckets have no policy (NoSuchBucketPolicy)
		return "", nil
	}
	if resp == nil {
		return "", nil
	}
	return resp.Body, nil
}

func (a *mqlAlicloudOssBucket) tags() (map[string]any, error) {
	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketTags(context.Background(), &oss.GetBucketTagsRequest{Bucket: &a.Name.Data})
	if err != nil {
		return nil, nil
	}
	res := map[string]any{}
	if resp != nil && resp.Tagging != nil && resp.Tagging.TagSet != nil {
		for _, t := range resp.Tagging.TagSet.Tags {
			if t.Key == nil {
				continue
			}
			res[*t.Key] = tea.StringValue(t.Value)
		}
	}
	return res, nil
}

func (a *mqlAlicloudOssBucket) publicAccessBlock() (any, error) {
	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketPublicAccessBlock(context.Background(), &oss.GetBucketPublicAccessBlockRequest{Bucket: &a.Name.Data})
	if err != nil {
		return nil, nil
	}
	if resp == nil || resp.PublicAccessBlockConfiguration == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.PublicAccessBlockConfiguration)
}

// fetchInfo memoizes GetBucketInfo, which backs bucketInfo and the flattened
// transferAcceleration, crossRegionReplication, dataRedundancyType, and
// blockPublicAccess accessors.
func (a *mqlAlicloudOssBucket) fetchInfo() (*oss.BucketInfo, error) {
	if a.infoLoaded.Load() {
		return a.info, nil
	}
	a.infoLock.Lock()
	defer a.infoLock.Unlock()
	if a.infoLoaded.Load() {
		return a.info, nil
	}

	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketInfo(context.Background(), &oss.GetBucketInfoRequest{Bucket: &a.Name.Data})
	if err != nil || resp == nil {
		a.info = nil
		a.infoLoaded.Store(true)
		return nil, nil
	}
	a.info = &resp.BucketInfo
	a.infoLoaded.Store(true)
	return a.info, nil
}

func (a *mqlAlicloudOssBucket) bucketInfo() (any, error) {
	info, err := a.fetchInfo()
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}
	return convert.JsonToDict(info)
}

func (a *mqlAlicloudOssBucket) transferAcceleration() (string, error) {
	info, err := a.fetchInfo()
	if err != nil {
		return "", err
	}
	if info == nil || info.TransferAcceleration == nil {
		return "", nil
	}
	return *info.TransferAcceleration, nil
}

func (a *mqlAlicloudOssBucket) crossRegionReplication() (string, error) {
	info, err := a.fetchInfo()
	if err != nil {
		return "", err
	}
	if info == nil || info.CrossRegionReplication == nil {
		return "", nil
	}
	return *info.CrossRegionReplication, nil
}

func (a *mqlAlicloudOssBucket) dataRedundancyType() (string, error) {
	info, err := a.fetchInfo()
	if err != nil {
		return "", err
	}
	if info == nil || info.DataRedundancyType == nil {
		return "", nil
	}
	return *info.DataRedundancyType, nil
}

func (a *mqlAlicloudOssBucket) blockPublicAccess() (bool, error) {
	info, err := a.fetchInfo()
	if err != nil {
		return false, err
	}
	if info == nil || info.BlockPublicAccess == nil {
		return false, nil
	}
	return *info.BlockPublicAccess, nil
}

// isPublic folds the two ways a bucket reaches anonymous callers, a public
// canned ACL and a bucket policy naming a "*" principal, into one verdict.
// Block public access overrides both, so it is checked first. The fields are
// read through their generated accessors so a query asking for isPublic
// alongside acl or policy costs one call each rather than two.
func (a *mqlAlicloudOssBucket) isPublic() (bool, error) {
	blocked := a.GetBlockPublicAccess()
	if blocked.Error != nil {
		return false, blocked.Error
	}
	if blocked.Data {
		return false, nil
	}

	acl := a.GetAcl()
	if acl.Error != nil {
		return false, acl.Error
	}
	switch strings.ToLower(strings.TrimSpace(acl.Data)) {
	case "public-read", "public-read-write":
		return true, nil
	}

	// Object Storage Service publishes its own verdict on whether the policy
	// opens the bucket. When it can be read it settles the question, so the
	// policy document is neither fetched nor parsed.
	status := a.GetPolicyAllowsPublicAccess()
	if status.Error == nil {
		return status.Data, nil
	}
	log.Debug().Err(status.Error).Str("bucket", a.Name.Data).
		Msg("alicloud: could not read the bucket policy status, falling back to parsing the policy")

	// The fallback exists because GetBucketPolicyStatus needs its own
	// permission: a credential that can read the document but not the status
	// still gets an answer rather than a silent false.
	policy := a.GetPolicy()
	if policy.Error != nil {
		return false, policy.Error
	}
	statements, err := parsePolicyDocument(policy.Data)
	if err != nil {
		// an unparseable policy is not evidence of exposure, and the raw
		// document stays available through the policy field. Warn rather than
		// stay silent: the parsed verdict is skipped, so a bucket opened by its
		// policy alone would read as not public.
		log.Warn().Err(err).Str("bucket", a.Name.Data).
			Msg("alicloud: could not parse bucket policy, isPublic reflects the acl only")
		return false, nil
	}
	return policyGrantsAnonymousAccess(statements), nil
}

// itoaInt renders a slice index for a synthetic cache key.
func itoaInt(i int) string {
	return strconv.Itoa(i)
}
