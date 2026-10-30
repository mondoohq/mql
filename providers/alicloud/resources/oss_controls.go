// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"

	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// ossConfigAbsent reports whether an error from a per-bucket configuration call
// means the configuration is simply not set, rather than that the read failed.
//
// Object Storage Service answers an unset configuration with 404 and a
// per-feature NoSuch* code. Only that shape is matched: a 403 from a credential
// without permission, and a transport failure carrying no ServiceError at all,
// both stay errors. Folding them into "not configured" is what would turn an
// unread bucket into a bucket that reports no CORS rules, no retention policy
// and no TLS floor, which is the reading an audit would pass on.
func ossConfigAbsent(err error) bool {
	var svcErr *oss.ServiceError
	if !errors.As(err, &svcErr) {
		return false
	}
	return svcErr.StatusCode == http.StatusNotFound
}

// ossStrings copies a slice of strings into a []any, dropping empty entries so
// an allow list never carries a blank that would read as a configured value.
func ossStrings(in []string) []any {
	res := []any{}
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		res = append(res, s)
	}
	return res
}

// policyAllowsPublicAccess reports Object Storage Service's own verdict on
// whether the attached bucket policy opens the bucket. A bucket with no policy
// answers 404, which is not a failure.
func (a *mqlAlicloudOssBucket) policyAllowsPublicAccess() (bool, error) {
	client, err := a.ossClient()
	if err != nil {
		return false, err
	}
	resp, err := client.GetBucketPolicyStatus(context.Background(), &oss.GetBucketPolicyStatusRequest{
		Bucket: &a.Name.Data,
	})
	if err != nil {
		if ossConfigAbsent(err) {
			return false, nil
		}
		return false, err
	}
	if resp == nil || resp.PolicyStatus == nil || resp.PolicyStatus.IsPublic == nil {
		return false, nil
	}
	return *resp.PolicyStatus.IsPublic, nil
}

// fetchHttpsConfig loads and memoizes the bucket's TLS version configuration,
// which both tlsEnforced and tlsVersions read. A transient error is not cached,
// so a later access retries rather than permanently reporting a bucket whose
// configuration was never read as having no TLS floor.
func (a *mqlAlicloudOssBucket) fetchHttpsConfig() (*oss.TLS, error) {
	if a.httpsLoaded.Load() {
		return a.httpsTLS, nil
	}
	a.httpsLock.Lock()
	defer a.httpsLock.Unlock()
	if a.httpsLoaded.Load() {
		return a.httpsTLS, nil
	}

	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketHttpsConfig(context.Background(), &oss.GetBucketHttpsConfigRequest{
		Bucket: &a.Name.Data,
	})
	if err != nil {
		if !ossConfigAbsent(err) {
			return nil, err
		}
		// not configured is a real answer and is cached like one
	} else if resp != nil && resp.HttpsConfiguration != nil {
		a.httpsTLS = resp.HttpsConfiguration.TLS
	}
	a.httpsLoaded.Store(true)
	return a.httpsTLS, nil
}

func (a *mqlAlicloudOssBucket) tlsEnforced() (bool, error) {
	tls, err := a.fetchHttpsConfig()
	if err != nil || tls == nil || tls.Enable == nil {
		return false, err
	}
	return *tls.Enable, nil
}

func (a *mqlAlicloudOssBucket) tlsVersions() ([]any, error) {
	tls, err := a.fetchHttpsConfig()
	if err != nil || tls == nil {
		return nil, err
	}
	return ossStrings(tls.TLSVersions), nil
}

// fetchWorm loads and memoizes the bucket's retention policy, which both
// objectLockState and objectLockRetentionDays read. A bucket without one answers
// 404, which the SDK documents explicitly for this call.
func (a *mqlAlicloudOssBucket) fetchWorm() (*oss.WormConfiguration, error) {
	if a.wormLoaded.Load() {
		return a.wormConfig, nil
	}
	a.wormLock.Lock()
	defer a.wormLock.Unlock()
	if a.wormLoaded.Load() {
		return a.wormConfig, nil
	}

	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketWorm(context.Background(), &oss.GetBucketWormRequest{
		Bucket: &a.Name.Data,
	})
	if err != nil {
		if !ossConfigAbsent(err) {
			return nil, err
		}
	} else if resp != nil {
		a.wormConfig = resp.WormConfiguration
	}
	a.wormLoaded.Store(true)
	return a.wormConfig, nil
}

func (a *mqlAlicloudOssBucket) objectLockState() (string, error) {
	worm, err := a.fetchWorm()
	if err != nil || worm == nil {
		return "", err
	}
	return string(worm.State), nil
}

func (a *mqlAlicloudOssBucket) objectLockRetentionDays() (int64, error) {
	worm, err := a.fetchWorm()
	if err != nil || worm == nil || worm.RetentionPeriodInDays == nil {
		return 0, err
	}
	return int64(*worm.RetentionPeriodInDays), nil
}

// fetchReferer loads and memoizes the bucket's referer restriction, which
// allowEmptyReferer, refererAllowList and refererDenyList all read.
func (a *mqlAlicloudOssBucket) fetchReferer() (*oss.RefererConfiguration, error) {
	if a.refererLoaded.Load() {
		return a.refererConfig, nil
	}
	a.refererLock.Lock()
	defer a.refererLock.Unlock()
	if a.refererLoaded.Load() {
		return a.refererConfig, nil
	}

	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketReferer(context.Background(), &oss.GetBucketRefererRequest{
		Bucket: &a.Name.Data,
	})
	if err != nil {
		if !ossConfigAbsent(err) {
			return nil, err
		}
	} else if resp != nil {
		a.refererConfig = resp.RefererConfiguration
	}
	a.refererLoaded.Store(true)
	return a.refererConfig, nil
}

// allowEmptyReferer reports whether a request with no Referer header is
// accepted. Object Storage Service defaults this to true, so an unconfigured
// bucket reports true rather than false: reporting false would claim a
// restriction the bucket does not have.
func (a *mqlAlicloudOssBucket) allowEmptyReferer() (bool, error) {
	cfg, err := a.fetchReferer()
	if err != nil {
		return false, err
	}
	if cfg == nil || cfg.AllowEmptyReferer == nil {
		return true, nil
	}
	return *cfg.AllowEmptyReferer, nil
}

func (a *mqlAlicloudOssBucket) refererAllowList() ([]any, error) {
	cfg, err := a.fetchReferer()
	if err != nil || cfg == nil || cfg.RefererList == nil {
		return nil, err
	}
	return ossStrings(cfg.RefererList.Referers), nil
}

func (a *mqlAlicloudOssBucket) refererDenyList() ([]any, error) {
	cfg, err := a.fetchReferer()
	if err != nil || cfg == nil || cfg.RefererBlacklist == nil {
		return nil, err
	}
	return ossStrings(cfg.RefererBlacklist.Referers), nil
}

// fetchWebsite loads and memoizes the bucket's static website configuration,
// which websiteEnabled and both document accessors read.
func (a *mqlAlicloudOssBucket) fetchWebsite() (*oss.WebsiteConfiguration, error) {
	if a.websiteLoaded.Load() {
		return a.websiteConfig, nil
	}
	a.websiteLock.Lock()
	defer a.websiteLock.Unlock()
	if a.websiteLoaded.Load() {
		return a.websiteConfig, nil
	}

	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketWebsite(context.Background(), &oss.GetBucketWebsiteRequest{
		Bucket: &a.Name.Data,
	})
	if err != nil {
		if !ossConfigAbsent(err) {
			return nil, err
		}
	} else if resp != nil {
		a.websiteConfig = resp.WebsiteConfiguration
	}
	a.websiteLoaded.Store(true)
	return a.websiteConfig, nil
}

func (a *mqlAlicloudOssBucket) websiteEnabled() (bool, error) {
	cfg, err := a.fetchWebsite()
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

func (a *mqlAlicloudOssBucket) websiteIndexDocument() (string, error) {
	cfg, err := a.fetchWebsite()
	if err != nil || cfg == nil || cfg.IndexDocument == nil || cfg.IndexDocument.Suffix == nil {
		return "", err
	}
	return *cfg.IndexDocument.Suffix, nil
}

func (a *mqlAlicloudOssBucket) websiteErrorDocument() (string, error) {
	cfg, err := a.fetchWebsite()
	if err != nil || cfg == nil || cfg.ErrorDocument == nil || cfg.ErrorDocument.Key == nil {
		return "", err
	}
	return *cfg.ErrorDocument.Key, nil
}

func (a *mqlAlicloudOssBucket) corsRules() ([]any, error) {
	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketCors(context.Background(), &oss.GetBucketCorsRequest{
		Bucket: &a.Name.Data,
	})
	if err != nil {
		if ossConfigAbsent(err) {
			return []any{}, nil
		}
		return nil, err
	}
	if resp == nil || resp.CORSConfiguration == nil {
		return []any{}, nil
	}

	res := []any{}
	for i, rule := range resp.CORSConfiguration.CORSRules {
		maxAge := int64(0)
		if rule.MaxAgeSeconds != nil {
			maxAge = *rule.MaxAgeSeconds
		}
		// CORS rules carry no id of their own, so they are keyed by position
		// within the bucket's rule list, which is the order the service applies
		// them in.
		resource, err := CreateResource(a.MqlRuntime, "alicloud.oss.bucket.corsRule", map[string]*llx.RawData{
			"__id":           llx.StringData(a.Name.Data + "/cors/" + itoaInt(i)),
			"allowedOrigins": llx.ArrayData(ossStrings(rule.AllowedOrigins), types.String),
			"allowedMethods": llx.ArrayData(ossStrings(rule.AllowedMethods), types.String),
			"allowedHeaders": llx.ArrayData(ossStrings(rule.AllowedHeaders), types.String),
			"exposeHeaders":  llx.ArrayData(ossStrings(rule.ExposeHeaders), types.String),
			"maxAgeSeconds":  llx.IntData(maxAge),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (a *mqlAlicloudOssBucket) replicationRules() ([]any, error) {
	client, err := a.ossClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetBucketReplication(context.Background(), &oss.GetBucketReplicationRequest{
		Bucket: &a.Name.Data,
	})
	if err != nil {
		if ossConfigAbsent(err) {
			return []any{}, nil
		}
		return nil, err
	}
	if resp == nil || resp.ReplicationConfiguration == nil {
		return []any{}, nil
	}

	res := []any{}
	for i, rule := range resp.ReplicationConfiguration.Rules {
		targetBucket, targetLocation := "", ""
		if rule.Destination != nil {
			targetBucket = convert.ToValue(rule.Destination.Bucket)
			targetLocation = convert.ToValue(rule.Destination.Location)
		}
		prefixes := []any{}
		if rule.PrefixSet != nil {
			// the SDK spells the field Prefixs
			prefixes = ossStrings(rule.PrefixSet.Prefixs)
		}
		kmsKeyID := ""
		if rule.EncryptionConfiguration != nil {
			kmsKeyID = convert.ToValue(rule.EncryptionConfiguration.ReplicaKmsKeyID)
		}

		ruleID := convert.ToValue(rule.ID)
		key := ruleID
		if key == "" {
			key = itoaInt(i)
		}
		resource, err := CreateResource(a.MqlRuntime, "alicloud.oss.bucket.replicationRule", map[string]*llx.RawData{
			"__id":                        llx.StringData(a.Name.Data + "/replication/" + key),
			"id":                          llx.StringData(ruleID),
			"targetBucket":                llx.StringData(targetBucket),
			"targetLocation":              llx.StringData(targetLocation),
			"status":                      llx.StringData(convert.ToValue(rule.Status)),
			"action":                      llx.StringData(convert.ToValue(rule.Action)),
			"historicalObjectReplication": llx.StringData(string(rule.HistoricalObjectReplication)),
			"prefixes":                    llx.ArrayData(prefixes, types.String),
			"syncRole":                    llx.StringData(convert.ToValue(rule.SyncRole)),
			"replicaKmsKeyId":             llx.StringData(kmsKeyID),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}
