// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"google.golang.org/api/storage/v1"
)

// The bucket configuration dicts below are assembled field by field instead of
// being re-marshaled from the SDK struct.
//
// Every bool on these types is tagged `json:"...,omitempty"`, and the generated
// MarshalJSON only overrides omitempty for fields named in ForceSendFields,
// which a decoded response never populates. Re-marshaling therefore turns
// {"enabled": false} into {}, so a bucket WITHOUT uniform bucket-level access
// reads as null rather than false and
// `buckets.where(uniformBucketLevelAccess["enabled"] == false)` matches nothing:
// exactly the buckets an audit is looking for are the ones it cannot find.
//
// Bools are written unconditionally, because false is an answer. Strings,
// counters, and nested messages keep the API's own omit-when-empty behavior, so
// an absent value stays absent rather than becoming a zero that reads as
// measured fact.

// setIfNotEmpty writes a string under key only when it carries a value.
func setIfNotEmpty(dict map[string]any, key, value string) {
	if value != "" {
		dict[key] = value
	}
}

// bucketIamConfigurationDict builds the bucket's iamConfiguration dict.
func bucketIamConfigurationDict(c *storage.BucketIamConfiguration) map[string]any {
	if c == nil {
		return nil
	}
	res := map[string]any{}
	setIfNotEmpty(res, "publicAccessPrevention", c.PublicAccessPrevention)
	if ubla := bucketUniformBucketLevelAccessDict(c.UniformBucketLevelAccess); ubla != nil {
		res["uniformBucketLevelAccess"] = ubla
	}
	if c.BucketPolicyOnly != nil {
		bpo := map[string]any{"enabled": c.BucketPolicyOnly.Enabled}
		setIfNotEmpty(bpo, "lockedTime", c.BucketPolicyOnly.LockedTime)
		res["bucketPolicyOnly"] = bpo
	}
	return res
}

// bucketUniformBucketLevelAccessDict builds the uniformBucketLevelAccess dict.
func bucketUniformBucketLevelAccessDict(u *storage.BucketIamConfigurationUniformBucketLevelAccess) map[string]any {
	if u == nil {
		return nil
	}
	res := map[string]any{"enabled": u.Enabled}
	setIfNotEmpty(res, "lockedTime", u.LockedTime)
	return res
}

// bucketRetentionPolicyDict builds the retentionPolicy dict. retentionPeriod
// keeps the API's string encoding, which is how the field has always been
// reported and what existing content compares against.
func bucketRetentionPolicyDict(rp *storage.BucketRetentionPolicy) map[string]any {
	if rp == nil {
		return nil
	}
	res := map[string]any{"isLocked": rp.IsLocked}
	setIfNotEmpty(res, "effectiveTime", rp.EffectiveTime)
	if rp.RetentionPeriod != 0 {
		res["retentionPeriod"] = strconv.FormatInt(rp.RetentionPeriod, 10)
	}
	return res
}

// bucketAutoclassDict builds the autoclass dict.
func bucketAutoclassDict(a *storage.BucketAutoclass) map[string]any {
	if a == nil {
		return nil
	}
	res := map[string]any{"enabled": a.Enabled}
	setIfNotEmpty(res, "terminalStorageClass", a.TerminalStorageClass)
	setIfNotEmpty(res, "terminalStorageClassUpdateTime", a.TerminalStorageClassUpdateTime)
	setIfNotEmpty(res, "toggleTime", a.ToggleTime)
	return res
}

// bucketHierarchicalNamespaceDict builds the hierarchicalNamespace dict.
func bucketHierarchicalNamespaceDict(h *storage.BucketHierarchicalNamespace) map[string]any {
	if h == nil {
		return nil
	}
	return map[string]any{"enabled": h.Enabled}
}

// bucketBillingDict builds the billing dict.
func bucketBillingDict(b *storage.BucketBilling) map[string]any {
	if b == nil {
		return nil
	}
	return map[string]any{"requesterPays": b.RequesterPays}
}

// bucketIpFilterDict builds the ipFilter dict.
func bucketIpFilterDict(f *storage.BucketIpFilter) map[string]any {
	if f == nil {
		return nil
	}
	res := map[string]any{
		"allowAllServiceAgentAccess": f.AllowAllServiceAgentAccess,
		"allowCrossOrgVpcs":          f.AllowCrossOrgVpcs,
	}
	setIfNotEmpty(res, "mode", f.Mode)
	if f.PublicNetworkSource != nil {
		public := map[string]any{}
		if len(f.PublicNetworkSource.AllowedIpCidrRanges) > 0 {
			public["allowedIpCidrRanges"] = convert.SliceAnyToInterface(f.PublicNetworkSource.AllowedIpCidrRanges)
		}
		res["publicNetworkSource"] = public
	}
	if len(f.VpcNetworkSources) > 0 {
		sources := make([]any, 0, len(f.VpcNetworkSources))
		for _, v := range f.VpcNetworkSources {
			if v == nil {
				continue
			}
			source := map[string]any{}
			setIfNotEmpty(source, "network", v.Network)
			if len(v.AllowedIpCidrRanges) > 0 {
				source["allowedIpCidrRanges"] = convert.SliceAnyToInterface(v.AllowedIpCidrRanges)
			}
			sources = append(sources, source)
		}
		res["vpcNetworkSources"] = sources
	}
	return res
}
