// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// cachedResource returns a resource already materialized under this id, or nil.
//
// NewResource runs a resource's init *before* it consults the runtime cache --
// it has to, because the cache key is the resolved resource's MqlID, which for
// a resource whose identity is computed during init is not knowable in advance.
// An init that fetches unconditionally therefore pays once per referring
// resource and then has its result discarded in favour of the cached instance:
// four EC2 instances in one VPC cost four DescribeVpcs calls for the one VPC,
// and the fan-in on aws.iam.role reaches 94 referring call sites.
//
// The cost is worst on a resource that is also a discovery target. cnspec
// evaluates every policy's filter against every asset, and both filters and
// data queries compile to a bare resource, so a scanned asset resolves its own
// resource once per query rather than once per asset. On an EFS file system
// that was a dozen concurrent DescribeFileSystems calls for the one file
// system, enough to exhaust the service's quota and report the asset's own id,
// tags and creation time as null.
//
// The opening exists for callers that already supply the id: a typed reference
// passes it, and an asset init derives it from the scanned asset, so the cache
// key is known up front and can be checked before spending a call. During a
// scan the hit rate is near total, because discovery builds each asset by
// walking the service's list and AWS shares one resource cache across an
// account and the assets discovered beneath it (see WithParentConnectionId in
// discovery_conversion.go).
//
// A key that does not match how the resource computes its own MqlID simply
// misses and leaves the caller on its existing path, so the probe can never
// return the wrong resource.
func cachedResource(runtime *plugin.Runtime, resourceName, id string) plugin.Resource {
	if id == "" || runtime == nil || runtime.Resources == nil {
		return nil
	}
	if res, ok := runtime.Resources.Get(resourceName + "\x00" + id); ok {
		return res
	}
	return nil
}

// cachedByArn is cachedResource for the resources that key their __id on the
// ARN, which is most of them.
//
// Same shape as the checks already in aws_kms.go, aws_vpc.go and aws_ec2.go;
// this only gives them one name.
func cachedByArn(runtime *plugin.Runtime, resourceName, arn string) plugin.Resource {
	return cachedResource(runtime, resourceName, arn)
}

// cachedArgByArn is cachedByArn for the common init shape, reading the ARN out
// of args itself. Returns nil when there is no usable "arn" argument, which
// leaves the caller on its existing path.
func cachedArgByArn(runtime *plugin.Runtime, resourceName string, args map[string]*llx.RawData) plugin.Resource {
	return cachedArg(runtime, resourceName, args, "arn")
}

// cachedArg is cachedResource reading the cache key out of the named argument,
// for the resources that key their __id on something other than the ARN.
// Returns nil when that argument is absent or is not a string, which leaves the
// caller on its existing path.
func cachedArg(runtime *plugin.Runtime, resourceName string, args map[string]*llx.RawData, key string) plugin.Resource {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	id, ok := raw.Value.(string)
	if !ok {
		return nil
	}
	return cachedResource(runtime, resourceName, id)
}
