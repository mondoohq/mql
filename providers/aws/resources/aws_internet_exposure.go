// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// exposure builds the shared network-exposure breakdown for a Neptune instance.
// The public-access flag lives on the instance, while the VPC security groups
// live on its parent cluster, so the open ingress rules are sourced from the
// cluster identified by clusterIdentifier.
func (a *mqlAwsNeptuneInstance) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publiclyAccessible := a.GetPubliclyAccessible()
	if publiclyAccessible.Error != nil {
		return nil, publiclyAccessible.Error
	}
	sgs, err := a.clusterSecurityGroups()
	if err != nil {
		return nil, err
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publiclyAccessible, sgs)
}

// clusterSecurityGroups returns the security groups of the Neptune cluster that
// owns this instance, located among the already-cached clusters by matching the
// instance's clusterIdentifier. It returns nil security groups (rather than an
// error) when the cluster cannot be found, so exposure still resolves.
func (a *mqlAwsNeptuneInstance) clusterSecurityGroups() (*plugin.TValue[[]any], error) {
	clusterIdentifier := a.GetClusterIdentifier()
	if clusterIdentifier.Error != nil {
		return nil, clusterIdentifier.Error
	}
	if clusterIdentifier.Data == "" {
		return nil, nil
	}

	obj, err := CreateResource(a.MqlRuntime, "aws.neptune", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	clusters := obj.(*mqlAwsNeptune).GetClusters()
	if clusters.Error != nil {
		return nil, clusters.Error
	}
	for _, raw := range clusters.Data {
		cluster, ok := raw.(*mqlAwsNeptuneCluster)
		if !ok {
			continue
		}
		id := cluster.GetClusterIdentifier()
		if id.Error != nil {
			return nil, id.Error
		}
		if id.Data == clusterIdentifier.Data {
			return cluster.GetSecurityGroups(), nil
		}
	}
	return nil, nil
}

func (a *mqlAwsSecretsmanagerSecret) isPublic() (bool, error) {
	return resourceIsPublic(a.GetPolicyStatements())
}

// isPublic reports whether the file system policy grants a wildcard principal.
// It routes through resourceIsPublicOrUnknown so that a policy that could not
// be read reports null: a denied DescribeFileSystemPolicy used to collapse
// into an empty statement list and a confident false on a file system that
// grants ClientMount to everyone.
func (a *mqlAwsEfsFilesystem) isPublic() (bool, error) {
	return resourceIsPublicOrUnknown(a.GetPolicyStatements(), &a.IsPublic)
}

func (a *mqlAwsBackupVault) isPublic() (bool, error) {
	return resourceIsPublic(a.GetPolicyStatements())
}

func (a *mqlAwsEsDomain) policyStatements() ([]any, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	return policyStatementsFromString(a.MqlRuntime, arn.Data, a.GetAccessPolicies())
}

// esDomainIsPublic reports whether an Elasticsearch/OpenSearch domain is
// reachable from the internet. A domain is public only when it has a public
// endpoint (it is not deployed inside a VPC) and its access policy grants a
// wildcard principal. VPC domains are unreachable from the internet regardless
// of their access policy.
func esDomainIsPublic(inVPC bool, policyAllowsPublic bool) bool {
	return !inVPC && policyAllowsPublic
}

// isPublic reports whether an Elasticsearch/OpenSearch (es) domain is reachable
// from the internet: it has a public endpoint (it is not deployed inside a VPC)
// and its access policy grants a wildcard principal access that is not scoped by
// a source-restricting condition.
func (a *mqlAwsEsDomain) isPublic() (bool, error) {
	inVPC := a.cacheVpcId != nil && *a.cacheVpcId != ""
	if inVPC {
		return false, nil
	}
	// Not in a VPC (checked above), so public reachability reduces to whether the
	// access policy grants a wildcard principal. esDomainIsPublic encodes the full
	// rule and is covered directly by unit tests.
	return resourceIsPublic(a.GetPolicyStatements())
}

type mqlAwsNeptuneInstanceInternal struct {
	lazyTags
	cacheKmsKeyId          string
	cacheMonitoringRoleArn string
}
