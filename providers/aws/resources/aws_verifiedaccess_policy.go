// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
)

// verifiedAccessPolicy is the access policy of a Verified Access group or
// endpoint. A nil policy with a nil error means the policy could not be read
// and the caller reports the fields as null.
type verifiedAccessPolicy struct {
	document *string
	enabled  *bool
}

// verifiedAccessPolicyCache shares one Get*Policy call between the
// policyDocument and policyEnabled fields.
type verifiedAccessPolicyCache struct {
	policyLock    sync.Mutex
	policyFetched bool
	policy        *verifiedAccessPolicy
}

func (c *verifiedAccessPolicyCache) load(permission string, fetch func() (*verifiedAccessPolicy, error)) (*verifiedAccessPolicy, error) {
	c.policyLock.Lock()
	defer c.policyLock.Unlock()
	if c.policyFetched {
		return c.policy, nil
	}
	policy, err := fetch()
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				c.policyFetched = true
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions(permission))
		}
		return nil, err
	}
	c.policy = policy
	c.policyFetched = true
	return c.policy, nil
}

type mqlAwsVerifiedaccessGroupInternal struct {
	verifiedAccessPolicyCache
}

func (a *mqlAwsVerifiedaccessGroup) fetchPolicy() (*verifiedAccessPolicy, error) {
	return a.load("ec2:GetVerifiedAccessGroupPolicy", func() (*verifiedAccessPolicy, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Ec2(a.Region.Data)
		id := a.VerifiedAccessGroupId.Data
		out, err := svc.GetVerifiedAccessGroupPolicy(context.Background(), &ec2.GetVerifiedAccessGroupPolicyInput{
			VerifiedAccessGroupId: &id,
		})
		if err != nil {
			return nil, err
		}
		return &verifiedAccessPolicy{document: out.PolicyDocument, enabled: out.PolicyEnabled}, nil
	})
}

func (a *mqlAwsVerifiedaccessGroup) policyDocument() (string, error) {
	policy, err := a.fetchPolicy()
	if err != nil {
		return "", err
	}
	if policy == nil || policy.document == nil {
		a.PolicyDocument.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *policy.document, nil
}

func (a *mqlAwsVerifiedaccessGroup) policyEnabled() (bool, error) {
	policy, err := a.fetchPolicy()
	if err != nil {
		return false, err
	}
	if policy == nil || policy.enabled == nil {
		a.PolicyEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *policy.enabled, nil
}

func (a *mqlAwsVerifiedaccessEndpoint) fetchPolicy() (*verifiedAccessPolicy, error) {
	return a.load("ec2:GetVerifiedAccessEndpointPolicy", func() (*verifiedAccessPolicy, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Ec2(a.Region.Data)
		id := a.VerifiedAccessEndpointId.Data
		out, err := svc.GetVerifiedAccessEndpointPolicy(context.Background(), &ec2.GetVerifiedAccessEndpointPolicyInput{
			VerifiedAccessEndpointId: &id,
		})
		if err != nil {
			return nil, err
		}
		return &verifiedAccessPolicy{document: out.PolicyDocument, enabled: out.PolicyEnabled}, nil
	})
}

func (a *mqlAwsVerifiedaccessEndpoint) policyDocument() (string, error) {
	policy, err := a.fetchPolicy()
	if err != nil {
		return "", err
	}
	if policy == nil || policy.document == nil {
		a.PolicyDocument.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *policy.document, nil
}

func (a *mqlAwsVerifiedaccessEndpoint) policyEnabled() (bool, error) {
	policy, err := a.fetchPolicy()
	if err != nil {
		return false, err
	}
	if policy == nil || policy.enabled == nil {
		a.PolicyEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *policy.enabled, nil
}
