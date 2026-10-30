// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// instance() returns null when the application's parent-instance pointer wasn't
// cached (e.g. the application was constructed via NewResource rather than
// listed under an instance).
func TestIdentitycenterApplicationInstanceNullWhenCacheEmpty(t *testing.T) {
	a := &mqlAwsIdentitycenterApplication{}
	got, err := a.instance()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, a.Instance.IsNull())
	assert.True(t, a.Instance.IsSet())
}

// fakeListInstances answers ListInstances per region scope and records the
// scopes it was asked for.
type fakeListInstances struct {
	byScope map[ssotypes.RegionScope][]ssotypes.InstanceMetadata
	errs    map[ssotypes.RegionScope]error
	// pages splits each scope's answer into pages of this size (0: one page)
	pages  int
	scopes []ssotypes.RegionScope
}

func (f *fakeListInstances) ListInstances(_ context.Context, in *ssoadmin.ListInstancesInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	f.scopes = append(f.scopes, in.RegionScope)
	if err := f.errs[in.RegionScope]; err != nil {
		return nil, err
	}
	all := f.byScope[in.RegionScope]
	start := 0
	if in.NextToken != nil {
		for i, inst := range all {
			if aws.ToString(inst.InstanceArn) == *in.NextToken {
				start = i
			}
		}
	}
	end := len(all)
	if f.pages > 0 && start+f.pages < end {
		end = start + f.pages
	}
	out := &ssoadmin.ListInstancesOutput{Instances: all[start:end]}
	if end < len(all) {
		out.NextToken = all[end].InstanceArn
	}
	return out, nil
}

// Measured: `aws sso-admin list-instances` on 2026-10-30 from a member account
// whose default region is us-west-2. The default (CURRENT_REGION) scope
// returned no instances; --region-scope ALL_REGIONS returned the organization
// instance with PrimaryRegion us-east-1. ARN, identity store and account ids
// are replaced.
var measuredUsEast1Instance = ssotypes.InstanceMetadata{
	InstanceArn:     aws.String("arn:aws:sso:::instance/ssoins-0000000000000000"),
	IdentityStoreId: aws.String("d-0000000000"),
	OwnerAccountId:  aws.String("000000000000"),
	Status:          ssotypes.InstanceStatusActive,
	PrimaryRegion:   aws.String("us-east-1"),
	Regions: []ssotypes.RegionMetadata{{
		RegionName:      aws.String("us-east-1"),
		Status:          ssotypes.RegionStatusActive,
		IsPrimaryRegion: true,
	}},
}

func TestListIdentitycenterInstancesAllRegions(t *testing.T) {
	f := &fakeListInstances{byScope: map[ssotypes.RegionScope][]ssotypes.InstanceMetadata{
		"":                             nil,
		ssotypes.RegionScopeAllRegions: {measuredUsEast1Instance},
	}}
	got, err := listIdentitycenterInstances(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "us-east-1", aws.ToString(got[0].PrimaryRegion))
	assert.Equal(t, []ssotypes.RegionScope{ssotypes.RegionScopeAllRegions}, f.scopes)
}

// Synthetic: pagination across the ALL_REGIONS walk; no target had more than
// one instance.
func TestListIdentitycenterInstancesPaginates(t *testing.T) {
	second := measuredUsEast1Instance
	second.InstanceArn = aws.String("arn:aws:sso:::instance/ssoins-1111111111111111")
	second.PrimaryRegion = aws.String("eu-central-1")
	f := &fakeListInstances{
		byScope: map[ssotypes.RegionScope][]ssotypes.InstanceMetadata{
			ssotypes.RegionScopeAllRegions: {measuredUsEast1Instance, second},
		},
		pages: 1,
	}
	got, err := listIdentitycenterInstances(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "eu-central-1", aws.ToString(got[1].PrimaryRegion))
}

// Synthetic: an endpoint that rejects RegionScope as invalid input; no target
// showed this (GovCloud and China were not reachable).
func TestListIdentitycenterInstancesFallsBackWhenScopeRejected(t *testing.T) {
	f := &fakeListInstances{
		byScope: map[ssotypes.RegionScope][]ssotypes.InstanceMetadata{
			"": {measuredUsEast1Instance},
		},
		errs: map[ssotypes.RegionScope]error{
			ssotypes.RegionScopeAllRegions: &ssotypes.ValidationException{Message: aws.String("unknown parameter regionScope")},
		},
	}
	got, err := listIdentitycenterInstances(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, []ssotypes.RegionScope{ssotypes.RegionScopeAllRegions, ""}, f.scopes)
}

// Synthetic: a denial must surface to the caller, not trigger a second call
// that would mask it.
func TestListIdentitycenterInstancesDoesNotRetryDenied(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}
	f := &fakeListInstances{errs: map[ssotypes.RegionScope]error{
		ssotypes.RegionScopeAllRegions: denied,
	}}
	_, err := listIdentitycenterInstances(context.Background(), f)
	require.Error(t, err)
	assert.Equal(t, []ssotypes.RegionScope{ssotypes.RegionScopeAllRegions}, f.scopes)
}

func TestIsRegionScopeUnsupported(t *testing.T) {
	// Synthetic: error codes an endpoint answers with for a parameter it does not know.
	assert.True(t, isRegionScopeUnsupported(&ssotypes.ValidationException{Message: aws.String("bad")}))
	assert.True(t, isRegionScopeUnsupported(&smithy.GenericAPIError{Code: "SerializationException"}))
	// Synthetic: refusals and transport failures are not a missing parameter.
	assert.False(t, isRegionScopeUnsupported(&ssotypes.AccessDeniedException{Message: aws.String("denied")}))
	assert.False(t, isRegionScopeUnsupported(&ssotypes.ThrottlingException{Message: aws.String("slow down")}))
	assert.False(t, isRegionScopeUnsupported(errors.New("dial tcp: connection refused")))
}
