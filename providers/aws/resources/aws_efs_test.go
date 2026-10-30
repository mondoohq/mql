// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
)

// awsAPIErr builds the error shape an SDK call actually returns: a service API
// error wrapped in the smithy response error that carries the HTTP status,
// wrapped again in the AWS response error that carries the request id. The
// classifiers under test walk that chain, so a bare smithy error would not
// exercise them.
func awsAPIErr(status int, code, message string) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &nethttp.Response{StatusCode: status}},
			Err:      &smithy.GenericAPIError{Code: code, Message: message},
		},
		RequestID: "0123456789",
	}
}

// efsAccessDenied is the response a role denied a single elasticfilesystem
// permission gets back.
func efsAccessDenied(action string) error {
	return awsAPIErr(403, "AccessDeniedException",
		"User is not authorized to perform: "+action)
}

type efsStub struct {
	out any
	err error
}

// stubEfsConn returns a connection whose EFS clients answer from stubs instead
// of the network. The middleware short-circuits at the Initialize step, before
// serialization, signing, and transport, so no credentials are needed and the
// stubbed value is returned as the typed SDK output struct.
func stubEfsConn(t *testing.T, stubs map[string]efsStub) *connection.AwsConnection {
	t.Helper()
	apiOption := func(s *middleware.Stack) error {
		return s.Initialize.Add(middleware.InitializeMiddlewareFunc("mqlEfsTestStub",
			func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
				middleware.InitializeOutput, middleware.Metadata, error,
			) {
				key := fmt.Sprintf("%T", in.Parameters)
				stub, ok := stubs[key]
				if !ok {
					return middleware.InitializeOutput{}, middleware.Metadata{},
						fmt.Errorf("test called unstubbed EFS operation %s", key)
				}
				if stub.err != nil {
					return middleware.InitializeOutput{}, middleware.Metadata{}, stub.err
				}
				return middleware.InitializeOutput{Result: stub.out}, middleware.Metadata{}, nil
			}), middleware.Before)
	}
	return connection.NewTestConnection(aws.Config{
		Region:     "us-east-1",
		APIOptions: []func(*middleware.Stack) error{apiOption},
	})
}

func stubbedEfsFilesystem(t *testing.T, stubs map[string]efsStub) *mqlAwsEfsFilesystem {
	t.Helper()
	rt := testRuntime()
	rt.Connection = stubEfsConn(t, stubs)
	return &mqlAwsEfsFilesystem{
		MqlRuntime: rt,
		Id:         setString("fs-0123456789abcdef0"),
		Region:     setString("us-east-1"),
		Arn:        setString("arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123456789abcdef0"),
	}
}

// A file system policy that grants ClientMount to every principal. This is the
// live shape that reported isPublic:false under a denied read.
const efsPublicPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "public-mount",
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": "elasticfilesystem:ClientMount",
      "Resource": "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123456789abcdef0"
    }
  ]
}`

// PolicyNotFound is what establishes that a file system has no policy. Nothing
// else may: a denial and a transport failure both leave the policy unknown,
// and folding either one in is what made a public file system read as private.
func TestEfsPolicyNotFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "no policy on the file system",
			err:  awsAPIErr(404, "PolicyNotFound", "Policy not found for file system fs-0123456789abcdef0"),
			want: true,
		},
		{
			name: "denied DescribeFileSystemPolicy is not an absent policy",
			err:  efsAccessDenied("elasticfilesystem:DescribeFileSystemPolicy"),
			want: false,
		},
		{
			name: "a 400 access denial is not an absent policy",
			err:  awsAPIErr(400, "AccessDenied", "not authorized"),
			want: false,
		},
		{
			name: "a server error is not an absent policy",
			err:  awsAPIErr(500, "InternalServerError", "internal error"),
			want: false,
		},
		{
			name: "a transport error is not an absent policy",
			err:  errors.New("dial tcp: lookup elasticfilesystem.us-east-1.amazonaws.com: no such host"),
			want: false,
		},
		{
			name: "nil is not a match",
			err:  nil,
			want: false,
		},
		{
			name: "wrapped 404 still matches",
			err: fmt.Errorf("describe policy: %w",
				awsAPIErr(404, "PolicyNotFound", "Policy not found")),
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, efsPolicyNotFound(tc.err))
		})
	}
}

// The critical case. A role denied only DescribeFileSystemPolicy must not
// produce the same reading as a file system that has no policy: the policy
// errors, the statements error, and isPublic errors rather than reporting a
// world-readable file system as private.
func TestEfsDeniedPolicyDoesNotReportNotPublic(t *testing.T) {
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeFileSystemPolicyInput": {
			err: efsAccessDenied("elasticfilesystem:DescribeFileSystemPolicy"),
		},
	})

	policy := fs.GetFileSystemPolicy()
	require.Error(t, policy.Error, "a denied policy read must not be reported as a value")
	assert.Equal(t, "", policy.Data)
	assert.True(t, policy.State&plugin.StateIsNull != 0, "the denied field must read as null, not as the empty string")

	statements := fs.GetPolicyStatements()
	require.Error(t, statements.Error, "statements parsed from an unread policy must not be an empty list")

	isPublic := fs.GetIsPublic()
	require.Error(t, isPublic.Error, "isPublic must not report false when the policy was refused")
	assert.True(t, isPublic.State&plugin.StateIsNull != 0, "isPublic must read as null, not as false")
}

// The other half: a file system that genuinely has no policy still reports a
// real, confident false. The 404 fix must not regress this into null.
func TestEfsAbsentPolicyReportsNotPublic(t *testing.T) {
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeFileSystemPolicyInput": {
			err: awsAPIErr(404, "PolicyNotFound", "Policy not found for file system fs-0123456789abcdef0"),
		},
	})

	policy := fs.GetFileSystemPolicy()
	require.NoError(t, policy.Error)
	assert.Equal(t, "", policy.Data)

	statements := fs.GetPolicyStatements()
	require.NoError(t, statements.Error)
	assert.Equal(t, []any{}, statements.Data)

	isPublic := fs.GetIsPublic()
	require.NoError(t, isPublic.Error)
	assert.False(t, isPublic.Data, "a file system with no policy is measurably not public")
}

// A file system whose policy really does grant a wildcard principal reports
// true, so the two failure-free readings stay distinguishable from each other
// as well as from the denial.
func TestEfsWildcardPolicyReportsPublic(t *testing.T) {
	policyDoc := efsPublicPolicy
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeFileSystemPolicyInput": {
			out: &efs.DescribeFileSystemPolicyOutput{
				FileSystemId: aws.String("fs-0123456789abcdef0"),
				Policy:       &policyDoc,
			},
		},
	})

	statements := fs.GetPolicyStatements()
	require.NoError(t, statements.Error)
	require.Len(t, statements.Data, 1)

	isPublic := fs.GetIsPublic()
	require.NoError(t, isPublic.Error)
	assert.True(t, isPublic.Data)
}

// A denied DescribeMountTargets must not return the partial (empty) slice: a
// mountTargets.all(...) check would then pass on a file system whose mount
// targets nobody enumerated.
func TestEfsDeniedMountTargetsIsNotAnEmptyList(t *testing.T) {
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeMountTargetsInput": {
			err: efsAccessDenied("elasticfilesystem:DescribeMountTargets"),
		},
	})

	res, err := fs.mountTargets()
	require.Error(t, err, "a denied mount target listing must not be reported as a complete list")
	assert.Nil(t, res)
}

// A denied DescribeAccessPoints must not return the partial (empty) slice.
func TestEfsDeniedAccessPointsIsNotAnEmptyList(t *testing.T) {
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeAccessPointsInput": {
			err: efsAccessDenied("elasticfilesystem:DescribeAccessPoints"),
		},
	})

	res, err := fs.accessPoints()
	require.Error(t, err, "a denied access point listing must not be reported as a complete list")
	assert.Nil(t, res)
}

// A mount target whose security groups could not be read must say so. The
// listing itself still succeeds: one unreadable mount target must not erase
// the others.
func TestEfsMountTargetSecurityGroupsDeniedIsNotAnEmptyList(t *testing.T) {
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeMountTargetsInput": {
			out: &efs.DescribeMountTargetsOutput{
				MountTargets: []efstypes.MountTargetDescription{{
					MountTargetId:        aws.String("fsmt-0123456789abcdef0"),
					FileSystemId:         aws.String("fs-0123456789abcdef0"),
					SubnetId:             aws.String("subnet-0123456789abcdef0"),
					NetworkInterfaceId:   aws.String("eni-0123456789abcdef0"),
					AvailabilityZoneName: aws.String("us-east-1a"),
					IpAddress:            aws.String("10.0.1.10"),
					LifeCycleState:       efstypes.LifeCycleStateAvailable,
				}},
			},
		},
		"*efs.DescribeMountTargetSecurityGroupsInput": {
			err: efsAccessDenied("elasticfilesystem:DescribeMountTargetSecurityGroups"),
		},
	})

	res, err := fs.mountTargets()
	require.NoError(t, err, "one unreadable security group list must not fail the whole listing")
	require.Len(t, res, 1)

	mt := res[0].(*mqlAwsEfsMountTarget)
	sgs, sgErr := mt.securityGroups()
	require.Error(t, sgErr, "a denied security group read must not read as no security groups")
	assert.Nil(t, sgs)
}

// EFS attaches at least one security group to every mount target, so a mount
// target that carries no cached ids was never read and must not report an
// empty list.
func TestEfsMountTargetSecurityGroupsUnreadIsAnError(t *testing.T) {
	mt := &mqlAwsEfsMountTarget{
		MqlRuntime:    testRuntime(),
		MountTargetId: setString("fsmt-0123456789abcdef0"),
		Region:        setString("us-east-1"),
	}
	sgs, err := mt.securityGroups()
	require.Error(t, err)
	assert.Nil(t, sgs)
}

// A successful listing caches every returned group id, including the second
// and later ones.
func TestEfsMountTargetSecurityGroupsAreCached(t *testing.T) {
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeMountTargetsInput": {
			out: &efs.DescribeMountTargetsOutput{
				MountTargets: []efstypes.MountTargetDescription{{
					MountTargetId:        aws.String("fsmt-0123456789abcdef0"),
					FileSystemId:         aws.String("fs-0123456789abcdef0"),
					AvailabilityZoneName: aws.String("us-east-1a"),
					LifeCycleState:       efstypes.LifeCycleStateAvailable,
				}},
			},
		},
		"*efs.DescribeMountTargetSecurityGroupsInput": {
			out: &efs.DescribeMountTargetSecurityGroupsOutput{
				SecurityGroups: []string{"sg-0123456789abcdef0", "sg-0fedcba9876543210"},
			},
		},
	})

	res, err := fs.mountTargets()
	require.NoError(t, err)
	require.Len(t, res, 1)

	mt := res[0].(*mqlAwsEfsMountTarget)
	require.NoError(t, mt.cacheSecurityGroupsErr)
	assert.Equal(t, []string{"sg-0123456789abcdef0", "sg-0fedcba9876543210"}, mt.cacheSecurityGroupIDs)
}

// A denied lifecycle read must not read like a file system with no lifecycle
// policy, and the 404 that establishes there is none must still read as null.
func TestEfsLifecycleConfigurationDeniedIsNotNull(t *testing.T) {
	denied := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeLifecycleConfigurationInput": {
			err: efsAccessDenied("elasticfilesystem:DescribeLifecycleConfiguration"),
		},
	})
	res, err := denied.lifecycleConfiguration()
	require.Error(t, err, "a denied lifecycle read must not read as no lifecycle policy")
	assert.Nil(t, res)

	absent := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeLifecycleConfigurationInput": {
			out: &efs.DescribeLifecycleConfigurationOutput{},
		},
	})
	res, err = absent.lifecycleConfiguration()
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.True(t, absent.LifecycleConfiguration.State&plugin.StateIsNull != 0)
}

// A denied replication read must not read like an unreplicated file system.
func TestEfsReplicationConfigurationDeniedIsNotNull(t *testing.T) {
	denied := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeReplicationConfigurationsInput": {
			err: efsAccessDenied("elasticfilesystem:DescribeReplicationConfigurations"),
		},
	})
	res, err := denied.replicationConfiguration()
	require.Error(t, err, "a denied replication read must not read as unreplicated")
	assert.Nil(t, res)

	absent := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeReplicationConfigurationsInput": {
			out: &efs.DescribeReplicationConfigurationsOutput{},
		},
	})
	res, err = absent.replicationConfiguration()
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.True(t, absent.ReplicationConfiguration.State&plugin.StateIsNull != 0)
}

// The deprecated dict promises a BackupPolicy object and nothing else. The SDK
// output also carries ResultMetadata, which describes the API call rather than
// the file system.
func TestEfsBackupPolicyDictShape(t *testing.T) {
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeBackupPolicyInput": {
			out: &efs.DescribeBackupPolicyOutput{
				BackupPolicy: &efstypes.BackupPolicy{Status: efstypes.StatusEnabled},
			},
		},
	})

	dict, err := fs.backupPolicy()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"BackupPolicy": map[string]any{"Status": "ENABLED"},
	}, dict)
}

// A denied backup policy read still errors, and the dict is not a value.
func TestEfsBackupPolicyDeniedIsAnError(t *testing.T) {
	fs := stubbedEfsFilesystem(t, map[string]efsStub{
		"*efs.DescribeBackupPolicyInput": {
			err: efsAccessDenied("elasticfilesystem:DescribeBackupPolicy"),
		},
	})

	dict, err := fs.backupPolicy()
	require.Error(t, err)
	assert.Nil(t, dict)
}

// The three-way distinction the isPublic verdict rests on, exercised directly
// on the helper so that the null-without-error case is covered too: an empty
// statement list is a measurement (not public), a null one is the absence of a
// measurement, and only the first may produce false.
func TestEfsIsPublicSeparatesNullStatementsFromEmptyOnes(t *testing.T) {
	t.Run("null statements report null, not false", func(t *testing.T) {
		fs := &mqlAwsEfsFilesystem{MqlRuntime: testRuntime()}
		fs.PolicyStatements = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}

		got, err := fs.isPublic()
		require.NoError(t, err)
		assert.False(t, got)
		assert.True(t, fs.IsPublic.State&plugin.StateIsNull != 0,
			"an unread policy must leave isPublic null rather than false")
	})

	t.Run("an empty statement list reports a real false", func(t *testing.T) {
		fs := &mqlAwsEfsFilesystem{MqlRuntime: testRuntime()}
		fs.PolicyStatements = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}

		got, err := fs.isPublic()
		require.NoError(t, err)
		assert.False(t, got)
		assert.True(t, fs.IsPublic.State&plugin.StateIsNull == 0,
			"a file system with no policy statements is measurably not public")
	})

	t.Run("a statement error propagates", func(t *testing.T) {
		fs := &mqlAwsEfsFilesystem{MqlRuntime: testRuntime()}
		fs.PolicyStatements = plugin.TValue[[]any]{
			State: plugin.StateIsSet | plugin.StateIsNull,
			Error: efsAccessDenied("elasticfilesystem:DescribeFileSystemPolicy"),
		}

		_, err := fs.isPublic()
		require.Error(t, err)
	})
}
