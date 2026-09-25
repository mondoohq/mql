// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	nethttp "net/http"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	ecrpublic_types "github.com/aws/aws-sdk-go-v2/service/ecrpublic/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestEcrImageArn(t *testing.T) {
	tests := []struct {
		name     string
		info     ImageInfo
		expected string
	}{
		{
			name: "private image is regional and uses the ecr service",
			info: ImageInfo{
				Region:     "us-west-2",
				RegistryId: "123456789012",
				RepoName:   "my-repo",
				Digest:     "sha256:abc",
			},
			expected: "arn:aws:ecr:us-west-2:123456789012:image/my-repo/sha256:abc",
		},
		{
			name: "public image uses the ecr-public service and carries no region",
			info: ImageInfo{
				Public:     true,
				Region:     "us-east-1",
				RegistryId: "123456789012",
				RepoName:   "my-repo",
				Digest:     "sha256:abc",
			},
			expected: "arn:aws:ecr-public::123456789012:image/my-repo/sha256:abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ecrImageArn(tc.info))
		})
	}
}

func TestEcrRepositoryArn(t *testing.T) {
	tests := []struct {
		name       string
		public     bool
		region     string
		registryId string
		repoName   string
		expected   string
	}{
		{
			name:       "private repository is regional",
			region:     "eu-central-1",
			registryId: "123456789012",
			repoName:   "my-repo",
			expected:   "arn:aws:ecr:eu-central-1:123456789012:repository/my-repo",
		},
		{
			// The public shape is what initAwsEcrRepository parses to route the
			// lookup at ecrpublic; a regional "ecr" ARN never matches, which is
			// why aws.ecr.image.repository was null for every public image.
			name:       "public repository names ecr-public and drops the region",
			public:     true,
			region:     "us-east-1",
			registryId: "123456789012",
			repoName:   "my-repo",
			expected:   "arn:aws:ecr-public::123456789012:repository/my-repo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ecrRepositoryArn(tc.public, tc.region, tc.registryId, tc.repoName))
		})
	}
}

func TestEcrEvaluationTime(t *testing.T) {
	epoch := time.Unix(0, 0)
	real := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	t.Run("nil stays nil", func(t *testing.T) {
		assert.Nil(t, ecrEvaluationTime(nil))
	})

	t.Run("unix epoch reads as absent", func(t *testing.T) {
		// ECR returns epoch 0 for a lifecycle policy it has never evaluated.
		// Forwarding it renders as a 1969 date and makes lastEvaluatedAt == null
		// false, so the never-evaluated policy looks evaluated.
		assert.Nil(t, ecrEvaluationTime(&epoch))
	})

	t.Run("epoch in a non-UTC location reads as absent", func(t *testing.T) {
		// AWS reported this as 1969-12-31T16:00:00-08:00; the instant, not the
		// rendered date, is what identifies the sentinel.
		pacific := time.FixedZone("PST", -8*60*60)
		local := epoch.In(pacific)
		assert.Nil(t, ecrEvaluationTime(&local))
	})

	t.Run("go zero time reads as absent", func(t *testing.T) {
		var zero time.Time
		assert.Nil(t, ecrEvaluationTime(&zero))
	})

	t.Run("a real evaluation time is preserved", func(t *testing.T) {
		got := ecrEvaluationTime(&real)
		require.NotNil(t, got)
		assert.Equal(t, real, *got)
	})
}

func TestEcrReplicationConfigurationToDict(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	t.Run("nil configuration yields nil", func(t *testing.T) {
		assert.Nil(t, ecrReplicationConfigurationToDict(nil))
	})

	t.Run("keys match the documented lowercase names", func(t *testing.T) {
		cfg := &ecrtypes.ReplicationConfiguration{
			Rules: []ecrtypes.ReplicationRule{
				{
					Destinations: []ecrtypes.ReplicationDestination{
						{Region: strPtr("us-west-2"), RegistryId: strPtr("123456789012")},
					},
					RepositoryFilters: []ecrtypes.RepositoryFilter{
						{Filter: strPtr("prod-"), FilterType: ecrtypes.RepositoryFilterTypePrefixMatch},
					},
				},
			},
		}

		got := ecrReplicationConfigurationToDict(cfg)
		require.NotNil(t, got)

		// convert.JsonToDict over the untagged SDK struct emitted "Rules";
		// replicationConfiguration["rules"] was null for every registry.
		assert.NotContains(t, got, "Rules")

		rules, ok := got["rules"].([]any)
		require.True(t, ok, "rules must be a list")
		require.Len(t, rules, 1)

		rule, ok := rules[0].(map[string]any)
		require.True(t, ok)
		assert.NotContains(t, rule, "Destinations")
		assert.NotContains(t, rule, "RepositoryFilters")

		destinations, ok := rule["destinations"].([]any)
		require.True(t, ok, "destinations must be a list")
		require.Len(t, destinations, 1)
		assert.Equal(t, map[string]any{
			"region":     "us-west-2",
			"registryId": "123456789012",
		}, destinations[0])

		filters, ok := rule["repositoryFilters"].([]any)
		require.True(t, ok, "repositoryFilters must be a list")
		require.Len(t, filters, 1)
		assert.Equal(t, map[string]any{
			"filter":     "prod-",
			"filterType": "PREFIX_MATCH",
		}, filters[0])
	})

	t.Run("zero values are reported, not dropped", func(t *testing.T) {
		// A rule with no filters replicates everything, and a nil string is an
		// empty value rather than a missing key. Omitting either would make a
		// query for the key read null and quietly skip the rule.
		cfg := &ecrtypes.ReplicationConfiguration{
			Rules: []ecrtypes.ReplicationRule{
				{
					Destinations: []ecrtypes.ReplicationDestination{
						{Region: nil, RegistryId: strPtr("")},
					},
				},
			},
		}

		got := ecrReplicationConfigurationToDict(cfg)
		rules := got["rules"].([]any)
		require.Len(t, rules, 1)
		rule := rules[0].(map[string]any)

		filters, ok := rule["repositoryFilters"]
		require.True(t, ok, "repositoryFilters key must be present even with no filters")
		assert.Equal(t, []any{}, filters)

		destinations := rule["destinations"].([]any)
		require.Len(t, destinations, 1)
		assert.Equal(t, map[string]any{
			"region":     "",
			"registryId": "",
		}, destinations[0])
	})

	t.Run("a registry with no rules still reports the rules key", func(t *testing.T) {
		got := ecrReplicationConfigurationToDict(&ecrtypes.ReplicationConfiguration{})
		require.NotNil(t, got)
		assert.Equal(t, []any{}, got["rules"])
	})
}

// A denied policy read must not be reported as "grants nothing":
// policyStatements carries the denial instead of collapsing it to an empty
// list.
func TestEcrRepositoryPolicyStatementsUnreadable(t *testing.T) {
	t.Run("denied policy yields the denial", func(t *testing.T) {
		repo := &mqlAwsEcrRepository{}
		denied := classifyAwsError(awsAPIError(400, "AccessDeniedException", "not authorized to perform ecr:GetRepositoryPolicy"), "ecr:GetRepositoryPolicy")
		repo.Policy = plugin.TValue[any]{Error: denied, State: plugin.StateIsSet}

		_, err := repo.policyStatements()
		require.ErrorIs(t, err, llx.ErrForbidden)
	})

	t.Run("policy read and absent yields an empty statement list", func(t *testing.T) {
		repo := &mqlAwsEcrRepository{}
		// The repository genuinely carries no policy: the read succeeded.
		repo.Policy = plugin.TValue[any]{State: plugin.StateIsSet | plugin.StateIsNull}

		got, err := repo.policyStatements()
		require.NoError(t, err)
		assert.Equal(t, []any{}, got)
		assert.False(t, repo.PolicyStatements.IsNull(),
			"a policy that was read and found absent is a measured empty list")
	})
}

func TestEcrRepositoryIsPublicUnknownWhenPolicyUnread(t *testing.T) {
	t.Run("null statement list reports isPublic as null, not false", func(t *testing.T) {
		repo := &mqlAwsEcrRepository{}
		repo.PolicyStatements = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}

		_, err := repo.isPublic()
		require.NoError(t, err)
		assert.True(t, repo.IsPublic.IsNull(),
			"a repository whose policy could not be read must not be reported as not-public")
	})

	t.Run("empty statement list reports isPublic as false", func(t *testing.T) {
		repo := &mqlAwsEcrRepository{}
		repo.PolicyStatements = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}

		got, err := repo.isPublic()
		require.NoError(t, err)
		assert.False(t, got)
		assert.False(t, repo.IsPublic.IsNull(),
			"a policy that was read and grants nothing is a measured false")
	})

	t.Run("the unread and the not-public cases are distinguishable", func(t *testing.T) {
		unread := &mqlAwsEcrRepository{}
		unread.PolicyStatements = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		_, err := unread.isPublic()
		require.NoError(t, err)

		notPublic := &mqlAwsEcrRepository{}
		notPublic.PolicyStatements = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
		_, err = notPublic.isPublic()
		require.NoError(t, err)

		assert.NotEqual(t, notPublic.IsPublic.IsNull(), unread.IsPublic.IsNull(),
			"an unread policy and a policy that grants nothing must not render alike")
	})
}

// ecrDeniedErr is the 403 shape Is400AccessDeniedError matches: the repository
// may well carry a policy, the scan role was simply not allowed to read it.
func ecrDeniedErr() error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &nethttp.Response{StatusCode: 403}},
			Err:      errors.New("AccessDeniedException: not authorized to perform ecr:GetRepositoryPolicy"),
		},
	}
}

func TestClassifyEcrPolicyError(t *testing.T) {
	msg := "policy not found"

	t.Run("a denied read is a failure, not absent", func(t *testing.T) {
		// This is the classification the whole fix turns on: reading it as
		// absent lets isPublic report false on a policy nobody ever saw.
		assert.Equal(t, ecrPolicyOutcomeFailed, classifyEcrPolicyError(ecrDeniedErr(), false))
		assert.Equal(t, ecrPolicyOutcomeFailed, classifyEcrPolicyError(ecrDeniedErr(), true))
	})

	t.Run("a denied read surfaces as forbidden", func(t *testing.T) {
		wrapped := fmt.Errorf("operation error ECR: GetRepositoryPolicy: %w", ecrDeniedErr())
		err := classifyAwsError(wrapped, "ecr:GetRepositoryPolicy")
		require.ErrorIs(t, err, llx.ErrForbidden)
		assert.Equal(t, []string{"ecr:GetRepositoryPolicy"}, llx.ErrorDetailOf(err).GetPermissions())
	})

	t.Run("private RepositoryPolicyNotFoundException is absent", func(t *testing.T) {
		err := &ecrtypes.RepositoryPolicyNotFoundException{Message: &msg}
		assert.Equal(t, ecrPolicyOutcomeAbsent, classifyEcrPolicyError(err, false))
	})

	t.Run("public RepositoryPolicyNotFoundException is absent", func(t *testing.T) {
		err := &ecrpublic_types.RepositoryPolicyNotFoundException{Message: &msg}
		assert.Equal(t, ecrPolicyOutcomeAbsent, classifyEcrPolicyError(err, true))
	})

	t.Run("the private not-found type does not satisfy the public branch", func(t *testing.T) {
		// The two SDKs declare distinct types under the same name; matching the
		// wrong one would read a real failure as "no policy attached".
		err := &ecrtypes.RepositoryPolicyNotFoundException{Message: &msg}
		assert.Equal(t, ecrPolicyOutcomeFailed, classifyEcrPolicyError(err, true))
	})

	t.Run("a repository that no longer exists is a failure, not an absent policy", func(t *testing.T) {
		err := &ecrtypes.RepositoryNotFoundException{Message: &msg}
		assert.Equal(t, ecrPolicyOutcomeFailed, classifyEcrPolicyError(err, false))
	})

	t.Run("a transport error is a failure, not an absent policy", func(t *testing.T) {
		assert.Equal(t, ecrPolicyOutcomeFailed, classifyEcrPolicyError(errors.New("connection reset by peer"), false))
	})
}
