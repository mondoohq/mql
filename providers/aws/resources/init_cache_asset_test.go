// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// assetInitCacheCase is one resource that is both a discovery target and an
// init that fetches. Each one paid an API call per data query and per policy
// filter, because cnspec compiles both to a bare resource and NewResource runs
// the init before it consults the cache.
type assetInitCacheCase struct {
	resource string
	// cacheKey is how the resource computes its own MqlID, which is the ARN for
	// most of them but not all.
	cacheKey string
	// seed builds the resource the way its service list does, so the probe has
	// something to find.
	seed map[string]*llx.RawData
	args map[string]*llx.RawData
	init func(*plugin.Runtime, map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error)
}

func assetInitCacheCases() []assetInitCacheCase {
	arnOf := func(service, resource string) string {
		return "arn:aws:" + service + ":us-east-1:123456789012:" + resource
	}
	byArn := func(resource, service, path string, init func(*plugin.Runtime, map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error)) assetInitCacheCase {
		a := arnOf(service, path)
		return assetInitCacheCase{
			resource: resource,
			cacheKey: a,
			seed:     map[string]*llx.RawData{"arn": llx.StringData(a)},
			args:     map[string]*llx.RawData{"arn": llx.StringData(a)},
			init:     init,
		}
	}

	cases := []assetInitCacheCase{
		byArn(ResourceAwsEfsFilesystem, "elasticfilesystem", "file-system/fs-05a7586f1438d5e10", initAwsEfsFilesystem),
		byArn(ResourceAwsEc2Instance, "ec2", "instance/i-1234567890abcdef0", initAwsEc2Instance),
		byArn(ResourceAwsLambdaFunction, "lambda", "function:my-func", initAwsLambdaFunction),
		byArn(ResourceAwsSecretsmanagerSecret, "secretsmanager", "secret:my-secret-AbCdEf", initAwsSecretsmanagerSecret),
		byArn(ResourceAwsCloudwatchLoggroup, "logs", "log-group:/aws/lambda/my-func:*", initAwsCloudwatchLoggroup),
		byArn(ResourceAwsCloudtrailTrail, "cloudtrail", "trail/my-trail", initAwsCloudtrailTrail),
		byArn(ResourceAwsEcrRepository, "ecr", "repository/my-repo", initAwsEcrRepository),
		byArn(ResourceAwsElbLoadbalancer, "elasticloadbalancing", "loadbalancer/app/my-lb/50dc6c495c0c9188", initAwsElbLoadbalancer),
		byArn(ResourceAwsEsDomain, "es", "domain/my-domain", initAwsEsDomain),
		byArn(ResourceAwsOpensearchDomain, "es", "domain/my-os-domain", initAwsOpensearchDomain),
		byArn(ResourceAwsRdsSnapshot, "rds", "snapshot:my-snapshot", initAwsRdsSnapshot),
		byArn(ResourceAwsMemorydbCluster, "memorydb", "cluster/my-cluster", initAwsMemorydbCluster),
		byArn(ResourceAwsTransferServer, "transfer", "server/s-1234567890abcdef0", initAwsTransferServer),
		byArn(ResourceAwsAppstreamFleet, "appstream", "fleet/my-fleet", initAwsAppstreamFleet),
	}

	// aws.cognito.userPool has no id() method; its MqlID is the __id it is
	// created with, which both the list and the init set to the ARN.
	poolArn := arnOf("cognito-idp", "userpool/us-east-1_AbCdEfGhI")
	cases = append(cases, assetInitCacheCase{
		resource: ResourceAwsCognitoUserPool,
		cacheKey: poolArn,
		seed: map[string]*llx.RawData{
			"__id": llx.StringData(poolArn),
			"arn":  llx.StringData(poolArn),
		},
		args: map[string]*llx.RawData{"arn": llx.StringData(poolArn)},
		init: initAwsCognitoUserPool,
	})

	// aws.codebuild.project keys its __id on the name alone, so the name is the
	// probe key and the ARN is not usable as one.
	cases = append(cases, assetInitCacheCase{
		resource: ResourceAwsCodebuildProject,
		cacheKey: "my-project",
		seed:     map[string]*llx.RawData{"name": llx.StringData("my-project")},
		args: map[string]*llx.RawData{
			"name":   llx.StringData("my-project"),
			"region": llx.StringData("us-east-1"),
		},
		init: initAwsCodebuildProject,
	})

	return cases
}

// Each of these inits must answer from the resource cache without touching the
// connection.
//
// The runtime here deliberately has a nil Connection, which is what makes the
// test able to fail: every one of these inits reaches for
// runtime.Connection.(*connection.AwsConnection) on its fetch path, and a type
// assertion on a nil interface panics. So deleting a probe, or moving it below
// the point where the init resolves its client, turns this test red rather than
// leaving it quietly green on a slower scan.
//
// The bug this pins: an EFS file system asset reported its own id, tags and
// creation time as null under ThrottlingException, because a dozen queries each
// spent their own DescribeFileSystems on a file system that was already in the
// cache.
func TestAssetInits_AnswerFromCacheWithoutAnApiCall(t *testing.T) {
	for _, tc := range assetInitCacheCases() {
		t.Run(tc.resource, func(t *testing.T) {
			runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

			seeded, err := CreateResource(runtime, tc.resource, tc.seed)
			require.NoError(t, err)
			require.Equal(t, tc.cacheKey, seeded.MqlID(),
				"the seed must land under the key the probe looks up; if this fails the probe is keyed on the wrong field")

			_, res, err := tc.init(runtime, tc.args)
			require.NoError(t, err)
			require.NotNil(t, res, "the init must return the cached resource, not fall through to a fetch")
			assert.Same(t, seeded, res)
		})
	}
}

// A cache miss must leave the init on its existing path rather than reporting
// the resource as absent. With a nil connection that path panics, which is
// exactly the fetch the probe is meant to skip -- so recovering a panic here is
// the assertion.
func TestAssetInits_MissFallsThroughToTheFetch(t *testing.T) {
	for _, tc := range assetInitCacheCases() {
		t.Run(tc.resource, func(t *testing.T) {
			runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

			reached := func() (reached bool) {
				defer func() {
					if r := recover(); r != nil {
						reached = true
					}
				}()
				_, res, err := tc.init(runtime, tc.args)
				// Some inits validate the ARN before building a client and
				// report a lookup failure instead; that is also not a false
				// "found".
				return err != nil || res == nil
			}()

			assert.True(t, reached,
				"an empty cache must not resolve the resource; the init has to go on and fetch")
		})
	}
}

// The fast path stays: a caller that already supplied every field must not be
// diverted into a cache lookup that could answer with a different instance.
func TestAssetInits_KeepTheCompleteArgsFastPath(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	fsArn := "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-abc"

	args, res, err := initAwsEfsFilesystem(runtime, map[string]*llx.RawData{
		"arn":       llx.StringData(fsArn),
		"id":        llx.StringData("fs-abc"),
		"region":    llx.StringData("us-east-1"),
		"encrypted": llx.BoolData(true),
	})
	require.NoError(t, err)
	assert.Nil(t, res, "complete args are built by the runtime, not resolved by the init")
	assert.NotNil(t, args)
}

func TestCachedArg(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	project, err := CreateResource(runtime, ResourceAwsCodebuildProject, map[string]*llx.RawData{
		"name": llx.StringData("my-project"),
	})
	require.NoError(t, err)

	t.Run("reads the key out of the named argument", func(t *testing.T) {
		got := cachedArg(runtime, ResourceAwsCodebuildProject,
			map[string]*llx.RawData{"name": llx.StringData("my-project")}, "name")
		assert.Same(t, project, got)
	})

	t.Run("the wrong argument is a miss", func(t *testing.T) {
		assert.Nil(t, cachedArg(runtime, ResourceAwsCodebuildProject,
			map[string]*llx.RawData{"arn": llx.StringData("my-project")}, "name"))
	})

	t.Run("a non-string value is a miss, not a panic", func(t *testing.T) {
		assert.Nil(t, cachedArg(runtime, ResourceAwsCodebuildProject,
			map[string]*llx.RawData{"name": llx.IntData(42)}, "name"))
	})
}

// aws.sqs.queue keys its __id on the queue URL, which is what its init calls
// GetQueueUrl to discover, so it resolves out of the already-walked queue list
// instead of probing by ARN.
func TestResolvedSqsQueueByArn(t *testing.T) {
	// Build the aws.sqs singleton through CreateResource so the list lands
	// under whatever key the resource computes for itself.
	newSqs := func(t *testing.T) (*plugin.Runtime, *mqlAwsSqs) {
		runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
		obj, err := CreateResource(runtime, ResourceAwsSqs, map[string]*llx.RawData{})
		require.NoError(t, err)
		return runtime, obj.(*mqlAwsSqs)
	}
	newRuntime := func(t *testing.T, urls ...string) (*plugin.Runtime, []*mqlAwsSqsQueue) {
		runtime, sqsRes := newSqs(t)
		queues := make([]*mqlAwsSqsQueue, 0, len(urls))
		list := make([]any, 0, len(urls))
		for _, u := range urls {
			q := &mqlAwsSqsQueue{Url: plugin.TValue[string]{Data: u, State: plugin.StateIsSet}}
			queues = append(queues, q)
			list = append(list, q)
		}
		sqsRes.Queues = plugin.TValue[[]any]{Data: list, State: plugin.StateIsSet}
		return runtime, queues
	}
	parse := func(t *testing.T, s string) arn.ARN {
		a, err := arn.Parse(s)
		require.NoError(t, err)
		return a
	}

	t.Run("matches on the url path", func(t *testing.T) {
		runtime, queues := newRuntime(t,
			"https://sqs.us-east-1.amazonaws.com/123456789012/other",
			"https://sqs.us-east-1.amazonaws.com/123456789012/wanted",
		)
		got := resolvedSqsQueueByArn(runtime, parse(t, "arn:aws:sqs:us-east-1:123456789012:wanted"))
		assert.Same(t, queues[1], got)
	})

	// The queue name and account live in the path whatever form the hostname
	// takes, so a fips or legacy endpoint must still match.
	t.Run("matches a non-standard endpoint form", func(t *testing.T) {
		runtime, queues := newRuntime(t, "https://sqs-fips.us-east-1.amazonaws.com/123456789012/wanted")
		got := resolvedSqsQueueByArn(runtime, parse(t, "arn:aws:sqs:us-east-1:123456789012:wanted"))
		assert.Same(t, queues[0], got)
	})

	// Same account, same queue name, different region is a different queue.
	t.Run("region must agree", func(t *testing.T) {
		runtime, _ := newRuntime(t, "https://sqs.us-west-2.amazonaws.com/123456789012/wanted")
		assert.Nil(t, resolvedSqsQueueByArn(runtime, parse(t, "arn:aws:sqs:us-east-1:123456789012:wanted")))
	})

	t.Run("another account's queue of the same name is not a match", func(t *testing.T) {
		runtime, _ := newRuntime(t, "https://sqs.us-east-1.amazonaws.com/999999999999/wanted")
		assert.Nil(t, resolvedSqsQueueByArn(runtime, parse(t, "arn:aws:sqs:us-east-1:123456789012:wanted")))
	})

	t.Run("no match in the list", func(t *testing.T) {
		runtime, _ := newRuntime(t, "https://sqs.us-east-1.amazonaws.com/123456789012/other")
		assert.Nil(t, resolvedSqsQueueByArn(runtime, parse(t, "arn:aws:sqs:us-east-1:123456789012:wanted")))
	})

	// The list must never be forced: for a one-off query against a single
	// queue, listing every queue in every region costs more than the
	// GetQueueUrl it would save.
	t.Run("an unresolved list is a miss, not a fetch", func(t *testing.T) {
		runtime, sqsRes := newSqs(t)

		assert.False(t, sqsRes.Queues.IsSet())
		assert.Nil(t, resolvedSqsQueueByArn(runtime, parse(t, "arn:aws:sqs:us-east-1:123456789012:wanted")))
		assert.False(t, sqsRes.Queues.IsSet(), "the probe must not trigger a ListQueues fan-out")
	})
}
