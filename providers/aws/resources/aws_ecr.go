// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	ecrpublic_types "github.com/aws/aws-sdk-go-v2/service/ecrpublic/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"

	"go.mondoo.com/mql/types"
)

// ecrLifecyclePolicyDoc represents the parsed JSON lifecycle policy document.
// The AWS SDK returns this as a raw JSON string with no typed structs.
type ecrLifecyclePolicyDoc struct {
	Rules []ecrLifecyclePolicyRule `json:"rules"`
}

type ecrLifecyclePolicyRule struct {
	RulePriority int                         `json:"rulePriority"`
	Description  string                      `json:"description"`
	Selection    ecrLifecyclePolicySelection `json:"selection"`
	Action       ecrLifecyclePolicyAction    `json:"action"`
}

type ecrLifecyclePolicySelection struct {
	TagStatus      string   `json:"tagStatus"`
	TagPatternList []string `json:"tagPatternList"`
	TagPrefixList  []string `json:"tagPrefixList"`
	CountType      string   `json:"countType"`
	CountUnit      string   `json:"countUnit"`
	CountNumber    int      `json:"countNumber"`
}

type ecrLifecyclePolicyAction struct {
	Type string `json:"type"`
}

// the max amount of retries for the ECR Describe* calls (1 initial + 7 retries).
const ecrDescribeMaxAttempts = 8

// raises the per-operation retry ceiling for private ECR Describe* calls.
func withEcrDescribeRetries(o *ecr.Options) {
	o.RetryMaxAttempts = ecrDescribeMaxAttempts
}

// raises the per-operation retry ceiling for public ECR Describe* calls.
func withEcrPublicDescribeRetries(o *ecrpublic.Options) {
	o.RetryMaxAttempts = ecrDescribeMaxAttempts
}

func (a *mqlAwsEcr) id() (string, error) {
	return "aws.ecr", nil
}

func (a *mqlAwsEcr) replicationConfiguration() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ecr("")
	ctx := context.Background()

	resp, err := svc.DescribeRegistry(ctx, &ecr.DescribeRegistryInput{})
	if err != nil {
		return nil, err
	}
	if resp.ReplicationConfiguration == nil {
		a.ReplicationConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return ecrReplicationConfigurationToDict(resp.ReplicationConfiguration), nil
}

// ecrReplicationConfigurationToDict renders the registry replication settings
// with the key names the schema documents. The SDK struct carries no json
// tags, so a reflective conversion emits Go field names (Rules, Destinations,
// RegistryId) and every query written against the documented lowercase keys
// resolves to null.
func ecrReplicationConfigurationToDict(cfg *ecrtypes.ReplicationConfiguration) map[string]any {
	if cfg == nil {
		return nil
	}

	rules := make([]any, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		destinations := make([]any, 0, len(rule.Destinations))
		for _, d := range rule.Destinations {
			destinations = append(destinations, map[string]any{
				"region":     convert.ToValue(d.Region),
				"registryId": convert.ToValue(d.RegistryId),
			})
		}

		filters := make([]any, 0, len(rule.RepositoryFilters))
		for _, f := range rule.RepositoryFilters {
			filters = append(filters, map[string]any{
				"filter":     convert.ToValue(f.Filter),
				"filterType": string(f.FilterType),
			})
		}

		rules = append(rules, map[string]any{
			"destinations":      destinations,
			"repositoryFilters": filters,
		})
	}

	return map[string]any{"rules": rules}
}

func (a *mqlAwsEcrRepository) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEcrImage) id() (string, error) {
	id := a.RegistryId.Data
	sha := a.Digest.Data
	name := a.RepoName.Data
	return id + "/" + name + "/" + sha, nil
}

func (a *mqlAwsEcrLifecyclePolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsEcrLifecyclePolicyRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsEcr) images() ([]any, error) {
	obj, err := CreateResource(a.MqlRuntime, ResourceAwsEcr, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	ecr := obj.(*mqlAwsEcr)
	res := []any{}

	repos, err := ecr.publicRepositories()
	if err != nil {
		return nil, err
	}
	for i := range repos {
		images, err := repos[i].(*mqlAwsEcrRepository).images()
		if err != nil {
			return nil, err
		}
		res = append(res, images...)
	}
	pRepos, err := ecr.privateRepositories()
	if err != nil {
		return nil, err
	}
	for i := range pRepos {
		images, err := pRepos[i].(*mqlAwsEcrRepository).images()
		if err != nil {
			return nil, err
		}
		res = append(res, images...)
	}
	return res, nil
}

func (a *mqlAwsEcr) privateRepositories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	if conn.Filters.Ecr.Scope == connection.EcrScopePublic {
		return []any{}, nil
	}

	return perRegion(conn, "ecr", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Ecr(region)
		res := []any{}

		// AWS caps repositoryNames at ECRDescribeRepositoriesNameLimit per request, so
		// a larger filter is split into batches and each batch is described separately.
		// 0 batches means all repositories should be described.
		batches := conn.Filters.Ecr.PrivateRepositoryNameBatches()
		if len(batches) == 0 {
			batches = [][]string{{}}
		}

		for _, batch := range batches {
			req := &ecr.DescribeRepositoriesInput{}
			if len(batch) > 0 {
				req.RepositoryNames = batch
			}

			paginator := ecr.NewDescribeRepositoriesPaginator(svc, req)
			for paginator.HasMorePages() {
				repoResp, err := paginator.NextPage(ctx, withEcrDescribeRetries)
				if err != nil {
					return nil, err
				}
				for _, r := range repoResp.Repositories {
					mqlRepoResource, err := buildEcrPrivateRepositoryResource(a.MqlRuntime, region, r)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRepoResource)
				}
			}
		}

		return res, nil
	})
}

func (a *mqlAwsEcrRepository) scanningFrequency() (string, error) {
	if a.Public.Data {
		// ECR Public exposes no scanning configuration, so the frequency is
		// unknown. An empty string is not one of the documented values.
		a.ScanningFrequency.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	name := a.Name.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ecr(region)
	ctx := context.Background()

	resp, err := svc.BatchGetRepositoryScanningConfiguration(ctx, &ecr.BatchGetRepositoryScanningConfigurationInput{
		RepositoryNames: []string{name},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			// The null state above is the answer; this empty string is only
			// the zero value Go requires and the runtime discards it.
			a.ScanningFrequency.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", err
	}

	if len(resp.ScanningConfigurations) > 0 {
		// The API returns exactly one ScanningConfiguration per repository in the request.
		return string(resp.ScanningConfigurations[0].ScanFrequency), nil
	}

	// Nothing came back for the repository, so the frequency is unknown rather
	// than the empty string, which is outside the documented value set.
	a.ScanningFrequency.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

func (a *mqlAwsEcrRepository) images() ([]any, error) {
	name := a.Name.Data
	region := a.Region.Data
	public := a.Public.Data
	uri := a.Uri.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	ctx := context.Background()
	mqlres := []any{}
	if public {
		svc := conn.EcrPublic(region)
		paginator := ecrpublic.NewDescribeImagesPaginator(svc, &ecrpublic.DescribeImagesInput{RepositoryName: &name})
		for paginator.HasMorePages() {
			res, err := paginator.NextPage(ctx, withEcrPublicDescribeRetries)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return nil, nil
				}
				return nil, err
			}
			for _, image := range res.ImageDetails {
				if conn.Filters.Ecr.IsFilteredOutByTags(image.ImageTags) {
					log.Debug().Str("repository", name).Strs("tags", image.ImageTags).Msg("skipping ecr public image due to tag filters")
					continue
				}
				imageArn := ecrImageArn(ImageInfo{Public: true, Region: region, RegistryId: convert.ToValue(image.RegistryId), RepoName: name, Digest: convert.ToValue(image.ImageDigest)})
				mqlImage, err := CreateResource(a.MqlRuntime, ResourceAwsEcrImage,
					map[string]*llx.RawData{
						// The public ARN names the ecr-public service and carries no
						// region, so it cannot collide with a same-named private repo --
						// which matters because the cachePublic write below would
						// otherwise flip the private image to "NOT_SCANNED".
						"__id":              llx.StringData(imageArn),
						"digest":            llx.StringDataPtr(image.ImageDigest),
						"mediaType":         llx.StringDataPtr(image.ImageManifestMediaType),
						"artifactMediaType": llx.StringDataPtr(image.ArtifactMediaType),
						"tags":              llx.ArrayData(toInterfaceArr(image.ImageTags), types.String),
						"registryId":        llx.StringDataPtr(image.RegistryId),
						"repoName":          llx.StringData(name),
						"region":            llx.StringData(region),
						"arn":               llx.StringData(imageArn),
						"uri":               llx.StringData(uri),
						"pushedAt":          llx.TimeDataPtr(image.ImagePushedAt),
						"sizeInBytes":       llx.IntDataPtr(image.ImageSizeInBytes),
						// ECR Public reports no pull time at all. Leaving the field
						// unset makes the runtime report a provider bug, so state the
						// absence explicitly.
						"lastRecordedPullTime": llx.NilData,
					})
				if err != nil {
					return nil, err
				}
				mqlImage.(*mqlAwsEcrImage).cachePublic = true
				mqlres = append(mqlres, mqlImage)
			}
		}
		return mqlres, nil
	}

	// private
	svc := conn.Ecr(region)
	paginator := ecr.NewDescribeImagesPaginator(svc, &ecr.DescribeImagesInput{RepositoryName: &name})
	for paginator.HasMorePages() {
		res, err := paginator.NextPage(ctx, withEcrDescribeRetries)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", region).Msg("error accessing region for AWS API")
				return nil, nil
			}
			return nil, err
		}
		for _, image := range res.ImageDetails {
			if conn.Filters.Ecr.IsFilteredOutByTags(image.ImageTags) {
				log.Debug().Str("repository", name).Strs("tags", image.ImageTags).Msg("skipping ecr private image due to tag filters")
				continue
			}
			imageArn := ecrImageArn(ImageInfo{Region: region, RegistryId: convert.ToValue(image.RegistryId), RepoName: name, Digest: convert.ToValue(image.ImageDigest)})
			mqlImage, err := CreateResource(a.MqlRuntime, ResourceAwsEcrImage,
				map[string]*llx.RawData{
					// region-qualified via the ARN: cross-region replication puts the
					// same registryId/repoName/digest in several regions, which the
					// id() fallback cannot tell apart.
					"__id":                 llx.StringData(imageArn),
					"arn":                  llx.StringData(imageArn),
					"digest":               llx.StringDataPtr(image.ImageDigest),
					"lastRecordedPullTime": llx.TimeDataPtr(image.LastRecordedPullTime),
					"mediaType":            llx.StringDataPtr(image.ImageManifestMediaType),
					"artifactMediaType":    llx.StringDataPtr(image.ArtifactMediaType),
					"pushedAt":             llx.TimeDataPtr(image.ImagePushedAt),
					"region":               llx.StringData(region),
					"registryId":           llx.StringDataPtr(image.RegistryId),
					"repoName":             llx.StringData(name),
					"sizeInBytes":          llx.IntDataPtr(image.ImageSizeInBytes),
					"tags":                 llx.ArrayData(toInterfaceArr(image.ImageTags), types.String),
					"uri":                  llx.StringData(uri),
				})
			if err != nil {
				return nil, err
			}
			mqlres = append(mqlres, mqlImage)
		}
	}
	return mqlres, nil
}

func newMqlEcrLifecyclePolicyRule(runtime *plugin.Runtime, repoArn string, rule ecrLifecyclePolicyRule) (*mqlAwsEcrLifecyclePolicyRule, error) {
	ruleId := fmt.Sprintf("%s/lifecyclePolicy/rule/%d", repoArn, rule.RulePriority)

	tagPatternList := rule.Selection.TagPatternList
	if tagPatternList == nil {
		tagPatternList = []string{}
	}
	tagPrefixList := rule.Selection.TagPrefixList
	if tagPrefixList == nil {
		tagPrefixList = []string{}
	}

	resource, err := CreateResource(runtime, "aws.ecr.lifecyclePolicy.rule",
		map[string]*llx.RawData{
			"__id":           llx.StringData(ruleId),
			"id":             llx.StringData(ruleId),
			"rulePriority":   llx.IntData(rule.RulePriority),
			"description":    llx.StringData(rule.Description),
			"tagStatus":      llx.StringData(rule.Selection.TagStatus),
			"tagPatternList": llx.ArrayData(toInterfaceArr(tagPatternList), types.String),
			"tagPrefixList":  llx.ArrayData(toInterfaceArr(tagPrefixList), types.String),
			"countType":      llx.StringData(rule.Selection.CountType),
			"countUnit":      llx.StringData(rule.Selection.CountUnit),
			"countNumber":    llx.IntData(rule.Selection.CountNumber),
			"actionType":     llx.StringData(rule.Action.Type),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsEcrLifecyclePolicyRule), nil
}

// ecrPolicyOutcome is what a failed GetRepositoryPolicy call means.
type ecrPolicyOutcome int

const (
	// ecrPolicyOutcomeFailed is an error worth surfacing to the caller.
	ecrPolicyOutcomeFailed ecrPolicyOutcome = iota
	// ecrPolicyOutcomeUnreadable is a denial: the repository may well have a
	// policy, we were simply not allowed to look.
	ecrPolicyOutcomeUnreadable
	// ecrPolicyOutcomeAbsent is a successful read of a repository that carries
	// no policy at all.
	ecrPolicyOutcomeAbsent
)

// classifyEcrPolicyError separates the two failures that both leave the policy
// field null. Only the absent case is a measurement, so only it may let
// isPublic report false; conflating them is how a scan role missing
// GetRepositoryPolicy reports a world-pullable repository as private.
//
// err must be non-nil: the caller establishes that the call failed before
// asking what kind of failure it was. There is no outcome that describes a
// successful read, so a nil error has no meaningful classification here.
func classifyEcrPolicyError(err error, public bool) ecrPolicyOutcome {
	if Is400AccessDeniedError(err) {
		return ecrPolicyOutcomeUnreadable
	}
	if public {
		var notFoundErr *ecrpublic_types.RepositoryPolicyNotFoundException
		if errors.As(err, &notFoundErr) {
			return ecrPolicyOutcomeAbsent
		}
		return ecrPolicyOutcomeFailed
	}
	var notFoundErr *ecrtypes.RepositoryPolicyNotFoundException
	if errors.As(err, &notFoundErr) {
		return ecrPolicyOutcomeAbsent
	}
	return ecrPolicyOutcomeFailed
}

func (a *mqlAwsEcrRepository) policy() (any, error) {
	name := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()

	var policyText *string
	if a.Public.Data {
		// ECR Public repositories carry their own resource policy, and it is the
		// only thing that says whether the world can pull from them. Reading it
		// from the private API is impossible, so it has to come from ecrpublic.
		// A distinct variable name keeps the permissions extractor, which maps
		// one client variable per function, from folding this into the private
		// ecr client assigned below.
		publicSvc := conn.EcrPublic("us-east-1") // only supported for us-east-1
		resp, err := publicSvc.GetRepositoryPolicy(ctx, &ecrpublic.GetRepositoryPolicyInput{
			RegistryId:     aws.String(conn.AccountId()),
			RepositoryName: &name,
		})
		if err != nil {
			switch classifyEcrPolicyError(err, true) {
			case ecrPolicyOutcomeUnreadable:
				return a.markPolicyUnreadable()
			case ecrPolicyOutcomeAbsent:
				return a.markPolicyAbsent()
			default:
				return nil, err
			}
		}
		policyText = resp.PolicyText
	} else {
		svc := conn.Ecr(a.Region.Data)
		resp, err := svc.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
			RepositoryName: &name,
		})
		if err != nil {
			switch classifyEcrPolicyError(err, false) {
			case ecrPolicyOutcomeUnreadable:
				return a.markPolicyUnreadable()
			case ecrPolicyOutcomeAbsent:
				return a.markPolicyAbsent()
			default:
				return nil, err
			}
		}
		policyText = resp.PolicyText
	}

	if policyText == nil {
		return a.markPolicyAbsent()
	}

	var policyDoc any
	if jsonErr := json.Unmarshal([]byte(*policyText), &policyDoc); jsonErr != nil {
		return nil, jsonErr
	}
	return policyDoc, nil
}

func (a *mqlAwsEcrRepository) lifecyclePolicy() (*mqlAwsEcrLifecyclePolicy, error) {
	if a.Public.Data {
		a.LifecyclePolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	name := a.Name.Data
	region := a.Region.Data
	repoArn := a.Arn.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ecr(region)
	ctx := context.Background()

	resp, err := svc.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
		RepositoryName: &name,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.LifecyclePolicy.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		// LifecyclePolicyNotFoundException means no policy is set
		var notFoundErr *ecrtypes.LifecyclePolicyNotFoundException
		if errors.As(err, &notFoundErr) {
			a.LifecyclePolicy.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	if resp.LifecyclePolicyText == nil {
		a.LifecyclePolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var doc ecrLifecyclePolicyDoc
	if jsonErr := json.Unmarshal([]byte(*resp.LifecyclePolicyText), &doc); jsonErr != nil {
		return nil, jsonErr
	}

	rules := []any{}
	for _, rule := range doc.Rules {
		mqlRule, err := newMqlEcrLifecyclePolicyRule(a.MqlRuntime, repoArn, rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, mqlRule)
	}

	policyId := repoArn + "/lifecyclePolicy"
	resource, err := CreateResource(a.MqlRuntime, "aws.ecr.lifecyclePolicy",
		map[string]*llx.RawData{
			"__id":            llx.StringData(policyId),
			"id":              llx.StringData(policyId),
			"lastEvaluatedAt": llx.TimeDataPtr(ecrEvaluationTime(resp.LastEvaluatedAt)),
			"rules":           llx.ArrayData(rules, types.Resource("aws.ecr.lifecyclePolicy.rule")),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsEcrLifecyclePolicy), nil
}

type ImageInfo struct {
	Region     string
	RepoName   string
	Digest     string
	RegistryId string
	// Public marks an image in the ECR Public registry, which is addressed
	// through the ecr-public service and has no region component.
	Public bool
}

func ecrImageArn(i ImageInfo) string {
	if i.Public {
		return fmt.Sprintf("arn:aws:ecr-public::%s:image/%s/%s", i.RegistryId, i.RepoName, i.Digest)
	}
	return fmt.Sprintf("arn:aws:ecr:%s:%s:image/%s/%s", i.Region, i.RegistryId, i.RepoName, i.Digest)
}

// ecrRepositoryArn builds the ARN of an ECR repository. ECR Public repositories
// live in the ecr-public service and carry no region, which is the shape
// initAwsEcrRepository parses to pick the registry it queries.
func ecrRepositoryArn(public bool, region, registryId, repoName string) string {
	if public {
		return fmt.Sprintf("arn:aws:ecr-public::%s:repository/%s", registryId, repoName)
	}
	return fmt.Sprintf("arn:aws:ecr:%s:%s:repository/%s", region, registryId, repoName)
}

// ecrEvaluationTime reports a never-evaluated timestamp as absent. ECR fills
// lastEvaluatedAt with the Unix epoch for a lifecycle policy it has not
// evaluated yet; forwarding that verbatim renders as a date in 1969 and makes
// a `lastEvaluatedAt == null` check false.
func ecrEvaluationTime(t *time.Time) *time.Time {
	if t == nil || t.IsZero() || t.Unix() == 0 {
		return nil
	}
	return t
}

func EcrImageName(i ImageInfo) string {
	return i.RepoName + "@" + i.Digest
}

func (a *mqlAwsEcrImage) repository() (*mqlAwsEcrRepository, error) {
	repoName := a.RepoName.Data
	if repoName == "" {
		a.Repository.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	arnVal := ecrRepositoryArn(a.cachePublic, a.Region.Data, a.RegistryId.Data, repoName)
	res, err := NewResource(a.MqlRuntime, "aws.ecr.repository",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		// Public-gallery images and cross-account repositories won't resolve to a
		// repository in this account; leave the reference null rather than failing.
		a.Repository.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsEcrRepository), nil
}

func initAwsEcrImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEcrImage); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch ecr image")
	}

	obj, err := CreateResource(runtime, "aws.ecr", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	ecr := obj.(*mqlAwsEcr)

	rawResources := ecr.GetImages()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		image := rawResource.(*mqlAwsEcrImage)
		if image.Arn.Data == arnVal {
			return args, image, nil
		}
	}
	return nil, nil, errors.New("ecr image does not exist")
}

func (a *mqlAwsEcr) publicRepositories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	if conn.Filters.Ecr.Scope == connection.EcrScopePrivate {
		return []any{}, nil
	}

	svc := conn.EcrPublic("us-east-1") // only supported for us-east-1
	res := []any{}

	// AWS caps repositoryNames at ECRDescribeRepositoriesNameLimit per request, so
	// a larger filter is split into batches and each batch is described separately.
	// 0 batches means all repositories should be described.
	batches := conn.Filters.Ecr.PublicRepositoryNameBatches()
	if len(batches) == 0 {
		batches = [][]string{{}}
	}

	for _, batch := range batches {
		req := &ecrpublic.DescribeRepositoriesInput{
			RegistryId: aws.String(conn.AccountId()),
		}
		if len(batch) > 0 {
			// AWS does not do partial results and returns an error if a single repository
			// supplied in the filters is not found
			req.RepositoryNames = batch
		}

		paginator := ecrpublic.NewDescribeRepositoriesPaginator(svc, req)
		for paginator.HasMorePages() {
			repoResp, err := paginator.NextPage(context.TODO(), withEcrPublicDescribeRetries)
			if err != nil {
				return nil, err
			}

			for _, r := range repoResp.Repositories {
				mqlRepoResource, err := buildEcrPublicRepositoryResource(a.MqlRuntime, r)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlRepoResource)
			}
		}
	}

	return res, nil
}

func buildEcrPrivateRepositoryResource(runtime *plugin.Runtime, region string, r ecrtypes.Repository) (*mqlAwsEcrRepository, error) {
	imageScanOnPush := false
	if r.ImageScanningConfiguration != nil {
		imageScanOnPush = r.ImageScanningConfiguration.ScanOnPush
	}
	var encryptionType string
	var kmsKeyArn *string
	if r.EncryptionConfiguration != nil {
		encryptionType = string(r.EncryptionConfiguration.EncryptionType)
		kmsKeyArn = r.EncryptionConfiguration.KmsKey
	}
	mqlRepoResource, err := CreateResource(runtime, ResourceAwsEcrRepository,
		map[string]*llx.RawData{
			"arn":                llx.StringDataPtr(r.RepositoryArn),
			"name":               llx.StringDataPtr(r.RepositoryName),
			"uri":                llx.StringDataPtr(r.RepositoryUri),
			"registryId":         llx.StringDataPtr(r.RegistryId),
			"public":             llx.BoolData(false),
			"region":             llx.StringData(region),
			"imageScanOnPush":    llx.BoolData(imageScanOnPush),
			"imageTagMutability": llx.StringData(string(r.ImageTagMutability)),
			"encryptionType":     llx.StringData(encryptionType),
			"createdAt":          llx.TimeDataPtr(r.CreatedAt),
		})
	if err != nil {
		return nil, err
	}
	res := mqlRepoResource.(*mqlAwsEcrRepository)
	res.cacheKmsKeyArn = kmsKeyArn
	return res, nil
}

func buildEcrPublicRepositoryResource(runtime *plugin.Runtime, r ecrpublic_types.Repository) (*mqlAwsEcrRepository, error) {
	mqlRepoResource, err := CreateResource(runtime, ResourceAwsEcrRepository,
		map[string]*llx.RawData{
			"arn":        llx.StringDataPtr(r.RepositoryArn),
			"name":       llx.StringDataPtr(r.RepositoryName),
			"uri":        llx.StringDataPtr(r.RepositoryUri),
			"registryId": llx.StringDataPtr(r.RegistryId),
			"public":     llx.BoolData(true),
			"region":     llx.StringData("us-east-1"),
			// None of these three are returned by the public ECR API --
			// ecrpublic's Repository carries only CreatedAt, RegistryId,
			// RepositoryArn, RepositoryName and RepositoryUri. Nothing was
			// read, so nothing is asserted: a fabricated value reads in a
			// report exactly like a measured one, whichever way it happens to
			// fall. Report them as unknown instead.
			"imageScanOnPush":    llx.NilData,
			"imageTagMutability": llx.NilData,
			"encryptionType":     llx.NilData,
			"createdAt":          llx.TimeDataPtr(r.CreatedAt),
		})
	if err != nil {
		return nil, err
	}
	return mqlRepoResource.(*mqlAwsEcrRepository), nil
}

type mqlAwsEcrRepositoryInternal struct {
	catalogFetched bool
	catalogData    *ecrpublic_types.RepositoryCatalogData
	catalogLock    sync.Mutex
	cacheKmsKeyArn *string
	// policyUnreadable separates a policy that could not be read from one that
	// was read and found absent. Both leave the policy field null, but only the
	// first must stop policyStatements and isPublic from reporting that the
	// repository grants nothing.
	policyUnreadable bool
}

// markPolicyUnreadable records a repository policy the scan was not allowed to
// read. Nothing is known about what it grants, so downstream fields report null
// rather than an empty statement list.
func (a *mqlAwsEcrRepository) markPolicyUnreadable() (any, error) {
	a.policyUnreadable = true
	a.Policy.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// markPolicyAbsent records a repository that genuinely carries no policy. The
// read succeeded, so isPublic can honestly report false.
func (a *mqlAwsEcrRepository) markPolicyAbsent() (any, error) {
	a.Policy.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsEcrRepository) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == nil || *a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsEcrRepository) fetchCatalogData() (*ecrpublic_types.RepositoryCatalogData, error) {
	if a.catalogFetched {
		return a.catalogData, nil
	}
	a.catalogLock.Lock()
	defer a.catalogLock.Unlock()
	if a.catalogFetched {
		return a.catalogData, nil
	}

	if !a.Public.Data {
		a.catalogFetched = true
		a.catalogData = nil
		return nil, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EcrPublic("us-east-1")
	ctx := context.Background()

	name := a.Name.Data
	resp, err := svc.GetRepositoryCatalogData(ctx, &ecrpublic.GetRepositoryCatalogDataInput{
		RegistryId:     aws.String(conn.AccountId()),
		RepositoryName: &name,
	})
	if err != nil {
		log.Warn().Str("repository", name).Err(err).Msg("could not fetch ECR public catalog data")
		a.catalogFetched = true
		a.catalogData = nil
		return nil, nil
	}

	a.catalogFetched = true
	a.catalogData = resp.CatalogData
	return a.catalogData, nil
}

func (a *mqlAwsEcrRepository) aboutText() (string, error) {
	data, err := a.fetchCatalogData()
	if err != nil || data == nil {
		return "", err
	}
	return convert.ToValue(data.AboutText), nil
}

func (a *mqlAwsEcrRepository) usageText() (string, error) {
	data, err := a.fetchCatalogData()
	if err != nil || data == nil {
		return "", err
	}
	return convert.ToValue(data.UsageText), nil
}

func (a *mqlAwsEcrRepository) catalogDescription() (string, error) {
	data, err := a.fetchCatalogData()
	if err != nil || data == nil {
		return "", err
	}
	return convert.ToValue(data.Description), nil
}

func (a *mqlAwsEcrRepository) operatingSystems() ([]any, error) {
	data, err := a.fetchCatalogData()
	if err != nil || data == nil {
		return []any{}, err
	}
	return convert.SliceAnyToInterface(data.OperatingSystems), nil
}

func (a *mqlAwsEcrRepository) architectures() ([]any, error) {
	data, err := a.fetchCatalogData()
	if err != nil || data == nil {
		return []any{}, err
	}
	return convert.SliceAnyToInterface(data.Architectures), nil
}

func (a *mqlAwsEcrRepository) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	arnVal := a.Arn.Data
	tags := make(map[string]any)

	if a.Public.Data {
		// ECR Public repositories are tagged like any other resource, and
		// managedBy and cloudformationStack are derived from those tags.
		publicSvc := conn.EcrPublic("us-east-1") // only supported for us-east-1
		resp, err := publicSvc.ListTagsForResource(ctx, &ecrpublic.ListTagsForResourceInput{
			ResourceArn: &arnVal,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return markTagsUnreadable(&a.Tags)
			}
			return nil, err
		}
		for _, t := range resp.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}
		return tags, nil
	}

	svc := conn.Ecr(a.Region.Data)
	resp, err := svc.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{
		ResourceArn: &arnVal,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	for _, t := range resp.Tags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

// ==================== ECR Image Scan Findings ====================

type mqlAwsEcrImageInternal struct {
	cachePublic             bool
	scanFetched             bool
	scanFindingsCache       []ecrtypes.ImageScanFinding
	scanStatusCache         string
	scanSeverityCountsCache map[string]int32
	scanLock                sync.Mutex
}

func (a *mqlAwsEcrImage) fetchScanFindings() error {
	if a.scanFetched {
		return nil
	}
	a.scanLock.Lock()
	defer a.scanLock.Unlock()
	if a.scanFetched {
		return nil
	}

	repoName := a.RepoName.Data
	digest := a.Digest.Data
	region := a.Region.Data

	// Public images don't support scan findings
	if a.cachePublic {
		a.scanFetched = true
		a.scanStatusCache = "NOT_SCANNED"
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ecr(region)
	ctx := context.Background()

	var findings []ecrtypes.ImageScanFinding
	paginator := ecr.NewDescribeImageScanFindingsPaginator(svc, &ecr.DescribeImageScanFindingsInput{
		RepositoryName: &repoName,
		ImageId:        &ecrtypes.ImageIdentifier{ImageDigest: &digest},
	})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			var scanNotFound *ecrtypes.ScanNotFoundException
			if errors.As(err, &scanNotFound) {
				a.scanFetched = true
				a.scanStatusCache = "NOT_SCANNED"
				return nil
			}
			if Is400AccessDeniedError(err) {
				a.scanFetched = true
				a.scanStatusCache = ""
				return nil
			}
			return err
		}
		if resp.ImageScanStatus != nil {
			a.scanStatusCache = string(resp.ImageScanStatus.Status)
		}
		if resp.ImageScanFindings != nil {
			findings = append(findings, resp.ImageScanFindings.Findings...)
			if resp.ImageScanFindings.FindingSeverityCounts != nil {
				a.scanSeverityCountsCache = make(map[string]int32)
				for k, v := range resp.ImageScanFindings.FindingSeverityCounts {
					a.scanSeverityCountsCache[string(k)] = v
				}
			}
		}
	}
	a.scanFindingsCache = findings
	a.scanFetched = true
	return nil
}

func (a *mqlAwsEcrImage) scanStatus() (string, error) {
	if err := a.fetchScanFindings(); err != nil {
		return "", err
	}
	return a.scanStatusCache, nil
}

func (a *mqlAwsEcrImage) scanFindings() ([]any, error) {
	if err := a.fetchScanFindings(); err != nil {
		return nil, err
	}

	imageArn := a.Arn.Data
	res := make([]any, 0, len(a.scanFindingsCache))
	for i, f := range a.scanFindingsCache {
		attrs := map[string]any{}
		for _, attr := range f.Attributes {
			if attr.Key != nil {
				attrs[*attr.Key] = convert.ToValue(attr.Value)
			}
		}

		findingId := fmt.Sprintf("%s/scanFinding/%d", imageArn, i)
		mqlFinding, err := CreateResource(a.MqlRuntime, "aws.ecr.image.scanFinding",
			map[string]*llx.RawData{
				"__id":        llx.StringData(findingId),
				"name":        llx.StringDataPtr(f.Name),
				"description": llx.StringDataPtr(f.Description),
				"uri":         llx.StringDataPtr(f.Uri),
				"severity":    llx.StringData(string(f.Severity)),
				"attributes":  llx.DictData(attrs),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFinding)
	}
	return res, nil
}

func (a *mqlAwsEcrImage) scanFindingSeverityCounts() (any, error) {
	if err := a.fetchScanFindings(); err != nil {
		return nil, err
	}
	if a.scanSeverityCountsCache == nil {
		return nil, nil
	}
	counts := make(map[string]any)
	for k, v := range a.scanSeverityCountsCache {
		counts[k] = int64(v)
	}
	return counts, nil
}

func (a *mqlAwsEcrImageScanFinding) id() (string, error) {
	return a.__id, nil
}

// ==================== ECR Registry Scanning Configuration ====================

func (a *mqlAwsEcr) scanningConfiguration() (*mqlAwsEcrScanningConfiguration, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ecr("")
	ctx := context.Background()

	resp, err := svc.GetRegistryScanningConfiguration(ctx, &ecr.GetRegistryScanningConfigurationInput{})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.ScanningConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	if resp.ScanningConfiguration == nil {
		a.ScanningConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	rules := make([]any, 0, len(resp.ScanningConfiguration.Rules))
	for i, rule := range resp.ScanningConfiguration.Rules {
		filters := make([]any, 0, len(rule.RepositoryFilters))
		for _, f := range rule.RepositoryFilters {
			filters = append(filters, map[string]any{
				"filter":     convert.ToValue(f.Filter),
				"filterType": string(f.FilterType),
			})
		}

		mqlRule, err := CreateResource(a.MqlRuntime, "aws.ecr.scanningConfiguration.rule",
			map[string]*llx.RawData{
				"__id":              llx.StringData(fmt.Sprintf("aws.ecr.scanningConfiguration.rule/%d", i)),
				"scanFrequency":     llx.StringData(string(rule.ScanFrequency)),
				"repositoryFilters": llx.ArrayData(filters, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		rules = append(rules, mqlRule)
	}

	mqlConfig, err := CreateResource(a.MqlRuntime, "aws.ecr.scanningConfiguration",
		map[string]*llx.RawData{
			"__id":     llx.StringData("aws.ecr.scanningConfiguration"),
			"scanType": llx.StringData(string(resp.ScanningConfiguration.ScanType)),
			"rules":    llx.ArrayData(rules, types.Resource("aws.ecr.scanningConfiguration.rule")),
		})
	if err != nil {
		return nil, err
	}
	return mqlConfig.(*mqlAwsEcrScanningConfiguration), nil
}

func (a *mqlAwsEcrScanningConfiguration) id() (string, error) {
	return "aws.ecr.scanningConfiguration", nil
}

func (a *mqlAwsEcrScanningConfigurationRule) id() (string, error) {
	return a.__id, nil
}

func initAwsEcrRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEcrRepository); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch ecr repository")
	}

	if cached := cachedArgByArn(runtime, ResourceAwsEcrRepository, args); cached != nil {
		return args, cached, nil
	}

	// When an ARN is supplied, the registry kind (private vs public), region,
	// and repository name are all encoded in it, so we can issue a single
	// targeted DescribeRepositories call instead of listing every repository in
	// every region (plus all public repos).
	if args["arn"] != nil {
		arnVal, _ := args["arn"].Value.(string)
		if parsed, err := arn.Parse(arnVal); err == nil && strings.HasPrefix(parsed.Resource, "repository/") {
			name := strings.TrimPrefix(parsed.Resource, "repository/")
			conn := runtime.Connection.(*connection.AwsConnection)
			switch parsed.Service {
			case "ecr-public":
				svc := conn.EcrPublic("us-east-1") // only supported for us-east-1
				resp, err := svc.DescribeRepositories(context.Background(), &ecrpublic.DescribeRepositoriesInput{
					RegistryId:      aws.String(conn.AccountId()),
					RepositoryNames: []string{name},
				}, withEcrPublicDescribeRetries)
				if err != nil {
					// Surface unexpected errors; on access-denied or a stale ARN
					// (RepositoryNotFoundException) fall through to the list-scan.
					if !Is400AccessDeniedError(err) && !isResourceNotFoundError(err) {
						return nil, nil, err
					}
				} else if len(resp.Repositories) > 0 {
					r, err := buildEcrPublicRepositoryResource(runtime, resp.Repositories[0])
					if err != nil {
						return nil, nil, err
					}
					return args, r, nil
				}
			case "ecr":
				svc := conn.Ecr(parsed.Region)
				resp, err := svc.DescribeRepositories(context.Background(), &ecr.DescribeRepositoriesInput{
					RepositoryNames: []string{name},
				}, withEcrDescribeRetries)
				if err != nil {
					// Surface unexpected errors; on access-denied or a stale ARN
					// (RepositoryNotFoundException) fall through to the list-scan.
					if !Is400AccessDeniedError(err) && !isResourceNotFoundError(err) {
						return nil, nil, err
					}
				} else if len(resp.Repositories) > 0 {
					r, err := buildEcrPrivateRepositoryResource(runtime, parsed.Region, resp.Repositories[0])
					if err != nil {
						return nil, nil, err
					}
					return args, r, nil
				}
			}
		}
	}

	// Fallback: list private + public repositories and scan (e.g. when called
	// with only a name and no ARN, or the targeted lookup was denied/not found).
	obj, err := CreateResource(runtime, ResourceAwsEcr, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	e := obj.(*mqlAwsEcr)

	repos := []any{}
	var lastErr error
	if priv, err := e.privateRepositories(); err == nil {
		repos = append(repos, priv...)
	} else {
		lastErr = err
	}
	if pub, err := e.publicRepositories(); err == nil {
		repos = append(repos, pub...)
	} else {
		lastErr = err
	}
	if len(repos) == 0 && lastErr != nil {
		return nil, nil, fmt.Errorf("failed to list ecr repositories: %w", lastErr)
	}

	var arnVal, nameVal string
	if args["arn"] != nil {
		arnVal, _ = args["arn"].Value.(string)
	}
	if args["name"] != nil {
		nameVal, _ = args["name"].Value.(string)
	}
	for _, raw := range repos {
		r := raw.(*mqlAwsEcrRepository)
		if (arnVal != "" && r.Arn.Data == arnVal) || (nameVal != "" && r.Name.Data == nameVal) {
			return args, r, nil
		}
	}
	return nil, nil, errors.New("ecr repository does not exist")
}
