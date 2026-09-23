// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
	catypes "github.com/aws/aws-sdk-go-v2/service/codeartifact/types"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsCodeartifact) id() (string, error) {
	return "aws.codeartifact", nil
}

// caPackageFormats lists the package formats we probe for endpoint URLs.
// CodeArtifact does not list the per-repository active formats up front;
// GetRepositoryEndpoint(format) is called once per format and the formats
// the repo does not host return ConflictException, which is handled as
// "not present" without surfacing as an error.
var caPackageFormats = []catypes.PackageFormat{
	catypes.PackageFormatNpm,
	catypes.PackageFormatPypi,
	catypes.PackageFormatMaven,
	catypes.PackageFormatNuget,
	catypes.PackageFormatGeneric,
	catypes.PackageFormatRuby,
	catypes.PackageFormatSwift,
	catypes.PackageFormatCargo,
}

// ===== domains =====

func (a *mqlAwsCodeartifact) domains() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDomains(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCodeartifact) getDomains(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Codeartifact(region)
			ctx := context.Background()

			res := []any{}
			paginator := codeartifact.NewListDomainsPaginator(svc, &codeartifact.ListDomainsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("codeartifact is not available in region")
						return res, nil
					}
					return nil, err
				}
				for i := range page.Domains {
					summary := page.Domains[i]
					if summary.Name == nil || summary.Owner == nil {
						continue
					}
					mqlDomain, err := newMqlAwsCodeartifactDomain(a.MqlRuntime, region, *summary.Name, *summary.Owner)
					if err != nil {
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Str("domain", *summary.Name).Msg("error accessing domain for AWS API")
							continue
						}
						return nil, err
					}
					if mqlDomain == nil {
						continue
					}
					res = append(res, mqlDomain)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsCodeartifactDomain(runtime *plugin.Runtime, region, name, owner string) (plugin.Resource, error) {
	ctx := context.Background()
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Codeartifact(region)

	out, err := svc.DescribeDomain(ctx, &codeartifact.DescribeDomainInput{
		Domain:      &name,
		DomainOwner: &owner,
	})
	if err != nil {
		return nil, err
	}
	if out.Domain == nil {
		return nil, nil
	}
	d := out.Domain
	arn := ""
	if d.Arn != nil {
		arn = *d.Arn
	}

	tags := map[string]any{}
	if arn != "" {
		tagOut, err := svc.ListTagsForResource(ctx, &codeartifact.ListTagsForResourceInput{ResourceArn: &arn})
		if err != nil {
			if !Is400AccessDeniedError(err) {
				return nil, err
			}
		} else {
			for _, t := range tagOut.Tags {
				tags[convert.ToValue(t.Key)] = convert.ToValue(t.Value)
			}
		}
	}

	args := map[string]*llx.RawData{
		"__id":            llx.StringData(arn),
		"arn":             llx.StringData(arn),
		"name":            llx.StringDataPtr(d.Name),
		"owner":           llx.StringDataPtr(d.Owner),
		"region":          llx.StringData(region),
		"status":          llx.StringData(string(d.Status)),
		"createdTime":     llx.TimeDataPtr(d.CreatedTime),
		"encryptionKey":   llx.StringDataPtr(d.EncryptionKey),
		"repositoryCount": llx.IntData(int64(d.RepositoryCount)),
		"assetSizeBytes":  llx.IntData(d.AssetSizeBytes),
		"tags":            llx.MapData(tags, types.String),
	}

	obj, err := CreateResource(runtime, "aws.codeartifact.domain", args)
	if err != nil {
		return nil, err
	}
	obj.(*mqlAwsCodeartifactDomain).cacheS3BucketArn = convert.ToValue(d.S3BucketArn)
	mqlDomain := obj.(*mqlAwsCodeartifactDomain)
	mqlDomain.cacheKmsKeyArn = d.EncryptionKey
	mqlDomain.cacheDomainName = name
	mqlDomain.cacheDomainOwner = owner
	mqlDomain.cacheRegion = region
	return mqlDomain, nil
}

func (a *mqlAwsCodeartifactDomain) s3Bucket() (*mqlAwsS3Bucket, error) {
	arnVal := a.cacheS3BucketArn
	if arnVal == "" {
		a.S3Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsCodeartifactDomain) id() (string, error) {
	return a.Arn.Data, nil
}

func initAwsCodeartifactDomain(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Only skip the lookup when the caller already supplied the identity we
	// would resolve. repository.domain() passes name+owner+region (3 args), so a
	// bare `len(args) > 2` fast path skipped the fetch and produced a husk whose
	// id() (the unset arn) was empty, aliasing every repository's domain.
	if args["arn"] != nil {
		return args, nil, nil
	}
	name := rawStringArg(args["name"])
	region := rawStringArg(args["region"])
	owner := rawStringArg(args["owner"])
	if name == "" || region == "" || owner == "" {
		return args, nil, nil
	}
	mqlDomain, err := newMqlAwsCodeartifactDomain(runtime, region, name, owner)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlDomain, nil
}

type mqlAwsCodeartifactDomainInternal struct {
	cacheS3BucketArn string
	cacheKmsKeyArn   *string
	cacheDomainName  string
	cacheDomainOwner string
	cacheRegion      string

	policyOnce sync.Once
	policyDoc  any
	policyErr  error
}

func (a *mqlAwsCodeartifactDomain) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == nil || *a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsCodeartifactDomain) policy() (any, error) {
	a.policyOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Codeartifact(a.cacheRegion)
		ctx := context.Background()
		out, err := svc.GetDomainPermissionsPolicy(ctx, &codeartifact.GetDomainPermissionsPolicyInput{
			Domain:      &a.cacheDomainName,
			DomainOwner: &a.cacheDomainOwner,
		})
		if err != nil {
			if isCodeArtifactNotFound(err) {
				return
			}
			a.policyErr = classifyAwsError(err, "codeartifact:GetDomainPermissionsPolicy")
			return
		}
		if out.Policy == nil {
			return
		}
		a.policyDoc = map[string]any{
			"document":    convert.ToValue(out.Policy.Document),
			"resourceArn": convert.ToValue(out.Policy.ResourceArn),
			"revision":    convert.ToValue(out.Policy.Revision),
		}
	})
	if a.policyErr != nil {
		return nil, a.policyErr
	}
	return a.policyDoc, nil
}

// ===== repositories =====

func (a *mqlAwsCodeartifact) repositories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getRepositories(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCodeartifact) getRepositories(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Codeartifact(region)
			ctx := context.Background()

			res := []any{}
			paginator := codeartifact.NewListRepositoriesPaginator(svc, &codeartifact.ListRepositoriesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("codeartifact is not available in region")
						return res, nil
					}
					return nil, err
				}
				for i := range page.Repositories {
					summary := page.Repositories[i]
					if summary.Name == nil || summary.DomainName == nil || summary.DomainOwner == nil {
						continue
					}
					mqlRepo, err := newMqlAwsCodeartifactRepository(a.MqlRuntime, region,
						*summary.DomainName, *summary.DomainOwner, *summary.Name)
					if err != nil {
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Str("repository", *summary.Name).Msg("error accessing repository for AWS API")
							continue
						}
						return nil, err
					}
					if mqlRepo == nil {
						continue
					}
					res = append(res, mqlRepo)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsCodeartifactRepository(runtime *plugin.Runtime, region, domainName, domainOwner, name string) (plugin.Resource, error) {
	ctx := context.Background()
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Codeartifact(region)

	out, err := svc.DescribeRepository(ctx, &codeartifact.DescribeRepositoryInput{
		Domain:      &domainName,
		DomainOwner: &domainOwner,
		Repository:  &name,
	})
	if err != nil {
		return nil, err
	}
	if out.Repository == nil {
		return nil, nil
	}
	r := out.Repository

	arn := ""
	if r.Arn != nil {
		arn = *r.Arn
	}

	upstreams := make([]any, 0, len(r.Upstreams))
	for i := range r.Upstreams {
		upstreams = append(upstreams, map[string]any{
			"repositoryName": convert.ToValue(r.Upstreams[i].RepositoryName),
		})
	}
	conns := make([]any, 0, len(r.ExternalConnections))
	for i := range r.ExternalConnections {
		conns = append(conns, map[string]any{
			"externalConnectionName": convert.ToValue(r.ExternalConnections[i].ExternalConnectionName),
			"packageFormat":          string(r.ExternalConnections[i].PackageFormat),
			"status":                 string(r.ExternalConnections[i].Status),
		})
	}

	tags := map[string]any{}
	if arn != "" {
		tagOut, err := svc.ListTagsForResource(ctx, &codeartifact.ListTagsForResourceInput{ResourceArn: &arn})
		if err != nil {
			if !Is400AccessDeniedError(err) {
				return nil, err
			}
		} else {
			for _, t := range tagOut.Tags {
				tags[convert.ToValue(t.Key)] = convert.ToValue(t.Value)
			}
		}
	}

	args := map[string]*llx.RawData{
		"__id":                 llx.StringData(arn),
		"arn":                  llx.StringData(arn),
		"name":                 llx.StringDataPtr(r.Name),
		"region":               llx.StringData(region),
		"administratorAccount": llx.StringDataPtr(r.AdministratorAccount),
		"domainName":           llx.StringDataPtr(r.DomainName),
		"domainOwner":          llx.StringDataPtr(r.DomainOwner),
		"description":          llx.StringDataPtr(r.Description),
		"createdTime":          llx.TimeDataPtr(r.CreatedTime),
		"upstreams":            llx.ArrayData(upstreams, types.Dict),
		"externalConnections":  llx.ArrayData(conns, types.Dict),
		"tags":                 llx.MapData(tags, types.String),
	}

	obj, err := CreateResource(runtime, "aws.codeartifact.repository", args)
	if err != nil {
		return nil, err
	}
	mqlRepo := obj.(*mqlAwsCodeartifactRepository)
	mqlRepo.cacheDomainName = domainName
	mqlRepo.cacheDomainOwner = domainOwner
	mqlRepo.cacheRepoName = name
	mqlRepo.cacheRegion = region
	return mqlRepo, nil
}

func (a *mqlAwsCodeartifactRepository) id() (string, error) {
	return a.Arn.Data, nil
}

func initAwsCodeartifactRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	name := rawStringArg(args["name"])
	domainName := rawStringArg(args["domainName"])
	domainOwner := rawStringArg(args["domainOwner"])
	region := rawStringArg(args["region"])
	if name == "" || domainName == "" || domainOwner == "" || region == "" {
		return args, nil, nil
	}
	mqlRepo, err := newMqlAwsCodeartifactRepository(runtime, region, domainName, domainOwner, name)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlRepo, nil
}

type mqlAwsCodeartifactRepositoryInternal struct {
	cacheDomainName  string
	cacheDomainOwner string
	cacheRepoName    string
	cacheRegion      string

	policyOnce sync.Once
	policyDoc  any
	policyErr  error

	endpointsOnce sync.Once
	endpointsData map[string]any
	endpointsErr  error
}

func (a *mqlAwsCodeartifactRepository) domain() (*mqlAwsCodeartifactDomain, error) {
	if a.cacheDomainName == "" || a.cacheDomainOwner == "" || a.cacheRegion == "" {
		a.Domain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.codeartifact.domain", map[string]*llx.RawData{
		"name":   llx.StringData(a.cacheDomainName),
		"owner":  llx.StringData(a.cacheDomainOwner),
		"region": llx.StringData(a.cacheRegion),
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Domain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAwsCodeartifactDomain), nil
}

func (a *mqlAwsCodeartifactRepository) policy() (any, error) {
	a.policyOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Codeartifact(a.cacheRegion)
		ctx := context.Background()
		out, err := svc.GetRepositoryPermissionsPolicy(ctx, &codeartifact.GetRepositoryPermissionsPolicyInput{
			Domain:      &a.cacheDomainName,
			DomainOwner: &a.cacheDomainOwner,
			Repository:  &a.cacheRepoName,
		})
		if err != nil {
			if isCodeArtifactNotFound(err) {
				return
			}
			a.policyErr = classifyAwsError(err, "codeartifact:GetRepositoryPermissionsPolicy")
			return
		}
		if out.Policy == nil {
			return
		}
		a.policyDoc = map[string]any{
			"document":    convert.ToValue(out.Policy.Document),
			"resourceArn": convert.ToValue(out.Policy.ResourceArn),
			"revision":    convert.ToValue(out.Policy.Revision),
		}
	})
	if a.policyErr != nil {
		return nil, a.policyErr
	}
	return a.policyDoc, nil
}

func (a *mqlAwsCodeartifactRepository) endpoints() (map[string]any, error) {
	a.endpointsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Codeartifact(a.cacheRegion)
		ctx := context.Background()
		result := map[string]any{}
		for _, pkgFormat := range caPackageFormats {
			out, err := svc.GetRepositoryEndpoint(ctx, &codeartifact.GetRepositoryEndpointInput{
				Domain:      &a.cacheDomainName,
				DomainOwner: &a.cacheDomainOwner,
				Repository:  &a.cacheRepoName,
				Format:      pkgFormat,
			})
			if err != nil {
				if isCodeArtifactNotFound(err) || isCodeArtifactValidation(err) {
					continue
				}
				a.endpointsErr = classifyAwsError(err, "codeartifact:GetRepositoryEndpoint")
				return
			}
			if out.RepositoryEndpoint != nil && *out.RepositoryEndpoint != "" {
				result[string(pkgFormat)] = *out.RepositoryEndpoint
			}
		}
		a.endpointsData = result
	})
	if a.endpointsErr != nil {
		return nil, a.endpointsErr
	}
	return a.endpointsData, nil
}

// ===== helpers =====

// isCodeArtifactNotFound returns true for ResourceNotFoundException, which the
// permissions-policy APIs return when no policy is attached to the domain or
// repository. Treated as "no policy" rather than a real error.
func isCodeArtifactNotFound(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "ResourceNotFoundException"
	}
	return false
}

// isCodeArtifactValidation returns true for ValidationException, which
// GetRepositoryEndpoint returns when the repository has no configuration for
// the requested package format. Treated as "no endpoint for that format".
func isCodeArtifactValidation(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "ValidationException"
	}
	return false
}
