// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsCloudfront) id() (string, error) {
	return "aws.cloudfront", nil
}

type mqlAwsCloudfrontInternal struct {
	domainIndexMu    sync.Mutex
	domainIndexBuilt bool
	domainIndex      map[string]*mqlAwsCloudfrontDistribution
}

// distributionByDomainName returns the distribution whose domain name matches
// the given already-normalized DNS name, or nil when none matches. It builds a
// normalized-domain-name index on first call and reuses it afterwards. The index
// lives on the aws.cloudfront list resource, which the runtime caches, so many
// callers (for example Route 53 alias records) share one index instead of each
// rescanning every distribution.
func (a *mqlAwsCloudfront) distributionByDomainName(normalized string) (*mqlAwsCloudfrontDistribution, error) {
	a.domainIndexMu.Lock()
	defer a.domainIndexMu.Unlock()

	if !a.domainIndexBuilt {
		dists := a.GetDistributions()
		if dists.Error != nil {
			return nil, dists.Error
		}
		idx := make(map[string]*mqlAwsCloudfrontDistribution, len(dists.Data))
		for _, d := range dists.Data {
			dist, ok := d.(*mqlAwsCloudfrontDistribution)
			if !ok {
				continue
			}
			domainName := dist.GetDomainName()
			if domainName.Error != nil {
				return nil, domainName.Error
			}
			if domainName.Data != "" {
				idx[normalizeAliasDNSName(domainName.Data)] = dist
			}
		}
		a.domainIndex = idx
		a.domainIndexBuilt = true
	}
	return a.domainIndex[normalized], nil
}

func (a *mqlAwsCloudfrontDistribution) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsCloudfrontDistributionOrigin) id() (string, error) {
	account := a.Account.Data
	id := a.Id.Data
	return account + "/" + id, nil
}

// cloudfrontOriginTls reports how CloudFront reaches a custom origin. The
// origin leg is configured independently of the viewer leg, so a distribution
// can enforce HTTPS to viewers while fetching from the origin in plaintext or
// over a deprecated TLS version. S3 origins served through the S3 origin config
// carry no custom origin config and yield an empty policy and no protocols,
// rather than a policy that would read as plaintext.
func cloudfrontOriginTls(config *cftypes.CustomOriginConfig) (string, []any) {
	protocols := []any{}
	if config == nil {
		return "", protocols
	}
	if config.OriginSslProtocols != nil {
		for _, p := range config.OriginSslProtocols.Items {
			protocols = append(protocols, string(p))
		}
	}
	return string(config.OriginProtocolPolicy), protocols
}

func (a *mqlAwsCloudfront) distributions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Cloudfront("") // global service
	ctx := context.Background()
	res := []any{}

	params := &cloudfront.ListDistributionsInput{}
	paginator := cloudfront.NewListDistributionsPaginator(svc, params)
	for paginator.HasMorePages() {
		distributions, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather aws cloudfront distributions")
		}

		if distributions.DistributionList == nil {
			continue
		}
		for _, distribution := range distributions.DistributionList.Items {
			origins := []any{}
			if or := distribution.Origins; or != nil {
				for _, origin := range distribution.Origins.Items {
					var oai string
					if origin.S3OriginConfig != nil && origin.S3OriginConfig.OriginAccessIdentity != nil {
						oai = *origin.S3OriginConfig.OriginAccessIdentity
					}
					originProtocolPolicy, originSslProtocols := cloudfrontOriginTls(origin.CustomOriginConfig)
					mqlAwsCloudfrontOrigin, err := CreateResource(a.MqlRuntime, "aws.cloudfront.distribution.origin",
						map[string]*llx.RawData{
							// Origin.Id is documented as unique only *within* a
							// distribution, so the key must name the distribution.
							// Reusing an origin id like "S3Origin" across distributions
							// is routine, and the collision also lets the
							// cacheOriginMtlsCertArn write below land on another
							// distribution's already-emitted origin.
							"__id":                  llx.StringData(convert.ToValue(distribution.ARN) + "/origin/" + convert.ToValue(origin.Id)),
							"domainName":            llx.StringDataPtr(origin.DomainName),
							"id":                    llx.StringDataPtr(origin.Id),
							"connectionAttempts":    llx.IntDataDefault(origin.ConnectionAttempts, 0),
							"connectionTimeout":     llx.IntDataDefault(origin.ConnectionTimeout, 0),
							"originPath":            llx.StringDataPtr(origin.OriginPath),
							"account":               llx.StringData(conn.AccountId()),
							"originAccessControlId": llx.StringDataPtr(origin.OriginAccessControlId),
							"originAccessIdentity":  llx.StringData(oai),
							"originProtocolPolicy":  llx.StringData(originProtocolPolicy),
							"originSslProtocols":    llx.ArrayData(originSslProtocols, types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlOrigin := mqlAwsCloudfrontOrigin.(*mqlAwsCloudfrontDistributionOrigin)
					if origin.CustomOriginConfig != nil && origin.CustomOriginConfig.OriginMtlsConfig != nil {
						mqlOrigin.cacheOriginMtlsCertArn = convert.ToValue(origin.CustomOriginConfig.OriginMtlsConfig.ClientCertificateArn)
					}
					origins = append(origins, mqlAwsCloudfrontOrigin)
				}
			}
			cacheBehaviors := []any{}
			if cb := distribution.CacheBehaviors; cb != nil {
				cacheBehaviors, err = convert.JsonToDictSlice(distribution.CacheBehaviors.Items)
				if err != nil {
					return nil, err
				}
			}
			defaultCacheBehavior, err := convert.JsonToDict(distribution.DefaultCacheBehavior)
			if err != nil {
				return nil, err
			}

			cnames := []any{}
			if distribution.Aliases != nil {
				for _, alias := range distribution.Aliases.Items {
					cnames = append(cnames, alias)
				}
			}

			var viewerProtocolPolicy string
			if distribution.DefaultCacheBehavior != nil {
				viewerProtocolPolicy = string(distribution.DefaultCacheBehavior.ViewerProtocolPolicy)
			}
			var minimumProtocolVersion string
			var sslSupportMethod string
			if distribution.ViewerCertificate != nil {
				minimumProtocolVersion = string(distribution.ViewerCertificate.MinimumProtocolVersion)
				sslSupportMethod = string(distribution.ViewerCertificate.SSLSupportMethod)
			}
			var geoRestrictionType string
			if distribution.Restrictions != nil && distribution.Restrictions.GeoRestriction != nil {
				geoRestrictionType = string(distribution.Restrictions.GeoRestriction.RestrictionType)
			}

			var viewerMtlsMode, viewerMtlsTrustStoreId string
			if distribution.ViewerMtlsConfig != nil {
				viewerMtlsMode = string(distribution.ViewerMtlsConfig.Mode)
				if distribution.ViewerMtlsConfig.TrustStoreConfig != nil {
					viewerMtlsTrustStoreId = convert.ToValue(distribution.ViewerMtlsConfig.TrustStoreConfig.TrustStoreId)
				}
			}

			args := map[string]*llx.RawData{
				"arn":                    llx.StringDataPtr(distribution.ARN),
				"id":                     llx.StringDataPtr(distribution.Id),
				"staging":                llx.BoolDataPtr(distribution.Staging),
				"cacheBehaviors":         llx.ArrayData(cacheBehaviors, types.Any),
				"cnames":                 llx.ArrayData(cnames, types.String),
				"defaultCacheBehavior":   llx.MapData(defaultCacheBehavior, types.Any),
				"domainName":             llx.StringDataPtr(distribution.DomainName),
				"enabled":                llx.BoolDataPtr(distribution.Enabled),
				"httpVersion":            llx.StringData(string(distribution.HttpVersion)),
				"isIPV6Enabled":          llx.BoolDataPtr(distribution.IsIPV6Enabled),
				"origins":                llx.ArrayData(origins, types.Resource("aws.cloudfront.distribution.origin")),
				"priceClass":             llx.StringData(string(distribution.PriceClass)),
				"status":                 llx.StringDataPtr(distribution.Status),
				"viewerProtocolPolicy":   llx.StringData(viewerProtocolPolicy),
				"minimumProtocolVersion": llx.StringData(minimumProtocolVersion),
				"sslSupportMethod":       llx.StringData(sslSupportMethod),
				"webAclId":               llx.StringDataPtr(distribution.WebACLId),
				"geoRestrictionType":     llx.StringData(geoRestrictionType),
				"lastModifiedAt":         llx.TimeDataPtr(distribution.LastModifiedTime),
				"comment":                llx.StringDataPtr(distribution.Comment),
				"viewerMtlsMode":         llx.StringData(viewerMtlsMode),
				"viewerMtlsTrustStoreId": llx.StringData(viewerMtlsTrustStoreId),
			}

			mqlAwsCloudfrontDist, err := CreateResource(a.MqlRuntime, "aws.cloudfront.distribution", args)
			if err != nil {
				return nil, err
			}

			res = append(res, mqlAwsCloudfrontDist)
		}
	}

	return res, nil
}

func (a *mqlAwsCloudfrontDistributionLoggingConfig) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsCloudfrontDistribution) webAcl() (*mqlAwsWafAcl, error) {
	arnVal := a.WebAclId.Data
	// WAFv2 associations store the full ARN; WAF Classic stores a bare ID that
	// the aws.waf.acl resource cannot resolve, so only build the ref for an ARN.
	if !strings.HasPrefix(arnVal, "arn:") {
		a.WebAcl.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.waf.acl",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWafAcl), nil
}

type mqlAwsCloudfrontDistributionInternal struct {
	detailFetched bool
	detailErr     error
	detailLock    sync.Mutex
	detail        *cloudfront.GetDistributionOutput
}

// fetchDistributionDetail lazily loads the full distribution via GetDistribution
// and caches it (double-check locking) so fields backed by the same call —
// logging() and continuousDeploymentPolicyId() — share one API request.
func (a *mqlAwsCloudfrontDistribution) fetchDistributionDetail() (*cloudfront.GetDistributionOutput, error) {
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	a.detailLock.Lock()
	defer a.detailLock.Unlock()
	if a.detailFetched {
		return a.detail, a.detailErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("") // global service
	ctx := context.Background()

	// Extract distribution ID from ARN: arn:aws:cloudfront::ACCOUNT:distribution/DIST_ID
	parsedArn, err := arn.Parse(a.Arn.Data)
	if err != nil {
		a.detailErr = errors.Wrap(err, "could not parse cloudfront distribution ARN")
		a.detailFetched = true
		return nil, a.detailErr
	}
	parts := strings.SplitN(parsedArn.Resource, "/", 2)
	if len(parts) < 2 {
		a.detailErr = fmt.Errorf("unexpected cloudfront distribution ARN resource format: %s", parsedArn.Resource)
		a.detailFetched = true
		return nil, a.detailErr
	}
	distID := parts[1]

	resp, err := svc.GetDistribution(ctx, &cloudfront.GetDistributionInput{Id: &distID})
	if err != nil {
		a.detailErr = errors.Wrap(err, "could not get cloudfront distribution details")
		a.detailFetched = true
		return nil, a.detailErr
	}
	a.detail = resp
	a.detailFetched = true
	return resp, nil
}

func (a *mqlAwsCloudfrontDistribution) continuousDeploymentPolicyId() (string, error) {
	resp, err := a.fetchDistributionDetail()
	if err != nil {
		return "", err
	}
	if resp.Distribution == nil || resp.Distribution.DistributionConfig == nil {
		return "", nil
	}
	return convert.ToValue(resp.Distribution.DistributionConfig.ContinuousDeploymentPolicyId), nil
}

func (a *mqlAwsCloudfrontDistribution) callerReference() (string, error) {
	resp, err := a.fetchDistributionDetail()
	if err != nil {
		return "", err
	}
	if resp.Distribution == nil || resp.Distribution.DistributionConfig == nil {
		return "", nil
	}
	return convert.ToValue(resp.Distribution.DistributionConfig.CallerReference), nil
}

func (a *mqlAwsCloudfrontDistribution) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &cloudfront.ListTagsForResourceInput{
		Resource: &a.Arn.Data,
	})
	if err != nil {
		return nil, classifyAwsError(err, "cloudfront:ListTagsForResource")
	}
	tags := make(map[string]any)
	if resp.Tags != nil {
		for _, t := range resp.Tags.Items {
			tags[convert.ToValue(t.Key)] = convert.ToValue(t.Value)
		}
	}
	return tags, nil
}

func (a *mqlAwsCloudfrontDistribution) managedBy() (string, error) {
	owner, err := managedByFromResourceTags(a.GetTags())
	if err != nil {
		return "", err
	}
	if owner != "" {
		return owner, nil
	}
	// CloudFront injects no provenance tag, but Terraform sets the distribution
	// caller reference to a "terraform-" prefixed value; fall back to that.
	cr := a.GetCallerReference()
	if cr.Error != nil {
		return "", cr.Error
	}
	return managedByWithCreationToken("", cr.Data), nil
}

func (a *mqlAwsCloudfrontDistribution) logging() (*mqlAwsCloudfrontDistributionLoggingConfig, error) {
	resp, err := a.fetchDistributionDetail()
	if err != nil {
		return nil, err
	}

	if resp.Distribution == nil || resp.Distribution.DistributionConfig == nil || resp.Distribution.DistributionConfig.Logging == nil {
		a.Logging.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	logging := resp.Distribution.DistributionConfig.Logging
	mqlLogging, err := CreateResource(a.MqlRuntime, ResourceAwsCloudfrontDistributionLoggingConfig,
		map[string]*llx.RawData{
			"__id":           llx.StringData(a.Arn.Data + "/logging"),
			"enabled":        llx.BoolDataPtr(logging.Enabled),
			"bucket":         llx.StringDataPtr(logging.Bucket),
			"prefix":         llx.StringDataPtr(logging.Prefix),
			"includeCookies": llx.BoolDataPtr(logging.IncludeCookies),
		})
	if err != nil {
		return nil, err
	}
	return mqlLogging.(*mqlAwsCloudfrontDistributionLoggingConfig), nil
}

func (a *mqlAwsCloudfrontFunction) id() (string, error) {
	// ARN is the same for the DEVELOPMENT and LIVE versions of a function, so
	// `ListFunctions` returns the same function twice on a published function.
	// Composite the stage into the cache key so both versions surface as
	// distinct rows instead of one silently overwriting the other.
	if a.Stage.Data == "" {
		return a.Arn.Data, nil
	}
	return a.Arn.Data + ":" + a.Stage.Data, nil
}

func (a *mqlAwsCloudfrontFunction) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &cloudfront.ListTagsForResourceInput{
		Resource: &a.Arn.Data,
	})
	if err != nil {
		return nil, classifyAwsError(err, "cloudfront:ListTagsForResource")
	}
	tags := make(map[string]any)
	if resp.Tags != nil {
		for _, tag := range resp.Tags.Items {
			if tag.Key != nil {
				val := ""
				if tag.Value != nil {
					val = *tag.Value
				}
				tags[*tag.Key] = val
			}
		}
	}
	return tags, nil
}

func (a *mqlAwsCloudfront) functions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Cloudfront("") // global service
	ctx := context.Background()
	res := []any{}

	// the AWS SDK does not have a paginator for this function
	var marker *string
	for {
		functions, err := svc.ListFunctions(ctx, &cloudfront.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, errors.Wrap(err, "could not gather aws cloudfront functions")
		}

		if functions.FunctionList == nil {
			break
		}

		for i := range functions.FunctionList.Items {
			funct := functions.FunctionList.Items[i]
			var stage, comment, runtime string
			var lmTime, crTime *time.Time
			var arn *string
			if metadata := funct.FunctionMetadata; metadata != nil {
				lmTime = metadata.LastModifiedTime
				crTime = metadata.CreatedTime
				stage = string(metadata.Stage)
				arn = metadata.FunctionARN
			}
			if arn == nil {
				constructed := fmt.Sprintf("arn:aws:cloudfront::%s:function/%s", conn.AccountId(), convert.ToValue(funct.Name))
				arn = &constructed
			}
			if config := funct.FunctionConfig; config != nil {
				comment = convert.ToValue(config.Comment)
				runtime = string(config.Runtime)
			}

			args := map[string]*llx.RawData{
				"name":             llx.StringDataPtr(funct.Name),
				"status":           llx.StringDataPtr(funct.Status),
				"lastModifiedTime": llx.TimeDataPtr(lmTime),
				"createdAt":        llx.TimeDataPtr(crTime),
				"stage":            llx.StringData(stage),
				"comment":          llx.StringData(comment),
				"runtime":          llx.StringData(runtime),
				"arn":              llx.StringDataPtr(arn),
			}

			mqlAwsCloudfrontDist, err := CreateResource(a.MqlRuntime, "aws.cloudfront.function", args)
			if err != nil {
				return nil, err
			}

			res = append(res, mqlAwsCloudfrontDist)
		}
		if functions.FunctionList.NextMarker == nil {
			break
		}
		marker = functions.FunctionList.NextMarker
	}

	return res, nil
}

func (a *mqlAwsCloudfrontAnycastIpList) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsCloudfrontAnycastIpListInternal struct {
	cacheId string
}

func (a *mqlAwsCloudfront) anycastIpLists() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("") // global service
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListAnycastIpLists(ctx, &cloudfront.ListAnycastIpListsInput{
			Marker:   marker,
			MaxItems: aws.Int32(100),
		})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "cloudfront:ListAnycastIpLists"), "could not list cloudfront anycast ip lists")
		}

		if resp.AnycastIpLists == nil {
			break
		}

		for _, item := range resp.AnycastIpLists.Items {
			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.anycastIpList",
				map[string]*llx.RawData{
					"arn":            llx.StringDataPtr(item.Arn),
					"id":             llx.StringDataPtr(item.Id),
					"name":           llx.StringDataPtr(item.Name),
					"status":         llx.StringDataPtr(item.Status),
					"ipCount":        llx.IntDataDefault(item.IpCount, 0),
					"lastModifiedAt": llx.TimeDataPtr(item.LastModifiedTime),
					"region":         llx.StringData("global"),
				})
			if err != nil {
				return nil, err
			}
			typed := mqlResource.(*mqlAwsCloudfrontAnycastIpList)
			typed.cacheId = aws.ToString(item.Id)
			res = append(res, typed)
		}

		if resp.AnycastIpLists.NextMarker == nil {
			break
		}
		marker = resp.AnycastIpLists.NextMarker
	}
	return res, nil
}

func (a *mqlAwsCloudfrontAnycastIpList) anycastIps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	id := a.cacheId
	resp, err := svc.GetAnycastIpList(ctx, &cloudfront.GetAnycastIpListInput{
		Id: &id,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not get cloudfront anycast ip list")
	}
	if resp.AnycastIpList == nil {
		return []any{}, nil
	}
	return toInterfaceArr(resp.AnycastIpList.AnycastIps), nil
}

func (a *mqlAwsCloudfrontAnycastIpList) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &cloudfront.ListTagsForResourceInput{
		Resource: &a.Arn.Data,
	})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]any)
	if resp.Tags != nil {
		for _, tag := range resp.Tags.Items {
			if tag.Key != nil {
				val := ""
				if tag.Value != nil {
					val = *tag.Value
				}
				tags[*tag.Key] = val
			}
		}
	}
	return tags, nil
}

func initAwsCloudfrontDistribution(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformCloudfrontDistribution); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch cloudfront distribution")
	}

	obj, err := CreateResource(runtime, "aws.cloudfront", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	cf := obj.(*mqlAwsCloudfront)
	rawResources := cf.GetDistributions()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}
	for _, rawResource := range rawResources.Data {
		distribution := rawResource.(*mqlAwsCloudfrontDistribution)
		if distribution.Arn.Data == arnVal {
			return args, distribution, nil
		}
	}
	return nil, nil, errors.New("cloudfront distribution does not exist")
}

// Origin mTLS client certificate (typed reference)

type mqlAwsCloudfrontDistributionOriginInternal struct {
	cacheOriginMtlsCertArn string
}

func (a *mqlAwsCloudfrontDistributionOrigin) originMtlsClientCertificate() (*mqlAwsAcmCertificate, error) {
	if a.cacheOriginMtlsCertArn == "" {
		a.OriginMtlsClientCertificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlCert, err := NewResource(a.MqlRuntime, "aws.acm.certificate",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheOriginMtlsCertArn)})
	if err != nil {
		return nil, err
	}
	return mqlCert.(*mqlAwsAcmCertificate), nil
}

// Trust stores

func (a *mqlAwsCloudfrontTrustStore) id() (string, error) {
	return a.Arn.Data, nil
}

// useClientCertificateOcspEndpoint is resolved lazily because ListTrustStores
// only returns summaries; the OCSP setting requires a GetTrustStore call.
func (a *mqlAwsCloudfrontTrustStore) useClientCertificateOcspEndpoint() (bool, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("") // global service
	resp, err := svc.GetTrustStore(context.Background(), &cloudfront.GetTrustStoreInput{
		Identifier: &a.Id.Data,
	})
	if err != nil {
		return false, err
	}
	if resp.TrustStore == nil {
		return false, nil
	}
	return convert.ToValue(resp.TrustStore.UseClientCertificateOCSPEndpoint), nil
}

func (a *mqlAwsCloudfront) trustStores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("") // global service
	ctx := context.Background()
	res := []any{}

	var marker *string
	for {
		resp, err := svc.ListTrustStores(ctx, &cloudfront.ListTrustStoresInput{
			Marker: marker,
		})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "cloudfront:ListTrustStores"), "could not gather aws cloudfront trust stores")
		}
		for _, ts := range resp.TrustStoreList {
			mqlTs, err := CreateResource(a.MqlRuntime, "aws.cloudfront.trustStore",
				map[string]*llx.RawData{
					"__id":                   llx.StringDataPtr(ts.Arn),
					"id":                     llx.StringDataPtr(ts.Id),
					"arn":                    llx.StringDataPtr(ts.Arn),
					"name":                   llx.StringDataPtr(ts.Name),
					"status":                 llx.StringData(string(ts.Status)),
					"numberOfCaCertificates": llx.IntDataDefault(ts.NumberOfCaCertificates, 0),
					"reason":                 llx.StringDataPtr(ts.Reason),
					"lastModifiedAt":         llx.TimeDataPtr(ts.LastModifiedTime),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTs)
		}
		if resp.NextMarker == nil {
			break
		}
		marker = resp.NextMarker
	}
	return res, nil
}

func (a *mqlAwsCloudfrontDistribution) protectedByWaf() (bool, error) {
	webAclId := a.GetWebAclId()
	if webAclId.Error != nil {
		return false, webAclId.Error
	}
	return webAclId.Data != "", nil
}

// enforcesHttps reports whether every cache behavior — the default plus any
// additional behaviors — requires viewers to use HTTPS. A single allow-all
// behavior leaves a plaintext path open, so all are checked.
func (a *mqlAwsCloudfrontDistribution) enforcesHttps() (bool, error) {
	policy := a.GetViewerProtocolPolicy()
	if policy.Error != nil {
		return false, policy.Error
	}
	if !viewerPolicyEnforcesHttps(policy.Data) {
		return false, nil
	}

	cacheBehaviors := a.GetCacheBehaviors()
	if cacheBehaviors.Error != nil {
		return false, cacheBehaviors.Error
	}
	for _, cb := range cacheBehaviors.Data {
		behavior, ok := cb.(map[string]any)
		if !ok {
			continue
		}
		// aws-sdk-go-v2 types carry no json tags, so JsonToDict preserves the
		// Go field name "ViewerProtocolPolicy".
		if vp, ok := behavior["ViewerProtocolPolicy"].(string); ok && !viewerPolicyEnforcesHttps(vp) {
			return false, nil
		}
	}
	return true, nil
}
