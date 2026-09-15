// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	smithy "github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/providers/network/resources/certificates"
	"go.mondoo.com/mql/v13/types"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/util/cert"
)

const (
	vpcArnPattern                 = "arn:aws:vpc:%s:%s:id/%s"
	elbv1LbArnPattern             = "arn:aws:elasticloadbalancing:%s:%s:loadbalancer/classic/%s"
	cloudwatchAlarmArnPattern     = "arn:aws:cloudwatch:%s:%s:metricalarm/%s/%s"
	ec2InstanceArnPattern         = "arn:aws:ec2:%s:%s:instance/%s"
	securityGroupArnPattern       = "arn:aws:ec2:%s:%s:security-group/%s"
	volumeArnPattern              = "arn:aws:ec2:%s:%s:volume/%s"
	snapshotArnPattern            = "arn:aws:ec2:%s:%s:snapshot/%s"
	internetGwArnPattern          = "arn:aws:ec2:%s:%s:gateway/%s"
	vpnConnArnPattern             = "arn:aws:ec2:%s:%s:vpn-connection/%s"
	networkAclArnPattern          = "arn:aws:ec2:%s:%s:network-acl/%s"
	imageArnPattern               = "arn:aws:ec2:%s:%s:image/%s"
	keypairArnPattern             = "arn:aws:ec2:%s:%s:keypair/%s"
	subnetArnPattern              = "arn:aws:ec2:%s:%s:subnet/%s"
	routeTableArnPattern          = "arn:aws:ec2:%s:%s:route-table/%s"
	s3ArnPattern                  = "arn:aws:s3:::%s"
	dynamoTableArnPattern         = "arn:aws:dynamodb:%s:%s:table/%s"
	limitsArn                     = "arn:aws:dynamodb:%s:%s"
	dynamoGlobalTableArnPattern   = "arn:aws:dynamodb:-:%s:globaltable/%s"
	rdsInstanceArnPattern         = "arn:aws:rds:%s:%s:db:%s"
	apiArnPattern                 = "arn:aws:apigateway:%s:%s::/apis/%s"
	apiStageArnPattern            = "arn:aws:apigateway:%s:%s::/apis/%s/stages/%s"
	apiAuthorizerArnPattern       = "arn:aws:apigateway:%s:%s::/restapis/%s/authorizers/%s"
	apiRequestValidatorArnPattern = "arn:aws:apigateway:%s:%s::/restapis/%s/requestvalidators/%s"
	apiKeyArnPattern              = "arn:aws:apigateway:%s:%s::/apikeys/%s"
	apiUsagePlanArnPattern        = "arn:aws:apigateway:%s:%s::/usageplans/%s"
	apiVpcLinkArnPattern          = "arn:aws:apigateway:%s:%s::/vpclinks/%s"
	transitGatewayArnPattern      = "arn:aws:ec2:%s:%s:transit-gateway/%s"
	efsFilesystemArnPattern       = "arn:aws:elasticfilesystem:%s:%s:file-system/%s"
	fsxFilesystemArnPattern       = "arn:aws:fsx:%s:%s:file-system/%s"
	prefixListArnPattern          = "arn:aws:ec2:%s:%s:prefix-list/%s"
	vpcEndpointArnPattern         = "arn:aws:ec2:%s:%s:vpc-endpoint/%s"
	vpcFlowLogArnPattern          = "arn:aws:ec2:%s:%s:vpc-flow-log/%s"
	natGatewayArnPattern          = "arn:aws:ec2:%s:%s:natgateway/%s"
	networkInterfaceArnPattern    = "arn:aws:ec2:%s:%s:network-interface/%s"
	dhcpOptionsArnPattern         = "arn:aws:ec2:%s:%s:dhcp-options/%s"
	tgwAttachmentArnPattern       = "arn:aws:ec2:%s:%s:transit-gateway-attachment/%s"
	tgwRouteTableArnPattern       = "arn:aws:ec2:%s:%s:transit-gateway-route-table/%s"
)

func NewSecurityGroupArn(region, accountID, sgID string) string {
	return fmt.Sprintf(securityGroupArnPattern, region, accountID, sgID)
}

// s3BucketNameFromUri extracts the bucket name from an "s3://bucket/key" URI.
// Returns "" when the value carries no s3:// scheme, so a location that is not
// an S3 URI (a file-system path, an empty string) is never mistaken for a
// bucket name.
func s3BucketNameFromUri(uri string) string {
	trimmed := strings.TrimPrefix(uri, "s3://")
	if trimmed == uri {
		return ""
	}
	return strings.SplitN(trimmed, "/", 2)[0]
}

// s3BucketRefFromUri resolves an "s3://bucket/key" URI to a typed aws.s3.bucket,
// marking the field null when the URI names no bucket.
func s3BucketRefFromUri(runtime *plugin.Runtime, uri string, field *plugin.TValue[*mqlAwsS3Bucket]) (*mqlAwsS3Bucket, error) {
	name := s3BucketNameFromUri(uri)
	if name == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.s3.bucket",
		map[string]*llx.RawData{"name": llx.StringData(name)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

// s3BucketRefFromArn resolves an S3 bucket ARN to a typed aws.s3.bucket,
// marking the field null when no ARN is set.
func s3BucketRefFromArn(runtime *plugin.Runtime, bucketArn string, field *plugin.TValue[*mqlAwsS3Bucket]) (*mqlAwsS3Bucket, error) {
	if bucketArn == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.s3.bucket",
		map[string]*llx.RawData{"arn": llx.StringData(bucketArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

// ecrRepositoryArnFromImageUri builds the repository ARN for an ECR image URI
// of the form <registryId>.dkr.ecr.<region>.amazonaws.com/<repo>[:tag][@digest].
// Returns "" when the URI does not point at an ECR repository, which is the
// case for images served from Docker Hub or another public registry.
func ecrRepositoryArnFromImageUri(image string) string {
	if !strings.Contains(image, ".dkr.ecr.") {
		return ""
	}
	host, path, ok := strings.Cut(image, "/")
	if !ok {
		return ""
	}
	hostParts := strings.Split(host, ".")
	if len(hostParts) < 4 {
		return ""
	}
	repoName := path
	if i := strings.IndexByte(repoName, '@'); i >= 0 {
		repoName = repoName[:i]
	}
	if i := strings.IndexByte(repoName, ':'); i >= 0 {
		repoName = repoName[:i]
	}
	if repoName == "" {
		return ""
	}
	return ecrRepositoryArn(false, hostParts[3], hostParts[0], repoName)
}

// awsResolveVpcFromSubnets resolves the VPC that a workload's subnets belong to
// by describing the first subnet. Marks the field null when no subnets are
// configured or the subnet no longer exists.
func awsResolveVpcFromSubnets(runtime *plugin.Runtime, region string, subnetIds []string, field *plugin.TValue[*mqlAwsVpc]) (*mqlAwsVpc, error) {
	if len(subnetIds) == 0 {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	ctx := context.Background()
	resp, err := svc.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []ec2types.Filter{{Name: aws.String("subnet-id"), Values: []string{subnetIds[0]}}},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Subnets) == 0 || resp.Subnets[0].VpcId == nil {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.vpc",
		map[string]*llx.RawData{"id": llx.StringData(*resp.Subnets[0].VpcId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

// awsSecurityGroupRefs resolves security-group IDs to typed
// aws.ec2.securitygroup resources. Returns nil when there are no IDs.
func awsSecurityGroupRefs(runtime *plugin.Runtime, region string, sgIds []string) ([]any, error) {
	if len(sgIds) == 0 {
		return nil, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	res := make([]any, 0, len(sgIds))
	for _, sgId := range sgIds {
		mqlSg, err := NewResource(runtime, "aws.ec2.securitygroup",
			map[string]*llx.RawData{"arn": llx.StringData(NewSecurityGroupArn(region, conn.AccountId(), sgId))})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSg)
	}
	return res, nil
}

func (a *mqlAws) regions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	regions, err := conn.Regions()
	for i := range regions {
		res = append(res, regions[i])
	}
	return res, err
}

func Is400AccessDeniedError(err error) bool {
	var respErr *http.ResponseError
	if errors.As(err, &respErr) {
		statusCodeMatches := respErr.HTTPStatusCode() == 400 || respErr.HTTPStatusCode() == 403
		errorMessageMatches := strings.Contains(respErr.Error(), "AccessDenied") ||
			strings.Contains(respErr.Error(), "UnauthorizedOperation") ||
			strings.Contains(respErr.Error(), "AuthorizationError")
		return statusCodeMatches && errorMessageMatches
	}
	return false
}

// isOrganizationsNotInUseError reports the answer AWS gives a standalone
// account: AWSOrganizationsNotInUseException.
//
// It is a statement about the account, not a failure to read one. Every
// Organizations call answers this way when the account belongs to no
// organization, so it is what separates "not a multi-account environment" from
// "could not find out", and the two must not look alike to a caller trying to
// scope a check.
//
// Deliberately not folded into Is400AccessDeniedError, which answers a
// different question: a denial leaves the account's membership unknown, while
// this establishes it.
func isOrganizationsNotInUseError(err error) bool {
	if err == nil {
		return false
	}
	var notInUse *orgtypes.AWSOrganizationsNotInUseException
	return errors.As(err, &notInUse)
}

// isResourceNotFoundError reports whether err is an AWS "not found" API error
// (e.g. LoadBalancerNotFound, RepositoryNotFoundException). Targeted single-
// resource init lookups use it to fall through to their list-scan fallback for
// stale ARNs instead of hard-failing the resolution.
func isResourceNotFoundError(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		code := ae.ErrorCode()
		// Most services use a "*NotFound*" code (e.g. RepositoryNotFoundException,
		// LoadBalancerNotFound, ResourceNotFoundException); a few use a "NoSuch*"
		// code instead (e.g. NoSuchEntity, NoSuchBucket).
		return strings.Contains(code, "NotFound") || strings.HasPrefix(code, "NoSuch")
	}
	return false
}

// isOperationNotSupportedError reports whether err is an AWS ValidationException
// meaning the operation is not valid for the target resource - e.g. Bedrock
// GetResourcePolicy on a system-defined inference profile returns "The requested
// operation is not recognized by the service". Such a resource has no
// resource-based policy to report, so callers degrade to an empty policy.
func isOperationNotSupportedError(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "ValidationException" &&
			strings.Contains(ae.ErrorMessage(), "not recognized by the service")
	}
	return false
}

// isBadRequestError checks if the error is a 400 Bad Request error
// This is used to handle cases where a feature is not enabled for an AWS account
func isBadRequestError(err error) bool {
	var respErr *http.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() == 400 &&
			(strings.Contains(respErr.Error(), "BadRequest") ||
				strings.Contains(respErr.Error(), "feature is not enabled"))
	}
	return false
}

// IsMacieNotEnabledError checks if the error indicates Macie is not enabled in the region.
// The macie2 API returns this in three shapes across endpoints:
//   - 401 AccessDeniedException ("Macie is not enabled") on most session and listing APIs
//   - 403 AccessDeniedException on a handful of endpoints
//   - 404 ResourceNotFoundException ("Amazon Macie isn't enabled for your account") on
//     GetClassificationExportConfiguration and a few of the discovery Get* endpoints.
func IsMacieNotEnabledError(err error) bool {
	if err == nil {
		return false
	}

	var respErr *http.ResponseError
	if errors.As(err, &respErr) {
		msg := awsNormalizeApostrophes(respErr.Error())
		// Macie returns 401 status code with AccessDeniedException when not enabled
		if respErr.HTTPStatusCode() == 401 && strings.Contains(msg, "AccessDeniedException: Macie is not enabled") {
			return true
		}
		// Also catch general access denied cases for Macie, but only when the
		// message actually names Macie. Matching a bare AccessDenied swallowed
		// genuine macie2:* permission gaps and reported them as "Macie is not
		// enabled", so every Macie resource degraded to empty and any
		// data-classification policy passed vacuously.
		if (respErr.HTTPStatusCode() == 400 || respErr.HTTPStatusCode() == 401 || respErr.HTTPStatusCode() == 403) &&
			(strings.Contains(msg, "AccessDeniedException") || strings.Contains(msg, "AccessDenied")) &&
			(strings.Contains(msg, "Macie is not enabled") ||
				strings.Contains(msg, "Macie isn't enabled") ||
				strings.Contains(msg, "not enabled for your account")) {
			return true
		}
		// GetClassificationExportConfiguration / GetAutomatedDiscoveryConfiguration
		// return 404 ResourceNotFoundException when Macie isn't enabled in the region.
		if respErr.HTTPStatusCode() == 404 &&
			(strings.Contains(msg, "Macie isn't enabled") || strings.Contains(msg, "Macie is not enabled")) {
			return true
		}
		// The automated-discovery endpoints have a shape of their own that never
		// names Macie: 403 AccessDeniedException "Account Id: [...] has not been
		// onboarded". Onboarding state is not a permission gap, so matching it
		// does not reintroduce the swallowing problem the Macie-named condition
		// above exists to prevent - no IAM denial is phrased this way.
		if respErr.HTTPStatusCode() == 403 &&
			strings.Contains(msg, "AccessDeniedException") &&
			strings.Contains(msg, "has not been onboarded") {
			return true
		}
	}
	return false
}

// awsNormalizeApostrophes rewrites the typographic apostrophe to the ASCII one.
//
// Several services write prose error messages with U+2019 RIGHT SINGLE
// QUOTATION MARK rather than U+0027: Macie answers a region where it is not
// enabled with "Macie isn't enabled in the specified AWS Region", spelled with
// the curly one. A guard written with a plain apostrophe - which is what
// anyone typing the message back out produces - never matches it, and the
// service-not-enabled case it exists to absorb is reported as a failure
// instead. Normalising once is cheaper than getting the byte right at every
// call site, and survives AWS changing its mind about quote style.
func awsNormalizeApostrophes(s string) string {
	return strings.ReplaceAll(s, "’", "'")
}

// IsSecurityLakeNotEnabledError reports whether the error means Security Lake
// has not been enabled for the account.
//
// Security Lake answers a listing with 404 ResourceNotFoundException and "isn't
// enabled for your account in any Regions" until someone turns it on, which
// neither the access-denied nor the not-available-in-region guard covers. An
// account that has not adopted the service has no subscribers, which is the
// answer to report - not a failed query.
func IsSecurityLakeNotEnabledError(err error) bool {
	if err == nil {
		return false
	}
	var respErr *http.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	msg := awsNormalizeApostrophes(respErr.Error())
	return respErr.HTTPStatusCode() == 404 &&
		strings.Contains(msg, "ResourceNotFoundException") &&
		(strings.Contains(msg, "Security Lake isn't enabled") ||
			strings.Contains(msg, "Security Lake is not enabled"))
}

func Is400InstanceNotFoundError(err error) bool {
	var respErr *http.ResponseError
	if errors.As(err, &respErr) {
		if respErr.HTTPStatusCode() == 400 && (strings.Contains(respErr.Error(), "InvalidInstanceID.NotFound") || strings.Contains(respErr.Error(), "InvalidInstanceID.Malformed")) {
			return true
		}
	}
	return false
}

// IsServiceNotAvailableInRegionError checks if the error indicates the service or API action
// is not available in the region. This includes DNS lookup failures for regional services,
// InvalidAction errors for EC2 actions not yet deployed to a region (e.g., Verified Access),
// UnknownOperationException for services like Bedrock in unsupported regions, and the
// "request send failed" + retry-exhaustion combination produced when an endpoint resolves
// in DNS but every call fails to complete (e.g., bedrock-agent.us-west-1 returning HTTP 500
// on every retry because the service is not actually deployed there).
//
// Note on the retry-exhaustion match: the predicate requires BOTH "exceeded maximum number
// of attempts" AND "request send failed" so throttling/5xx responses that genuinely went
// over the wire — which the caller should see — are not silently swallowed.
func IsServiceNotAvailableInRegionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "UnknownEndpoint") ||
		strings.Contains(errStr, "could not resolve endpoint") ||
		strings.Contains(errStr, "InvalidAction") ||
		strings.Contains(errStr, "UnknownOperationException") ||
		strings.Contains(errStr, "Unknown operation") ||
		strings.Contains(errStr, "Unknown Operation") ||
		(strings.Contains(errStr, "exceeded maximum number of attempts") &&
			strings.Contains(errStr, "request send failed"))
}

func toInterfaceMap(m map[string]string) map[string]any {
	res := make(map[string]any)
	for k, v := range m {
		res[k] = v
	}
	return res
}

func toInterfaceArr(a []string) []any {
	res := []any{}
	for _, v := range a {
		res = append(res, v)
	}
	return res
}

func GetRegionFromArn(arnVal string) (string, error) {
	parsedArn, err := arn.Parse(arnVal)
	if err != nil {
		return "", err
	}
	return parsedArn.Region, nil
}

func CertificatesToMqlCertificates(runtime *plugin.Runtime, certs []*x509.Certificate) ([]any, error) {
	res := []any{}
	// to create certificate resources
	for i := range certs {
		cert := certs[i]

		if cert == nil {
			continue
		}

		certdata, err := certificates.EncodeCertAsPEM(cert)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(runtime, "certificate", map[string]*llx.RawData{
			"pem": llx.StringData(string(certdata)),
			// NOTE: if we do not set the hash here, it will generate the cache content before we can store it
			// we are using the hashes for the id, therefore it is required during creation
			"fingerprints": llx.MapData(certificates.Fingerprints(cert), types.String),
		})
		if err != nil {
			return nil, err
		}

		c := r.(*mqlAwsAcmCertificate)
		// c.Certificate = plugin.TValue[*x509.Certificate]{
		// 	Pem:   llx.StringData(cert.Pem),
		// 	Data:  cert,
		// 	State: plugin.StateIsSet,
		// } // TODO: revisit all this cert stuff. can we share resources across providers??

		res = append(res, c)
	}
	return res, nil
}

func ParseCertsFromPEM(r io.Reader) ([]*x509.Certificate, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	certs, err := cert.ParseCertsPEM(data)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func EncodeCertAsPEM(cert *x509.Certificate) ([]byte, error) {
	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: CertificateBlockType, Bytes: cert.Raw}); err != nil {
		return nil, err
	}
	return certBuffer.Bytes(), nil
}

const (
	// CertificateBlockType is a possible value for pem.Block.Type.
	CertificateBlockType = "CERTIFICATE"
)

// getAssetIdentifier returns the asset's validated resource ARN from its
// platform IDs, or "" when the asset carries no parseable arn:aws: ID (e.g.
// an account asset). Discovered resource assets always store their own ARN in
// PlatformIds, so ARN matching is sufficient for init lookups; the asset name
// is a display name (possibly a Name tag), never a resource key, and must not
// be used for resolution. Callers must only inject a non-empty result into
// init args — an empty args["arn"] defeats `args["arn"] == nil` guards.
// The platform argument is the platform of the resource asking. The scanned
// asset's platform is the exact discriminator for what kind of thing it is
// (connection.Platforms holds one entry per discoverable object type), so
// requiring it here stops an init from adopting the ARN of an unrelated asset.
// Without that check a bare query -- e.g. the policy filter
// `aws.secretsmanager.secret.lastChangedDate != null`, which cnspec evaluates
// against every asset -- made each init fetch the scanned asset's own ARN and
// call its own API with it. That cost 1,494 DescribeSecret and 504
// DescribeClusterV2 calls per scan on ARNs that could never resolve.
func getAssetIdentifier(runtime *plugin.Runtime, platform string) string {
	var a *inventory.Asset
	if conn, ok := runtime.Connection.(*connection.AwsConnection); ok {
		a = conn.Asset()
	}
	if a == nil {
		return ""
	}
	if a.Platform == nil || a.Platform.Name != platform {
		// the scanned asset is not this kind of resource, so its ARN is not ours
		return ""
	}

	arnStr := ""
	for _, id := range a.PlatformIds {
		if strings.HasPrefix(id, "arn:aws:") {
			if _, err := arn.Parse(id); err == nil {
				arnStr = id
			} else {
				log.Debug().Str("invalid_arn", id).Err(err).Msg("skipping invalid ARN in asset PlatformIds")
			}
		}
	}

	return arnStr
}

// getAssetName returns the discovered asset's name, or "" when the connection
// has no asset. Use it only for resources whose lookup API is name-driven
// (e.g. IAM GetUser/GetGroup) and whose discovery sets the asset name to the
// resource's own name; for everything else resolve by ARN via
// getAssetIdentifier — the asset name is a display name, not a resource key.
// The platform argument gates the name the same way getAssetIdentifier gates
// the ARN, and for the same reason: without it a bare aws.iam.user query on an
// EBS volume asset called GetUser with the volume id as the user name. Of 169
// distinct names one scan passed to GetUser, 4 were IAM users; the rest were
// log groups, volume ids and UUIDs belonging to whatever else was scanned.
func getAssetName(runtime *plugin.Runtime, platform string) string {
	var a *inventory.Asset
	if conn, ok := runtime.Connection.(*connection.AwsConnection); ok {
		a = conn.Asset()
	}
	if a == nil {
		return ""
	}
	if a.Platform == nil || a.Platform.Name != platform {
		// the scanned asset is not this kind of resource, so its name is not ours
		return ""
	}
	return a.Name
}

func mapStringInterfaceToStringString(m map[string]any) map[string]string {
	newM := make(map[string]string)
	for k, v := range m {
		newM[k] = v.(string)
	}
	return newM
}

// fetchTagsConcurrency bounds the in-flight per-item tag calls made by
// fetchTagsConcurrently. It is deliberately small: tag lookups are a means to
// evaluate discovery filters, not the workload, and every provider job already
// runs inside a region-level worker pool.
const fetchTagsConcurrency = 10

// fetchTagsConcurrently resolves tags for a set of keys and returns them keyed by
// the same value. It exists for services whose tags can only be read one resource
// at a time (SQS, SNS, and Lambda have no batch tags endpoint), where evaluating
// a tag filter would otherwise serialize one round trip per resource. Services
// that do offer a plural tags endpoint should call that instead; see
// batchFetchTags in aws_route53.go.
//
// Per-item failures are tolerated rather than fatal, and presence in the result
// map is what distinguishes them from a resource that simply has no tags:
//
//   - key present, map non-nil (possibly empty) - tags were read successfully
//   - key absent - the fetch failed for that resource
//
// Callers must use the comma-ok form to tell those apart. A resource whose tags
// could not be read yields a nil map, which
// GeneralDiscoveryFilters.IsFilteredOutByTags treats the same as an empty tag
// set: it is dropped when an include filter is set and kept when only exclude
// filters are set. That is the established behavior across the provider - an
// unreadable tag set cannot prove a match, so we do not claim one. Callers that
// seed the fetched tags onto a resource must only do so for keys that are
// present, or an unreadable tag set gets published as an authoritative empty one.
func fetchTagsConcurrently[K comparable](ctx context.Context, keys []K, fetch func(context.Context, K) (map[string]string, error)) map[K]map[string]string {
	result := make(map[K]map[string]string, len(keys))
	if len(keys) == 0 {
		return result
	}

	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(fetchTagsConcurrency)
	for _, key := range keys {
		g.Go(func() error {
			tags, err := fetch(gctx, key)
			if err != nil {
				log.Debug().Err(err).Interface("key", key).Msg("could not fetch tags for filter evaluation")
				return nil
			}
			if tags == nil {
				// Normalize so a successful fetch is always a non-nil map and
				// absence unambiguously means failure.
				tags = map[string]string{}
			}
			mu.Lock()
			defer mu.Unlock()
			result[key] = tags
			return nil
		})
	}
	// The worker func never returns an error, so Wait only drains the pool.
	_ = g.Wait()
	return result
}

// securityGroupIdHandler is a helper struct to handle security group ids and convert them to resources
// This makes it easy to extend the internal representation of a resource and fetch security groups asynchronous
type securityGroupIdHandler struct {
	securityGroupArns []string
}

// setSecurityGroupArns sets the security group arns
func (sgh *securityGroupIdHandler) setSecurityGroupArns(ids []string) {
	sgh.securityGroupArns = ids
}

// newSecurityGroupResources creates new security group resources based on the security group arns
func (sgh *securityGroupIdHandler) newSecurityGroupResources(runtime *plugin.Runtime) ([]any, error) {
	sgs := []any{}
	for i := range sgh.securityGroupArns {
		sgArn := sgh.securityGroupArns[i]
		mqlSg, err := NewResource(runtime, "aws.ec2.securitygroup",
			map[string]*llx.RawData{
				"arn": llx.StringData(sgArn),
			})
		if err != nil {
			return nil, err
		}
		sgs = append(sgs, mqlSg)
	}
	return sgs, nil
}
