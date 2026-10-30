// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/logger/zerologadapter"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/iox"
)

type AwsConnection struct {
	plugin.Connection
	Conf             *inventory.Config
	asset            *inventory.Asset
	cfg              aws.Config
	accountId        string
	clientcache      ClientsCache
	awsConfigOptions []func(*config.LoadOptions) error
	PlatformOverride string
	Filters          DiscoveryFilters
	// gaps records service/region pairs this scan could not read. See
	// coverage.go for why an unreadable region must not look like an empty one.
	gaps coverageGaps

	opts awsConnectionOptions
}

// awsConnectionOptions carries everything that distinguishes one AWS
// connection from another. Every field must be exported: hashstructure skips
// unexported fields, so an unexported field contributes nothing to Hash() and
// two connections for different accounts would collide.
type awsConnectionOptions struct {
	Scope   string
	Profile string
	Options map[string]string
	// CredentialFingerprint distinguishes connections whose options are
	// identical but whose credentials resolve to different accounts.
	CredentialFingerprint string
}

// credentialFingerprint derives a stable, non-reversible identifier for a set
// of credentials so that two connections using different credentials hash
// differently. The secret is hashed, never retained.
func credentialFingerprint(creds []*vault.Credential) string {
	if len(creds) == 0 {
		return ""
	}
	h := sha256.New()
	for _, cred := range creds {
		if cred == nil {
			continue
		}
		fmt.Fprintf(h, "%s\x00%d\x00%s\x00", cred.SecretId, cred.Type, cred.User)
		h.Write(cred.Secret)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func NewMockConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) *AwsConnection {
	return &AwsConnection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
	}
}

// NewTestConnection builds a connection around a caller-supplied aws.Config.
// It exists so that tests can hand the SDK clients a config carrying
// APIOptions middleware and exercise a lister end to end without network or
// credentials; cfg is unexported, so there is no other way to reach it from
// outside this package.
func NewTestConnection(cfg aws.Config) *AwsConnection {
	return &AwsConnection{cfg: cfg}
}

func NewAwsConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*AwsConnection, error) {
	log.Debug().Msg("new aws connection")
	// check flags for connection options
	c := &AwsConnection{
		awsConfigOptions: []func(*config.LoadOptions) error{},
	}

	// merge the options to make sure we don't miss anything
	if asset.Options == nil {
		asset.Options = map[string]string{}
	}
	maps.Copy(asset.Options, conf.Options)

	opts := parseFlagsForConnectionOptions(asset.Options, conf.GetCredentials())
	for _, opt := range opts {
		opt(c)
	}
	// custom retry client with reduced retries and shorter backoff
	// to avoid excessive delays when regions are unreachable
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 2                    // reduced from 5 to avoid long delays on unreachable regions
	retryClient.RetryWaitMax = 10 * time.Second // cap at 10s instead of 30s
	retryClient.Logger = zerologadapter.New(log.Logger)
	c.awsConfigOptions = append(c.awsConfigOptions, config.WithHTTPClient(retryClient.StandardClient()))

	cfg, err := config.LoadDefaultConfig(context.Background(), c.awsConfigOptions...)
	if err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		log.Info().Msg("no AWS region found, using us-east-1")
		cfg.Region = "us-east-1" // in case the user has no region set, default to us-east-1
	}

	c.Connection = plugin.NewConnection(id, asset)
	c.Conf = conf
	c.asset = asset
	c.cfg = cfg
	c.opts.Profile = asset.Options["profile"]
	c.opts.Scope = asset.Options["scope"]
	c.opts.Options = asset.Options
	c.opts.CredentialFingerprint = credentialFingerprint(conf.GetCredentials())
	c.Filters = DiscoveryFiltersFromOpts(conf.Discover.GetFilter())
	return c, nil
}

func (c *AwsConnection) Hash() uint64 {
	// generate hash of the config options used to to initialize this connection,
	// we use this to avoid verifying a client with the same options more than once
	hash, err := hashstructure.Hash(c.opts, hashstructure.FormatV2, nil)
	if err != nil {
		log.Error().Err(err).Msg("unable to hash connection")
	}
	return hash
}

func (c *AwsConnection) Verify() (string, error) {
	identity, err := CheckIam(c.cfg.Copy())
	if err != nil {
		log.Debug().Err(err).Msg("could not gather details of AWS account")
		// try with govcloud region, store error to return it if this last option does not work
		err1 := err
		cfgCopy := c.cfg.Copy()
		cfgCopy.Region = "us-gov-west-1"
		identity, err = CheckIam(cfgCopy)
		if err != nil {
			return "", err1
		}
	}
	account := ""
	if identity.Account != nil {
		account = *identity.Account
	}

	return account, nil
}

func (c *AwsConnection) SetAccountId(id string) {
	if id != "" {
		c.accountId = id
	}
}

// GetCachedValue returns a previously cached value for the given key. It is
// connection-scoped and safe for concurrent use, intended for account- or
// region-level data that multiple resources would otherwise re-fetch.
func (c *AwsConnection) GetCachedValue(key string) (any, bool) {
	entry, ok := c.clientcache.Load(key)
	if !ok {
		return nil, false
	}
	return entry.Data, true
}

// SetCachedValue stores a value under the given key for the lifetime of the
// connection. See GetCachedValue.
func (c *AwsConnection) SetCachedValue(key string, val any) {
	c.clientcache.Store(key, &CacheEntry{Data: val})
}

func (p *AwsConnection) AccountId() string {
	return p.accountId
}

func (p *AwsConnection) Region() string {
	return p.cfg.Region
}

func parseFlagsForConnectionOptions(m map[string]string, creds []*vault.Credential) []ConnectionOption {
	o := make([]ConnectionOption, 0)
	if apiEndpoint, ok := m["endpoint-url"]; ok {
		o = append(o, WithEndpoint(apiEndpoint))
	}

	if awsRegion, ok := m["region"]; ok {
		log.Debug().Str("region", awsRegion).Msg("using region")
		o = append(o, WithRegion(awsRegion))
	}

	if awsProfile, ok := m["profile"]; ok {
		log.Debug().Str("profile", awsProfile).Msg("using aws profile")
		o = append(o, WithProfile(awsProfile))
	}

	if role, ok := m["role"]; ok {
		log.Debug().Str("role", role).Msg("using aws sts assume role")
		cfg, _ := config.LoadDefaultConfig(context.Background())
		externalId := m["external-id"]
		o = append(o, WithAssumeRole(cfg, role, externalId))
	}

	if len(creds) > 0 {
		cred := creds[0]
		o = append(o, WithStaticCredentials(m["access-key-id"], string(cred.Secret), m["session-token"]))
	}
	return o
}

type ConnectionOption func(charp *AwsConnection)

// // delegate back to the default v2 resolver otherwise
// return s3.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, params)
func WithEndpoint(apiEndpoint string) ConnectionOption {
	return func(a *AwsConnection) {
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...any) (aws.Endpoint, error) {
			if apiEndpoint != "" {
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           apiEndpoint,
					SigningRegion: region,
				}, nil
			}

			// returning EndpointNotFoundError will allow the service to fallback to its default resolution
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})
		a.awsConfigOptions = append(a.awsConfigOptions, config.WithEndpointResolverWithOptions(customResolver))
	}
}

func WithRegion(region string) ConnectionOption {
	return func(a *AwsConnection) {
		a.awsConfigOptions = append(a.awsConfigOptions, config.WithRegion(region))
	}
}

func WithProfile(profile string) ConnectionOption {
	return func(a *AwsConnection) {
		a.awsConfigOptions = append(a.awsConfigOptions, config.WithSharedConfigProfile(profile))
	}
}

func WithStaticCredentials(key string, secret string, token string) ConnectionOption {
	return func(a *AwsConnection) {
		a.awsConfigOptions = append(a.awsConfigOptions, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(key, secret, token)))
	}
}

func WithExternalId(id string) func(o *stscreds.AssumeRoleOptions) {
	if id != "" {
		return func(o *stscreds.AssumeRoleOptions) {
			o.ExternalID = &id
		}
	}
	return func(o *stscreds.AssumeRoleOptions) {}
}

func WithAssumeRole(defaultCfg aws.Config, roleArn string, externalId string) ConnectionOption {
	opts := WithExternalId(externalId)
	return func(a *AwsConnection) {
		stsClient := sts.NewFromConfig(defaultCfg)
		a.awsConfigOptions = append(a.awsConfigOptions, config.WithCredentialsProvider(
			aws.NewCredentialsCache(
				stscreds.NewAssumeRoleProvider(
					stsClient,
					roleArn,
					opts,
				)),
		))
	}
}

func (h *AwsConnection) Name() string {
	return "aws"
}

func (p *AwsConnection) Asset() *inventory.Asset {
	return p.asset
}

func (p *AwsConnection) UpdateAsset(asset *inventory.Asset) {
	p.asset = asset
}

func (p *AwsConnection) Profile() string {
	return p.opts.Profile
}

func (p *AwsConnection) Scope() string {
	return p.opts.Scope
}

func (p *AwsConnection) ConnectionOptions() map[string]string {
	return p.opts.Options
}

func (p *AwsConnection) RunCommand(command string) (*shared.Command, error) {
	return nil, errors.New("unimplemented")
}

func (p *AwsConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, errors.New("unimplemented")
}

func (p *AwsConnection) FileSystem() afero.Fs {
	return nil
}

func (p *AwsConnection) Capabilities() shared.Capabilities {
	return shared.Capability_RunCommand // not true, update to nothing
}

func (p *AwsConnection) Type() shared.ConnectionType {
	return "aws"
}

const MISSING_REGION_MSG = `The AWS region must be set for the deployment. Please use environment variables
or AWS profiles. Further details are available at:
- https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
- https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html`

// CheckRegion verifies that the config includes a region
func CheckRegion(cfg aws.Config) error {
	if len(cfg.Region) == 0 {
		return errors.New(MISSING_REGION_MSG)
	}
	return nil
}

func CheckIam(cfg aws.Config) (*sts.GetCallerIdentityOutput, error) {
	ctx := context.Background()
	svc := sts.NewFromConfig(cfg)
	resp, err := svc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	} else if resp.Account == nil || resp.UserId == nil {
		return nil, errors.New("could not read iam user")
	} else {
		return resp, nil
	}
}

// normalizeRegionFilter trims and de-duplicates the regions filter.
//
// The filter is split on commas without trimming, so `regions=us-east-1, us-west-2`
// yields " us-west-2" with a leading space, and a trailing comma yields "". An
// empty entry is worse than useless: the client treats an empty region as "use
// the configured one", so it silently scans the default region a second time.
func normalizeRegionFilter(regions []string) []string {
	out := make([]string, 0, len(regions))
	seen := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		region = strings.TrimSpace(region)
		if region == "" {
			continue
		}
		if _, dup := seen[region]; dup {
			continue
		}
		seen[region] = struct{}{}
		out = append(out, region)
	}
	return out
}

// unknownRegions reports which requested regions the account does not have
// enabled, preserving the order they were given in.
func unknownRegions(requested, enabled []string) []string {
	have := make(map[string]struct{}, len(enabled))
	for _, region := range enabled {
		have[region] = struct{}{}
	}
	unknown := []string{}
	for _, region := range requested {
		if _, ok := have[region]; !ok {
			unknown = append(unknown, region)
		}
	}
	return unknown
}

// discoverEnabledRegions lists the regions this account has enabled.
//
// allowFallback controls whether a failed DescribeRegions escalates to the
// slower routes (Account list-regions, then the public regional table plus a
// per-region access probe). They are worth it when the answer decides the whole
// scan's scope, and not worth it when the caller has already named its regions.
func (h *AwsConnection) discoverEnabledRegions(ctx context.Context, allowFallback bool) ([]string, error) {
	svc := h.Ec2(h.cfg.Region)

	// DescribeRegions works to get the list of enabled regions for the account ( each account of organization)
	// but this does not mean the respective service endpoint is available in that region. They will timeout instead of failing fast
	// (e.g. EKS,KMS,Sagemaker is for example not available in ap-southeast-1 etc)
	// This also does not cover SCPs that might block access to certain regions.
	res, err := svc.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		log.Warn().Err(err).Msg("unable to describe regions")
		if !allowFallback {
			return nil, err
		}
		// when we can't use `DescribeRegions` we will fallback to:
		// 1. Account list-regions
		// 2. Public regional table + region access verification
		enabledRegions, fallbackErr := h.fallbackGetEnabledRegions(ctx)
		if fallbackErr != nil {
			log.Warn().Err(fallbackErr).Msg("unable to list regions from fallback options")
			return nil, err
		}
		return enabledRegions, nil
	}

	regions := []string{}
	for _, region := range res.Regions {
		if region.RegionName == nil {
			continue
		}
		regions = append(regions, *region.RegionName)
	}
	return regions, nil
}

func (h *AwsConnection) Regions() ([]string, error) {
	// check cache for regions list, return if exists
	c, ok := h.clientcache.Load("_regions")
	if ok {
		log.Debug().Msg("use regions from cache")
		return c.Data.([]string), nil
	}

	ctx := context.Background()

	// include filters have precedence over exclude filters. in any normal situation they should be mutually exclusive.
	if regionLimits := normalizeRegionFilter(h.Filters.General.Regions); len(regionLimits) > 0 {
		// A region name that the account does not have enabled resolves to no
		// endpoint at all, and every lister then classifies the resulting DNS
		// miss as "this service is absent here". Left unchecked, a typo makes the
		// whole scan report zero resources and exit successfully. Skip the
		// expensive fallback here: it costs a probe per region, and the caller
		// has already told us which regions it wants.
		enabled, err := h.discoverEnabledRegions(ctx, false)
		if err != nil {
			// Degrading to a no-op is the safe direction - refusing to scan
			// because we could not read the region list would be worse. Say
			// plainly that the filter was taken as given, so this is not mistaken
			// for a filter that passed the check.
			log.Warn().Err(err).Strs("regions", regionLimits).
				Msg("could not list the account's enabled regions, accepting the regions filter unchecked; a misspelled region will report no resources")
		} else if unknown := unknownRegions(regionLimits, enabled); len(unknown) > 0 {
			return nil, fmt.Errorf("regions filter names %d region(s) this account does not have enabled: %s",
				len(unknown), strings.Join(unknown, ", "))
		}
		log.Debug().Strs("regions", regionLimits).Msg("using region limits")
		// cache the regions as part of the provider instance
		h.clientcache.Store("_regions", &CacheEntry{Data: regionLimits})
		return regionLimits, nil
	}
	// if no cache, get regions using ec2 client (using the ssm list global regions does not give the same list)
	log.Debug().Msg("no region cache or region limits found. fetching regions")
	regions, err := h.discoverEnabledRegions(ctx, true)
	if err != nil {
		return []string{}, err
	}

	// ensure excluded regions are discarded
	filteredRegions := []string{}
	for _, region := range regions {
		if !slices.Contains(h.Filters.General.ExcludeRegions, region) {
			filteredRegions = append(filteredRegions, region)
		}
	}

	if len(filteredRegions) != len(regions) {
		log.Debug().
			Strs("filtered_regions", filteredRegions).
			Msg("list of regions changed based of applied filters")
	}

	// cache the regions as part of the provider instance
	h.clientcache.Store("_regions", &CacheEntry{Data: filteredRegions})
	return filteredRegions, nil
}

// fallbackGetEnabledRegions tries multiple ways to return the list of enabled regions.
//
// NOTE use this only if `DescribeRegions` doesn't work
func (h *AwsConnection) fallbackGetEnabledRegions(ctx context.Context) (regions []string, err error) {
	// 1. Account list-regions
	response, err := h.Account("").ListRegions(ctx, &account.ListRegionsInput{
		RegionOptStatusContains: []types.RegionOptStatus{
			types.RegionOptStatusEnabled,
			types.RegionOptStatusEnabling,
			types.RegionOptStatusEnabledByDefault,
		},
	})
	if err == nil {
		for _, region := range response.Regions {
			regions = append(regions, *region.RegionName)
		}
		log.Debug().Strs("regions", regions).Msg("regions>fallback> using account list-regions")
		return
	}

	log.Warn().Err(err).Msg("unable to list account regions")

	// 2. Public regional table + region access verification
	regionsFromTable, err := fetchRegionsFromRegionalTable(ctx, regionalTableHTTPClient, "https://api.regional-table.region-services.aws.a2z.com/index.json")
	if err != nil {
		return
	}

	// verify which regions are enabled
	for _, region := range regionsFromTable {
		if h.isRegionEnabled(ctx, region) {
			regions = append(regions, region)
		}
	}

	log.Debug().Strs("regions", regions).Msg("using public regional table")
	return
}

// isRegionEnabled returns true if the provided region is enabled. We verify if a region is
// enabled by doing a simple request to that region.
func (h *AwsConnection) isRegionEnabled(ctx context.Context, region string) bool {
	_, err := h.STS(region).GetCallerIdentity(ctx, nil)
	return err == nil
}

type regionalTable struct {
	Metadata struct {
		Copyright     string `json:"copyright"`
		Disclaimer    string `json:"disclaimer"`
		FormatVersion string `json:"format:version"`
		SourceVersion string `json:"source:version"`
	} `json:"metadata"`
	Prices []struct {
		Attributes struct {
			AwsRegion      string `json:"aws:region"`
			AwsServiceName string `json:"aws:serviceName"`
			AwsServiceURL  string `json:"aws:serviceUrl"`
		} `json:"attributes"`
		ID string `json:"id"`
	} `json:"prices"`
}

// getRegionsFromRegionalTable is a workaround for cases where the DescribeRegions API
// is blocked. This function returns all possible AWS regions using a well known regional
// table provided by AWS.
//
// https://api.regional-table.region-services.aws.a2z.com/index.json
//
// NOTE: if we need to validate that we have access to that region or, that the region is
// enabled, we can improve this function to do STS identity calls for all regions.
var regionalTableHTTPClient = &http.Client{Timeout: 30 * time.Second}

func getRegionsFromRegionalTable() ([]string, error) {
	return fetchRegionsFromRegionalTable(context.Background(), regionalTableHTTPClient, "https://api.regional-table.region-services.aws.a2z.com/index.json")
}

func fetchRegionsFromRegionalTable(ctx context.Context, client *http.Client, endpoint string) (regions []string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("regional table returned HTTP %d", resp.StatusCode)
	}
	body, err := iox.ReadAllLimit(resp.Body, 16<<20)
	if err != nil {
		return
	}
	var regionalTableJSON regionalTable
	err = json.Unmarshal(body, &regionalTableJSON)
	if err != nil {
		return
	}

	for _, p := range regionalTableJSON.Prices {
		if p.Attributes.AwsRegion != "" {
			regions = append(regions, p.Attributes.AwsRegion)
		}
	}
	slices.Sort(regions)
	regions = slices.Compact(regions)
	return
}
