// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoidentityprovidertypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsCognito) id() (string, error) {
	return "aws.cognito", nil
}

func (a *mqlAwsCognito) userPools() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getUserPools(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}

	return res, nil
}

func (a *mqlAwsCognito) getUserPools(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("cognito>getUserPools>calling aws with region %s", region)

			svc := conn.CognitoIdentityProvider(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{
					MaxResults: aws.Int32(60),
					NextToken:  nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("cognito idp service not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, pool := range resp.UserPools {
					poolArn := cognitoUserPoolArn(region, conn.AccountId(), convert.ToValue(pool.Id))

					mqlPool, err := CreateResource(a.MqlRuntime, "aws.cognito.userPool",
						map[string]*llx.RawData{
							"__id":      llx.StringData(poolArn),
							"arn":       llx.StringData(poolArn),
							"id":        llx.StringDataPtr(pool.Id),
							"name":      llx.StringDataPtr(pool.Name),
							"region":    llx.StringData(region),
							"status":    llx.StringData(string(pool.Status)),
							"createdAt": llx.TimeDataPtr(pool.CreationDate),
							"updatedAt": llx.TimeDataPtr(pool.LastModifiedDate),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPool)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// cognitoUserPoolArn builds a user pool's ARN, which is also its __id. The
// listing path and the reference resolver share it so both agree on the cache
// key.
func cognitoUserPoolArn(region, accountID, userPoolId string) string {
	return "arn:aws:cognito-idp:" + region + ":" + accountID + ":userpool/" + userPoolId
}

func initAwsCognitoUserPool(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// During a discovered-asset scan the resource is queried with no args; recover
	// the pool's region and id from the ARN carried on the asset.
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformCognitoUserpool); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch cognito user pool")
	}

	arnVal := args["arn"].Value.(string)

	// The already-built pool carries the same fields this init would set; the
	// DescribeUserPool the init primes below is then paid once, by whichever
	// computed field asks for it, instead of once per query.
	if cached := cachedByArn(runtime, ResourceAwsCognitoUserPool, arnVal); cached != nil {
		return args, cached, nil
	}

	parsed, err := arn.Parse(arnVal)
	if err != nil {
		return nil, nil, err
	}
	region := parsed.Region
	poolId := strings.TrimPrefix(parsed.Resource, "userpool/")

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.CognitoIdentityProvider(region)
	ctx := context.Background()
	resp, err := svc.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: &poolId,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.UserPool == nil {
		return nil, nil, errors.New("aws cognito user pool not found: " + poolId)
	}

	up := resp.UserPool
	mqlPool, err := CreateResource(runtime, "aws.cognito.userPool",
		map[string]*llx.RawData{
			"__id":      llx.StringData(arnVal),
			"arn":       llx.StringData(arnVal),
			"id":        llx.StringData(poolId),
			"name":      llx.StringDataPtr(up.Name),
			"region":    llx.StringData(region),
			"status":    llx.StringData(string(up.Status)),
			"createdAt": llx.TimeDataPtr(up.CreationDate),
			"updatedAt": llx.TimeDataPtr(up.LastModifiedDate),
		})
	if err != nil {
		return nil, nil, err
	}

	// Pre-populate the DescribeUserPool cache so the computed fields (policies,
	// MFA config, schema, etc.) don't trigger a second API call.
	pool := mqlPool.(*mqlAwsCognitoUserPool)
	pool.descFetched = true
	pool.descData = resp
	return nil, pool, nil
}

// Internal caching for DescribeUserPool results
type mqlAwsCognitoUserPoolInternal struct {
	descFetched bool
	descData    *cognitoidentityprovider.DescribeUserPoolOutput
	descLock    sync.Mutex
}

func (a *mqlAwsCognitoUserPool) fetchDescribeUserPool() (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	if a.descFetched {
		return a.descData, nil
	}
	a.descLock.Lock()
	defer a.descLock.Unlock()

	if a.descFetched {
		return a.descData, nil
	}

	poolId := a.Id.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CognitoIdentityProvider(region)
	ctx := context.Background()

	resp, err := svc.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: &poolId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Str("userPoolId", poolId).Err(err).Msg("access denied describing Cognito user pool")
			a.descFetched = true
			a.descData = nil
			return nil, nil
		}
		return nil, err
	}

	a.descFetched = true
	a.descData = resp
	return resp, nil
}

func (a *mqlAwsCognitoUserPool) deletionProtection() (bool, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return false, err
	}
	return resp.UserPool.DeletionProtection == cognitoidentityprovidertypes.DeletionProtectionTypeActive, nil
}

func (a *mqlAwsCognitoUserPool) mfaConfiguration() (string, error) {
	poolId := a.Id.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CognitoIdentityProvider(region)
	ctx := context.Background()

	resp, err := svc.GetUserPoolMfaConfig(ctx, &cognitoidentityprovider.GetUserPoolMfaConfigInput{
		UserPoolId: &poolId,
	})
	if err != nil {
		return "", err
	}
	return string(resp.MfaConfiguration), nil
}

func (a *mqlAwsCognitoUserPool) passwordPolicy() (any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil || resp.UserPool.Policies == nil {
		return nil, err
	}
	return convert.JsonToDict(resp.UserPool.Policies.PasswordPolicy)
}

func (a *mqlAwsCognitoUserPool) passwordRequirements() (*mqlAwsCognitoUserPoolPasswordPolicy, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.UserPool == nil || resp.UserPool.Policies == nil || resp.UserPool.Policies.PasswordPolicy == nil {
		a.PasswordRequirements.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pp := resp.UserPool.Policies.PasswordPolicy
	res, err := CreateResource(a.MqlRuntime, "aws.cognito.userPool.passwordPolicy", map[string]*llx.RawData{
		"__id":                          llx.StringData(a.Arn.Data + "/passwordPolicy"),
		"minimumLength":                 llx.IntDataDefault(pp.MinimumLength, 0),
		"passwordHistorySize":           llx.IntDataDefault(pp.PasswordHistorySize, 0),
		"requireLowercase":              llx.BoolData(pp.RequireLowercase),
		"requireNumbers":                llx.BoolData(pp.RequireNumbers),
		"requireSymbols":                llx.BoolData(pp.RequireSymbols),
		"requireUppercase":              llx.BoolData(pp.RequireUppercase),
		"temporaryPasswordValidityDays": llx.IntData(int64(pp.TemporaryPasswordValidityDays)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCognitoUserPoolPasswordPolicy), nil
}

func (a *mqlAwsCognitoUserPool) advancedSecurityMode() (string, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil || resp.UserPool.UserPoolAddOns == nil {
		return "", err
	}
	return string(resp.UserPool.UserPoolAddOns.AdvancedSecurityMode), nil
}

func (a *mqlAwsCognitoUserPool) tags() (map[string]any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(resp.UserPool.UserPoolTags), nil
}

func (a *mqlAwsCognitoUserPool) userPoolTier() (string, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return "", err
	}
	return string(resp.UserPool.UserPoolTier), nil
}

func (a *mqlAwsCognitoUserPool) accountRecoverySetting() (any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	return convert.JsonToDict(resp.UserPool.AccountRecoverySetting)
}

func (a *mqlAwsCognitoUserPool) deviceConfiguration() (any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	return convert.JsonToDict(resp.UserPool.DeviceConfiguration)
}

func (a *mqlAwsCognitoUserPool) usernameConfiguration() (any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	return convert.JsonToDict(resp.UserPool.UsernameConfiguration)
}

func (a *mqlAwsCognitoUserPool) deviceRemembering() (*mqlAwsCognitoDeviceConfiguration, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.UserPool == nil || resp.UserPool.DeviceConfiguration == nil {
		// A user pool with device remembering deactivated returns no device
		// configuration at all, which is not the same as one that remembers
		// devices with both settings off.
		a.DeviceRemembering.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	dc := resp.UserPool.DeviceConfiguration
	res, err := CreateResource(a.MqlRuntime, "aws.cognito.deviceConfiguration", map[string]*llx.RawData{
		"__id":                             llx.StringData(a.Arn.Data + "/deviceConfiguration"),
		"challengeRequiredOnNewDevice":     llx.BoolData(dc.ChallengeRequiredOnNewDevice),
		"deviceOnlyRememberedOnUserPrompt": llx.BoolData(dc.DeviceOnlyRememberedOnUserPrompt),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCognitoDeviceConfiguration), nil
}

func (a *mqlAwsCognitoUserPool) usernamePolicy() (*mqlAwsCognitoUsernameConfiguration, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.UserPool == nil || resp.UserPool.UsernameConfiguration == nil {
		a.UsernamePolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "aws.cognito.usernameConfiguration", map[string]*llx.RawData{
		"__id":          llx.StringData(a.Arn.Data + "/usernameConfiguration"),
		"caseSensitive": llx.BoolData(aws.ToBool(resp.UserPool.UsernameConfiguration.CaseSensitive)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCognitoUsernameConfiguration), nil
}

func (a *mqlAwsCognitoUserPool) schema() ([]any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	out := make([]any, 0, len(resp.UserPool.SchemaAttributes))
	for i := range resp.UserPool.SchemaAttributes {
		entry, err := convert.JsonToDict(resp.UserPool.SchemaAttributes[i])
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func (a *mqlAwsCognitoUserPool) verificationMessageTemplate() (any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	return convert.JsonToDict(resp.UserPool.VerificationMessageTemplate)
}

func (a *mqlAwsCognitoUserPool) emailConfiguration() (any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	return convert.JsonToDict(resp.UserPool.EmailConfiguration)
}

func (a *mqlAwsCognitoUserPool) smsConfiguration() (any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	return convert.JsonToDict(resp.UserPool.SmsConfiguration)
}

// lambdaConfig returns the user pool's Lambda trigger map. We project the SDK
// struct into a flat map of trigger name -> ARN (for simple scalar triggers)
// or nested struct (for the v2 pre-token-generation / custom sender configs).
// This matches the JSON shape AWS publishes in its DescribeUserPool response.
func (a *mqlAwsCognitoUserPool) lambdaConfig() (any, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		return nil, err
	}
	return convert.JsonToDict(resp.UserPool.LambdaConfig)
}

// riskConfiguration lazily fetches the pool-level threat-protection
// configuration via DescribeRiskConfiguration. The call is only meaningful
// when the user pool has advanced security enabled — for pools without it
// the API returns a ResourceNotFoundException, which we surface as null.
func (a *mqlAwsCognitoUserPool) riskConfiguration() (any, error) {
	poolId := a.Id.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CognitoIdentityProvider(region)
	ctx := context.Background()

	resp, err := svc.DescribeRiskConfiguration(ctx, &cognitoidentityprovider.DescribeRiskConfigurationInput{
		UserPoolId: &poolId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, nil
		}
		// Pools without advanced security return ResourceNotFoundException
		// or UserPoolAddOnNotEnabledException — surface as null. Any other
		// error (rate limit, transient 5xx, etc.) propagates so the runtime
		// can retry or report it.
		var rnf *cognitoidentityprovidertypes.ResourceNotFoundException
		var uae *cognitoidentityprovidertypes.UserPoolAddOnNotEnabledException
		if errors.As(err, &rnf) || errors.As(err, &uae) {
			log.Debug().Str("userPoolId", poolId).Err(err).Msg("cognito risk configuration not available for user pool")
			return nil, nil
		}
		return nil, err
	}
	if resp == nil || resp.RiskConfiguration == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.RiskConfiguration)
}

// Identity Pools (Federated Identities)

func (a *mqlAwsCognito) identityPools() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getIdentityPools(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsCognito) getIdentityPools(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("cognito>getIdentityPools>calling aws with region %s", region)

			svc := conn.CognitoIdentity(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{
					MaxResults: aws.Int32(60),
					NextToken:  nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("cognito identity service not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, pool := range resp.IdentityPools {
					poolId := convert.ToValue(pool.IdentityPoolId)
					poolArn := "arn:aws:cognito-identity:" + region + ":" + conn.AccountId() + ":identitypool/" + poolId

					mqlPool, err := CreateResource(a.MqlRuntime, "aws.cognito.identityPool",
						map[string]*llx.RawData{
							"__id":   llx.StringData(poolArn),
							"id":     llx.StringData(poolId),
							"name":   llx.StringDataPtr(pool.IdentityPoolName),
							"region": llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPool)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsCognitoIdentityPoolInternal struct {
	descCache *cognitoidentity.DescribeIdentityPoolOutput
	descDone  bool
	descLock  sync.Mutex
}

const cognitoIdentityPoolArnPattern = "arn:aws:cognito-identity:%s:%s:identitypool/%s"

func (a *mqlAwsCognitoIdentityPool) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(cognitoIdentityPoolArnPattern, a.Region.Data, conn.AccountId(), a.Id.Data), nil
}

func (a *mqlAwsCognitoIdentityPool) describe() (*cognitoidentity.DescribeIdentityPoolOutput, error) {
	if a.descDone {
		return a.descCache, nil
	}
	a.descLock.Lock()
	defer a.descLock.Unlock()

	if a.descDone {
		return a.descCache, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CognitoIdentity(a.Region.Data)
	ctx := context.Background()
	poolId := a.Id.Data

	resp, err := svc.DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{
		IdentityPoolId: &poolId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.descDone = true
			return nil, nil
		}
		return nil, err
	}

	a.descCache = resp
	a.descDone = true
	return resp, nil
}

func (a *mqlAwsCognitoIdentityPool) allowUnauthenticatedIdentities() (bool, error) {
	resp, err := a.describe()
	if err != nil || resp == nil {
		return false, err
	}
	return resp.AllowUnauthenticatedIdentities, nil
}

func (a *mqlAwsCognitoIdentityPool) allowClassicFlow() (bool, error) {
	resp, err := a.describe()
	if err != nil || resp == nil {
		return false, err
	}
	if resp.AllowClassicFlow == nil {
		return false, nil
	}
	return *resp.AllowClassicFlow, nil
}

func (a *mqlAwsCognitoIdentityPool) developerProviderName() (string, error) {
	resp, err := a.describe()
	if err != nil || resp == nil {
		return "", err
	}
	return convert.ToValue(resp.DeveloperProviderName), nil
}

func (a *mqlAwsCognitoIdentityPool) openIdConnectProviderArns() ([]any, error) {
	resp, err := a.describe()
	if err != nil || resp == nil {
		return nil, err
	}
	var arns []any
	for _, arn := range resp.OpenIdConnectProviderARNs {
		arns = append(arns, arn)
	}
	return arns, nil
}

func (a *mqlAwsCognitoIdentityPool) samlProviderArns() ([]any, error) {
	resp, err := a.describe()
	if err != nil || resp == nil {
		return nil, err
	}
	var arns []any
	for _, arn := range resp.SamlProviderARNs {
		arns = append(arns, arn)
	}
	return arns, nil
}

func (a *mqlAwsCognitoIdentityPool) supportedLoginProviders() (map[string]any, error) {
	resp, err := a.describe()
	if err != nil || resp == nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(resp.SupportedLoginProviders), nil
}

func (a *mqlAwsCognitoIdentityPool) tags() (map[string]any, error) {
	resp, err := a.describe()
	if err != nil || resp == nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(resp.IdentityPoolTags), nil
}

func (a *mqlAwsCognitoIdentityPool) cognitoIdentityProviders() ([]any, error) {
	resp, err := a.describe()
	if err != nil || resp == nil {
		return nil, err
	}
	out := make([]any, 0, len(resp.CognitoIdentityProviders))
	for i := range resp.CognitoIdentityProviders {
		entry, err := convert.JsonToDict(resp.CognitoIdentityProviders[i])
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// roles lazily fetches the authenticated and unauthenticated role bindings
// for the identity pool. The Roles key holds a map with `authenticated` and
// `unauthenticated` role ARNs; RoleMappings holds the per-provider
// rule/token mapping when configured.
func (a *mqlAwsCognitoIdentityPool) roles() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CognitoIdentity(a.Region.Data)
	ctx := context.Background()
	poolId := a.Id.Data

	resp, err := svc.GetIdentityPoolRoles(ctx, &cognitoidentity.GetIdentityPoolRolesInput{
		IdentityPoolId: &poolId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, nil
		}
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if len(resp.Roles) == 0 && len(resp.RoleMappings) == 0 {
		return nil, nil
	}
	out := map[string]any{}
	if len(resp.Roles) > 0 {
		out["Roles"] = convert.MapToInterfaceMap(resp.Roles)
	}
	if len(resp.RoleMappings) > 0 {
		mappings := map[string]any{}
		for k, v := range resp.RoleMappings {
			entry, err := convert.JsonToDict(v)
			if err != nil {
				return nil, err
			}
			mappings[k] = entry
		}
		out["RoleMappings"] = mappings
	}
	return out, nil
}

// User pool app clients

func (a *mqlAwsCognitoUserPool) clients() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	poolId := a.Id.Data
	svc := conn.CognitoIdentityProvider(region)
	ctx := context.Background()

	res := []any{}
	paginator := cognitoidentityprovider.NewListUserPoolClientsPaginator(svc, &cognitoidentityprovider.ListUserPoolClientsInput{
		UserPoolId: &poolId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.UserPoolClients {
			detail, err := svc.DescribeUserPoolClient(ctx, &cognitoidentityprovider.DescribeUserPoolClientInput{
				UserPoolId: c.UserPoolId,
				ClientId:   c.ClientId,
			})
			if err != nil {
				log.Warn().Str("userPoolId", aws.ToString(c.UserPoolId)).Str("clientId", aws.ToString(c.ClientId)).Err(err).Msg("could not describe Cognito user pool client")
				continue
			}
			if detail.UserPoolClient == nil {
				continue
			}
			mqlClient, err := newMqlAwsCognitoUserPoolClient(a.MqlRuntime, region, detail.UserPoolClient)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlClient)
		}
	}
	return res, nil
}

func newMqlAwsCognitoUserPoolClient(runtime *plugin.Runtime, region string, c *cognitoidentityprovidertypes.UserPoolClientType) (plugin.Resource, error) {
	tokenUnits := map[string]any{}
	mqlTokenUnits := llx.NilData
	if c.TokenValidityUnits != nil {
		tokenUnits["accessToken"] = string(c.TokenValidityUnits.AccessToken)
		tokenUnits["idToken"] = string(c.TokenValidityUnits.IdToken)
		tokenUnits["refreshToken"] = string(c.TokenValidityUnits.RefreshToken)

		res, err := CreateResource(runtime, "aws.cognito.tokenValidityUnits", map[string]*llx.RawData{
			"__id":         llx.StringData(aws.ToString(c.UserPoolId) + "/" + aws.ToString(c.ClientId) + "/tokenValidityUnits"),
			"accessToken":  llx.StringData(string(c.TokenValidityUnits.AccessToken)),
			"idToken":      llx.StringData(string(c.TokenValidityUnits.IdToken)),
			"refreshToken": llx.StringData(string(c.TokenValidityUnits.RefreshToken)),
		})
		if err != nil {
			return nil, err
		}
		mqlTokenUnits = llx.ResourceData(res, "aws.cognito.tokenValidityUnits")
	}

	authFlows := make([]any, 0, len(c.ExplicitAuthFlows))
	for _, f := range c.ExplicitAuthFlows {
		authFlows = append(authFlows, string(f))
	}
	oauthFlows := make([]any, 0, len(c.AllowedOAuthFlows))
	for _, f := range c.AllowedOAuthFlows {
		oauthFlows = append(oauthFlows, string(f))
	}

	// DescribeUserPoolClient does not surface the GenerateSecret config flag
	// directly — infer it from whether a secret value was returned.
	hasSecret := c.ClientSecret != nil && *c.ClientSecret != ""

	res, err := CreateResource(runtime, "aws.cognito.userPoolClient", map[string]*llx.RawData{
		"clientId":                        llx.StringDataPtr(c.ClientId),
		"clientName":                      llx.StringDataPtr(c.ClientName),
		"userPoolId":                      llx.StringDataPtr(c.UserPoolId),
		"region":                          llx.StringData(region),
		"generateSecret":                  llx.BoolData(hasSecret),
		"refreshTokenValidity":            llx.IntData(int64(c.RefreshTokenValidity)),
		"accessTokenValidity":             llx.IntData(int64(aws.ToInt32(c.AccessTokenValidity))),
		"idTokenValidity":                 llx.IntData(int64(aws.ToInt32(c.IdTokenValidity))),
		"tokenValidityUnits":              llx.DictData(tokenUnits),
		"validityUnits":                   mqlTokenUnits,
		"explicitAuthFlows":               llx.ArrayData(authFlows, types.String),
		"supportedIdentityProviders":      llx.ArrayData(stringsToAnyArray(c.SupportedIdentityProviders), types.String),
		"callbackURLs":                    llx.ArrayData(stringsToAnyArray(c.CallbackURLs), types.String),
		"logoutURLs":                      llx.ArrayData(stringsToAnyArray(c.LogoutURLs), types.String),
		"defaultRedirectURI":              llx.StringDataPtr(c.DefaultRedirectURI),
		"allowedOAuthFlows":               llx.ArrayData(oauthFlows, types.String),
		"allowedOAuthScopes":              llx.ArrayData(stringsToAnyArray(c.AllowedOAuthScopes), types.String),
		"allowedOAuthFlowsUserPoolClient": llx.BoolData(aws.ToBool(c.AllowedOAuthFlowsUserPoolClient)),
		"preventUserExistenceErrors":      llx.StringData(string(c.PreventUserExistenceErrors)),
		"enableTokenRevocation":           llx.BoolData(aws.ToBool(c.EnableTokenRevocation)),
		"authSessionValidity":             llx.IntData(int64(aws.ToInt32(c.AuthSessionValidity))),
		"createdAt":                       llx.TimeDataPtr(c.CreationDate),
		"updatedAt":                       llx.TimeDataPtr(c.LastModifiedDate),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCognitoUserPoolClient), nil
}

func stringsToAnyArray(ss []string) []any {
	res := make([]any, len(ss))
	for i, s := range ss {
		res[i] = s
	}
	return res
}

func (a *mqlAwsCognitoUserPoolClient) id() (string, error) {
	return a.UserPoolId.Data + "/" + a.ClientId.Data, nil
}

// resolveCognitoUserPool returns the user-pool reference for a sub-resource
// keyed by region+userPoolId.
//
// It passes the ARN and nothing else. That is the one argument
// initAwsCognitoUserPool accepts, and the ARN is also the pool's __id, so a
// pool the listing path already built is served from the cache and one reached
// on its own is fetched and fully populated by the init.
func resolveCognitoUserPool(runtime *plugin.Runtime, region, userPoolId string) (*mqlAwsCognitoUserPool, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	poolArn := cognitoUserPoolArn(region, conn.AccountId(), userPoolId)
	mqlPool, err := NewResource(runtime, "aws.cognito.userPool",
		map[string]*llx.RawData{
			"arn": llx.StringData(poolArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlPool.(*mqlAwsCognitoUserPool), nil
}

func (a *mqlAwsCognitoUserPoolClient) userPool() (*mqlAwsCognitoUserPool, error) {
	return resolveCognitoUserPool(a.MqlRuntime, a.Region.Data, a.UserPoolId.Data)
}

// User pool hosted UI domain

func (a *mqlAwsCognitoUserPool) domain() (*mqlAwsCognitoUserPoolDomain, error) {
	resp, err := a.fetchDescribeUserPool()
	if err != nil || resp == nil || resp.UserPool == nil {
		a.Domain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, err
	}

	domain := aws.ToString(resp.UserPool.Domain)
	custom := aws.ToString(resp.UserPool.CustomDomain)
	name := custom
	if name == "" {
		name = domain
	}
	if name == "" {
		a.Domain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CognitoIdentityProvider(region)
	ctx := context.Background()
	detail, err := svc.DescribeUserPoolDomain(ctx, &cognitoidentityprovider.DescribeUserPoolDomainInput{
		Domain: &name,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.Domain.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if detail.DomainDescription == nil || aws.ToString(detail.DomainDescription.UserPoolId) == "" {
		a.Domain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	dd := detail.DomainDescription
	customConfig, _ := convert.JsonToDict(dd.CustomDomainConfig)

	tlsSecurityPolicy := ""
	if dd.CustomDomainConfig != nil {
		tlsSecurityPolicy = string(dd.CustomDomainConfig.SecurityPolicy)
	}

	res, err := CreateResource(a.MqlRuntime, "aws.cognito.userPoolDomain", map[string]*llx.RawData{
		"domain":                 llx.StringData(name),
		"userPoolId":             llx.StringDataPtr(dd.UserPoolId),
		"region":                 llx.StringData(region),
		"status":                 llx.StringData(string(dd.Status)),
		"cloudFrontDistribution": llx.StringDataPtr(dd.CloudFrontDistribution),
		"s3Bucket":               llx.StringDataPtr(dd.S3Bucket),
		"customDomainConfig":     llx.DictData(customConfig),
		"tlsSecurityPolicy":      llx.StringData(tlsSecurityPolicy),
		"version":                llx.StringDataPtr(dd.Version),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCognitoUserPoolDomain), nil
}

func (a *mqlAwsCognitoUserPoolDomain) id() (string, error) {
	return a.UserPoolId.Data + "/" + a.Domain.Data, nil
}

func (a *mqlAwsCognitoUserPoolDomain) userPool() (*mqlAwsCognitoUserPool, error) {
	return resolveCognitoUserPool(a.MqlRuntime, a.Region.Data, a.UserPoolId.Data)
}

// User pool federated identity providers

func (a *mqlAwsCognitoUserPool) identityProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	poolId := a.Id.Data
	svc := conn.CognitoIdentityProvider(region)
	ctx := context.Background()

	res := []any{}
	paginator := cognitoidentityprovider.NewListIdentityProvidersPaginator(svc, &cognitoidentityprovider.ListIdentityProvidersInput{
		UserPoolId: &poolId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, p := range page.Providers {
			detail, err := svc.DescribeIdentityProvider(ctx, &cognitoidentityprovider.DescribeIdentityProviderInput{
				UserPoolId:   &poolId,
				ProviderName: p.ProviderName,
			})
			if err != nil {
				log.Warn().Str("userPoolId", poolId).Str("providerName", aws.ToString(p.ProviderName)).Err(err).Msg("could not describe Cognito identity provider")
				continue
			}
			if detail.IdentityProvider == nil {
				continue
			}
			mqlIdp, err := newMqlAwsCognitoUserPoolIdentityProvider(a.MqlRuntime, region, detail.IdentityProvider)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlIdp)
		}
	}
	return res, nil
}

func newMqlAwsCognitoUserPoolIdentityProvider(runtime *plugin.Runtime, region string, p *cognitoidentityprovidertypes.IdentityProviderType) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "aws.cognito.userPoolIdentityProvider", map[string]*llx.RawData{
		"providerName":     llx.StringDataPtr(p.ProviderName),
		"providerType":     llx.StringData(string(p.ProviderType)),
		"userPoolId":       llx.StringDataPtr(p.UserPoolId),
		"region":           llx.StringData(region),
		"attributeMapping": llx.MapData(convert.MapToInterfaceMap(p.AttributeMapping), types.String),
		"idpIdentifiers":   llx.ArrayData(stringsToAnyArray(p.IdpIdentifiers), types.String),
		"providerDetails":  llx.MapData(convert.MapToInterfaceMap(p.ProviderDetails), types.String),
		"createdAt":        llx.TimeDataPtr(p.CreationDate),
		"updatedAt":        llx.TimeDataPtr(p.LastModifiedDate),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCognitoUserPoolIdentityProvider), nil
}

func (a *mqlAwsCognitoUserPoolIdentityProvider) id() (string, error) {
	return a.UserPoolId.Data + "/" + a.ProviderName.Data, nil
}

func (a *mqlAwsCognitoUserPoolIdentityProvider) userPool() (*mqlAwsCognitoUserPool, error) {
	return resolveCognitoUserPool(a.MqlRuntime, a.Region.Data, a.UserPoolId.Data)
}
