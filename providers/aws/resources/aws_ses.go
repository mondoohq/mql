// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sesv2_types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

type mqlAwsSesInternal struct {
	accountOnce sync.Once
	account     *sesv2.GetAccountOutput
	accountErr  error
}

func (a *mqlAwsSes) id() (string, error) {
	return "aws.ses", nil
}

// getAccount fetches account-level SES settings once. The pricing plan is
// account-global, so a single GetAccount call against the connection's default
// region serves every pricing field. Access-denied leaves the cached result
// nil so the pricing fields resolve to an empty string rather than erroring.
func (a *mqlAwsSes) getAccount() (*sesv2.GetAccountOutput, error) {
	a.accountOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Sesv2(conn.Region())
		out, err := svc.GetAccount(context.Background(), &sesv2.GetAccountInput{})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return
			}
			a.accountErr = err
			return
		}
		a.account = out
	})
	return a.account, a.accountErr
}

func (a *mqlAwsSes) pricingPlan() (string, error) {
	acct, err := a.getAccount()
	if err != nil {
		return "", err
	}
	if acct == nil || acct.PricingAttributes == nil {
		return "", nil
	}
	return string(acct.PricingAttributes.CurrentPlan), nil
}

func (a *mqlAwsSes) nextPricingPlan() (string, error) {
	acct, err := a.getAccount()
	if err != nil {
		return "", err
	}
	if acct == nil || acct.PricingAttributes == nil {
		return "", nil
	}
	return string(acct.PricingAttributes.NextPlan), nil
}

func sesTagsToMap(tags []sesv2_types.Tag) map[string]any {
	return tagsToMap(tags, func(t sesv2_types.Tag) *string { return t.Key }, func(t sesv2_types.Tag) *string { return t.Value })
}

// ---- aws.ses.identity ----

func (a *mqlAwsSes) identities() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getIdentities(conn), 5)
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

func (a *mqlAwsSes) getIdentities(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ses>getIdentities>calling aws with region %s", region)

			svc := conn.Sesv2(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				page, err := svc.ListEmailIdentities(ctx, &sesv2.ListEmailIdentitiesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("SES service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, identity := range page.EmailIdentities {
					mqlIdentity, err := newMqlAwsSesIdentity(a.MqlRuntime, region, conn.AccountId(), identity)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlIdentity)
				}
				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}
			return res, nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func sesIdentityArn(region, accountID, name string) string {
	return fmt.Sprintf("arn:aws:ses:%s:%s:identity/%s", region, accountID, name)
}

func newMqlAwsSesIdentity(runtime *plugin.Runtime, region string, accountID string, identity sesv2_types.IdentityInfo) (*mqlAwsSesIdentity, error) {
	name := ""
	if identity.IdentityName != nil {
		name = *identity.IdentityName
	}
	arn := sesIdentityArn(region, accountID, name)

	resource, err := CreateResource(runtime, "aws.ses.identity",
		map[string]*llx.RawData{
			"__id":               llx.StringData(arn),
			"arn":                llx.StringData(arn),
			"name":               llx.StringData(name),
			"region":             llx.StringData(region),
			"identityType":       llx.StringData(string(identity.IdentityType)),
			"verificationStatus": llx.StringData(string(identity.VerificationStatus)),
			"verifiedForSending": llx.BoolData(identity.SendingEnabled),
		})
	if err != nil {
		return nil, err
	}

	mqlIdentity := resource.(*mqlAwsSesIdentity)
	mqlIdentity.region = region
	mqlIdentity.cacheName = name
	return mqlIdentity, nil
}

type mqlAwsSesIdentityInternal struct {
	region    string
	cacheName string
	fetched   bool
	lock      sync.Mutex

	// Certificates come from a separate API call, so they get their own
	// guard: an identity queried only for its DKIM settings should not pay
	// for a certificate listing, and vice versa.
	certificatesFetched bool
	certificatesLock    sync.Mutex
	cachedCertificates  []any
}

// markIdentityDetailsNull marks every lazily fetched field as resolved-but-null
// so the runtime treats them as known-unavailable (e.g. on access-denied)
// rather than unresolved, which would otherwise re-trigger the accessor.
func (a *mqlAwsSesIdentity) markIdentityDetailsNull() {
	null := plugin.StateIsSet | plugin.StateIsNull
	a.FeedbackForwardingEnabled = plugin.TValue[bool]{State: null}
	a.DkimSigningEnabled = plugin.TValue[bool]{State: null}
	a.DkimStatus = plugin.TValue[string]{State: null}
	a.DkimSigningAttributesOrigin = plugin.TValue[string]{State: null}
	a.DkimSigningKeyLength = plugin.TValue[string]{State: null}
	a.DkimTokens = plugin.TValue[[]any]{State: null}
	a.MailFromDomain = plugin.TValue[string]{State: null}
	a.MailFromDomainStatus = plugin.TValue[string]{State: null}
	a.MailFromBehaviorOnMxFailure = plugin.TValue[string]{State: null}
	a.Policies = plugin.TValue[map[string]any]{State: null}
	a.Tags = plugin.TValue[map[string]any]{State: null}
}

func (a *mqlAwsSesIdentity) fetchDetails() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sesv2(a.region)
	ctx := context.Background()

	resp, err := svc.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{
		EmailIdentity: &a.cacheName,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Str("identity", a.cacheName).Msg("access denied getting SES email identity")
			a.markIdentityDetailsNull()
			a.fetched = true
			return nil
		}
		return err
	}

	a.FeedbackForwardingEnabled = plugin.TValue[bool]{Data: resp.FeedbackForwardingStatus, State: plugin.StateIsSet}

	dkimSigningEnabled := false
	dkimStatus := ""
	dkimOrigin := ""
	dkimKeyLength := ""
	dkimTokens := []any{}
	if resp.DkimAttributes != nil {
		dkimSigningEnabled = resp.DkimAttributes.SigningEnabled
		dkimStatus = string(resp.DkimAttributes.Status)
		dkimOrigin = string(resp.DkimAttributes.SigningAttributesOrigin)
		dkimKeyLength = string(resp.DkimAttributes.CurrentSigningKeyLength)
		for _, t := range resp.DkimAttributes.Tokens {
			dkimTokens = append(dkimTokens, t)
		}
	}
	a.DkimSigningEnabled = plugin.TValue[bool]{Data: dkimSigningEnabled, State: plugin.StateIsSet}
	a.DkimStatus = plugin.TValue[string]{Data: dkimStatus, State: plugin.StateIsSet}
	a.DkimSigningAttributesOrigin = plugin.TValue[string]{Data: dkimOrigin, State: plugin.StateIsSet}
	a.DkimSigningKeyLength = plugin.TValue[string]{Data: dkimKeyLength, State: plugin.StateIsSet}
	a.DkimTokens = plugin.TValue[[]any]{Data: dkimTokens, State: plugin.StateIsSet}

	mailFromDomain := ""
	mailFromDomainStatus := ""
	mailFromBehavior := ""
	if resp.MailFromAttributes != nil {
		if resp.MailFromAttributes.MailFromDomain != nil {
			mailFromDomain = *resp.MailFromAttributes.MailFromDomain
		}
		mailFromDomainStatus = string(resp.MailFromAttributes.MailFromDomainStatus)
		mailFromBehavior = string(resp.MailFromAttributes.BehaviorOnMxFailure)
	}
	a.MailFromDomain = plugin.TValue[string]{Data: mailFromDomain, State: plugin.StateIsSet}
	a.MailFromDomainStatus = plugin.TValue[string]{Data: mailFromDomainStatus, State: plugin.StateIsSet}
	a.MailFromBehaviorOnMxFailure = plugin.TValue[string]{Data: mailFromBehavior, State: plugin.StateIsSet}

	policies := map[string]any{}
	for k, v := range resp.Policies {
		policies[k] = v
	}
	a.Policies = plugin.TValue[map[string]any]{Data: policies, State: plugin.StateIsSet}

	a.Tags = plugin.TValue[map[string]any]{Data: sesTagsToMap(resp.Tags), State: plugin.StateIsSet}

	a.fetched = true
	return nil
}

func (a *mqlAwsSesIdentity) feedbackForwardingEnabled() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.FeedbackForwardingEnabled.Data, nil
}

func (a *mqlAwsSesIdentity) dkimSigningEnabled() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.DkimSigningEnabled.Data, nil
}

func (a *mqlAwsSesIdentity) dkimStatus() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.DkimStatus.Data, nil
}

func (a *mqlAwsSesIdentity) dkimSigningAttributesOrigin() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.DkimSigningAttributesOrigin.Data, nil
}

func (a *mqlAwsSesIdentity) dkimSigningKeyLength() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.DkimSigningKeyLength.Data, nil
}

func (a *mqlAwsSesIdentity) dkimTokens() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.DkimTokens.Data, nil
}

func (a *mqlAwsSesIdentity) mailFromDomain() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.MailFromDomain.Data, nil
}

func (a *mqlAwsSesIdentity) mailFromDomainStatus() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.MailFromDomainStatus.Data, nil
}

func (a *mqlAwsSesIdentity) mailFromBehaviorOnMxFailure() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.MailFromBehaviorOnMxFailure.Data, nil
}

func (a *mqlAwsSesIdentity) policies() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.Policies.Data, nil
}

func (a *mqlAwsSesIdentity) tags() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.Tags.Data, nil
}

func initAwsSesIdentity(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch aws ses identity")
	}

	// Resolve to the identity already populated by `aws.ses.identities` so the
	// cached region/name used by lazy GetEmailIdentity calls are preserved.
	obj, err := CreateResource(runtime, "aws.ses", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	ses := obj.(*mqlAwsSes)
	identities := ses.GetIdentities()
	if identities != nil && identities.Error == nil {
		var arnVal, nameVal string
		if args["arn"] != nil {
			arnVal, _ = args["arn"].Value.(string)
		}
		if args["name"] != nil {
			nameVal, _ = args["name"].Value.(string)
		}
		for _, raw := range identities.Data {
			i := raw.(*mqlAwsSesIdentity)
			if (arnVal != "" && i.Arn.Data == arnVal) || (nameVal != "" && i.Name.Data == nameVal) {
				return args, i, nil
			}
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws ses identity that is not in the identities list")
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	arnStr, _ := args["arn"].Value.(string)
	return nil, nil, fmt.Errorf("aws.ses.identity with arn %q not found", arnStr)
}

// ---- aws.ses.configurationSet ----

func (a *mqlAwsSes) configurationSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConfigurationSets(conn), 5)
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

func (a *mqlAwsSes) getConfigurationSets(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ses>getConfigurationSets>calling aws with region %s", region)

			svc := conn.Sesv2(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				page, err := svc.ListConfigurationSets(ctx, &sesv2.ListConfigurationSetsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("SES service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, name := range page.ConfigurationSets {
					mqlConfigSet, err := newMqlAwsSesConfigurationSet(a.MqlRuntime, region, conn.AccountId(), name)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlConfigSet)
				}
				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}
			return res, nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func sesConfigurationSetArn(region, accountID, name string) string {
	return fmt.Sprintf("arn:aws:ses:%s:%s:configuration-set/%s", region, accountID, name)
}

func newMqlAwsSesConfigurationSet(runtime *plugin.Runtime, region string, accountID string, name string) (*mqlAwsSesConfigurationSet, error) {
	arn := sesConfigurationSetArn(region, accountID, name)
	resource, err := CreateResource(runtime, "aws.ses.configurationSet",
		map[string]*llx.RawData{
			"__id":   llx.StringData(arn),
			"arn":    llx.StringData(arn),
			"name":   llx.StringData(name),
			"region": llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}

	mqlConfigSet := resource.(*mqlAwsSesConfigurationSet)
	mqlConfigSet.region = region
	mqlConfigSet.cacheName = name
	return mqlConfigSet, nil
}

type mqlAwsSesConfigurationSetInternal struct {
	region    string
	cacheName string
	fetched   bool
	lock      sync.Mutex
}

// markConfigurationSetDetailsNull marks every lazily fetched field as
// resolved-but-null so the runtime treats them as known-unavailable (e.g. on
// access-denied) rather than unresolved, which would otherwise re-trigger the
// accessor.
func (a *mqlAwsSesConfigurationSet) markConfigurationSetDetailsNull() {
	null := plugin.StateIsSet | plugin.StateIsNull
	a.TlsPolicy = plugin.TValue[string]{State: null}
	a.SendingPoolName = plugin.TValue[string]{State: null}
	a.SendingEnabled = plugin.TValue[bool]{State: null}
	a.ReputationMetricsEnabled = plugin.TValue[bool]{State: null}
	a.SuppressedReasons = plugin.TValue[[]any]{State: null}
	a.TrackingRedirectDomain = plugin.TValue[string]{State: null}
	a.TrackingHttpsPolicy = plugin.TValue[string]{State: null}
	a.Tags = plugin.TValue[map[string]any]{State: null}
}

func (a *mqlAwsSesConfigurationSet) fetchDetails() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sesv2(a.region)
	ctx := context.Background()

	resp, err := svc.GetConfigurationSet(ctx, &sesv2.GetConfigurationSetInput{
		ConfigurationSetName: &a.cacheName,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Str("configurationSet", a.cacheName).Msg("access denied getting SES configuration set")
			a.markConfigurationSetDetailsNull()
			a.fetched = true
			return nil
		}
		return err
	}

	tlsPolicy := ""
	sendingPoolName := ""
	if resp.DeliveryOptions != nil {
		tlsPolicy = string(resp.DeliveryOptions.TlsPolicy)
		if resp.DeliveryOptions.SendingPoolName != nil {
			sendingPoolName = *resp.DeliveryOptions.SendingPoolName
		}
	}
	a.TlsPolicy = plugin.TValue[string]{Data: tlsPolicy, State: plugin.StateIsSet}
	a.SendingPoolName = plugin.TValue[string]{Data: sendingPoolName, State: plugin.StateIsSet}

	sendingEnabled := false
	if resp.SendingOptions != nil {
		sendingEnabled = resp.SendingOptions.SendingEnabled
	}
	a.SendingEnabled = plugin.TValue[bool]{Data: sendingEnabled, State: plugin.StateIsSet}

	reputationEnabled := false
	if resp.ReputationOptions != nil {
		reputationEnabled = resp.ReputationOptions.ReputationMetricsEnabled
	}
	a.ReputationMetricsEnabled = plugin.TValue[bool]{Data: reputationEnabled, State: plugin.StateIsSet}

	suppressedReasons := []any{}
	if resp.SuppressionOptions != nil {
		for _, r := range resp.SuppressionOptions.SuppressedReasons {
			suppressedReasons = append(suppressedReasons, string(r))
		}
	}
	a.SuppressedReasons = plugin.TValue[[]any]{Data: suppressedReasons, State: plugin.StateIsSet}

	trackingDomain := ""
	trackingHttpsPolicy := ""
	if resp.TrackingOptions != nil {
		if resp.TrackingOptions.CustomRedirectDomain != nil {
			trackingDomain = *resp.TrackingOptions.CustomRedirectDomain
		}
		trackingHttpsPolicy = string(resp.TrackingOptions.HttpsPolicy)
	}
	a.TrackingRedirectDomain = plugin.TValue[string]{Data: trackingDomain, State: plugin.StateIsSet}
	a.TrackingHttpsPolicy = plugin.TValue[string]{Data: trackingHttpsPolicy, State: plugin.StateIsSet}

	a.Tags = plugin.TValue[map[string]any]{Data: sesTagsToMap(resp.Tags), State: plugin.StateIsSet}

	a.fetched = true
	return nil
}

func (a *mqlAwsSesConfigurationSet) tlsPolicy() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.TlsPolicy.Data, nil
}

func (a *mqlAwsSesConfigurationSet) sendingPoolName() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.SendingPoolName.Data, nil
}

func (a *mqlAwsSesConfigurationSet) sendingEnabled() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.SendingEnabled.Data, nil
}

func (a *mqlAwsSesConfigurationSet) reputationMetricsEnabled() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return a.ReputationMetricsEnabled.Data, nil
}

func (a *mqlAwsSesConfigurationSet) suppressedReasons() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.SuppressedReasons.Data, nil
}

func (a *mqlAwsSesConfigurationSet) trackingRedirectDomain() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.TrackingRedirectDomain.Data, nil
}

func (a *mqlAwsSesConfigurationSet) trackingHttpsPolicy() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.TrackingHttpsPolicy.Data, nil
}

func (a *mqlAwsSesConfigurationSet) tags() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.Tags.Data, nil
}

func initAwsSesConfigurationSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch aws ses configuration set")
	}

	// Resolve to the configuration set already populated by
	// `aws.ses.configurationSets` so the cached region/name used by lazy
	// GetConfigurationSet calls are preserved. Matching by ARN is unambiguous;
	// configuration-set names are only unique within a region, so a name-only
	// lookup returns the first region whose set matches.
	obj, err := CreateResource(runtime, "aws.ses", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	ses := obj.(*mqlAwsSes)
	configSets := ses.GetConfigurationSets()
	if configSets != nil && configSets.Error == nil {
		var arnVal, nameVal string
		if args["arn"] != nil {
			arnVal, _ = args["arn"].Value.(string)
		}
		if args["name"] != nil {
			nameVal, _ = args["name"].Value.(string)
		}
		for _, raw := range configSets.Data {
			c := raw.(*mqlAwsSesConfigurationSet)
			if (arnVal != "" && c.Arn.Data == arnVal) || (nameVal != "" && c.Name.Data == nameVal) {
				return args, c, nil
			}
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws ses configuration set that is not in the configuration sets list")
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	arnStr, _ := args["arn"].Value.(string)
	return nil, nil, fmt.Errorf("aws.ses.configurationSet with arn %q not found", arnStr)
}
