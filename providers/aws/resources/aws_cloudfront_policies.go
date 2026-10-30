// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/aws/connection"
	mqltypes "go.mondoo.com/mql/types"
)

// -- Response headers policies ----------------------------------------------

func (a *mqlAwsCloudfrontResponseHeadersPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) responseHeadersPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("") // global service
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListResponseHeadersPolicies(ctx, &cloudfront.ListResponseHeadersPoliciesInput{
			Marker: marker,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not gather aws cloudfront response headers policies")
		}
		if resp.ResponseHeadersPolicyList == nil {
			break
		}
		for _, item := range resp.ResponseHeadersPolicyList.Items {
			policy := item.ResponseHeadersPolicy
			if policy == nil {
				continue
			}
			args := map[string]*llx.RawData{
				"id":               llx.StringDataPtr(policy.Id),
				"type":             llx.StringData(string(item.Type)),
				"lastModifiedTime": llx.TimeDataPtr(policy.LastModifiedTime),
			}
			cfg := policy.ResponseHeadersPolicyConfig
			if cfg != nil {
				args["name"] = llx.StringDataPtr(cfg.Name)
				args["comment"] = llx.StringDataPtr(cfg.Comment)
				args["corsConfig"] = llx.MapData(cloudfrontResponseHeadersCorsToDict(cfg.CorsConfig), mqltypes.Any)
				args["securityHeadersConfig"] = llx.MapData(cloudfrontResponseHeadersSecurityToDict(cfg.SecurityHeadersConfig), mqltypes.Any)
				args["serverTimingHeadersConfig"] = llx.MapData(cloudfrontServerTimingToDict(cfg.ServerTimingHeadersConfig), mqltypes.Any)
				args["customHeadersConfig"] = llx.ArrayData(cloudfrontCustomHeadersToDictSlice(cfg.CustomHeadersConfig), mqltypes.Any)
				args["removeHeadersConfig"] = llx.ArrayData(cloudfrontRemoveHeadersToList(cfg.RemoveHeadersConfig), mqltypes.String)
			} else {
				args["name"] = llx.StringData("")
				args["comment"] = llx.StringData("")
				args["corsConfig"] = llx.MapData(nil, mqltypes.Any)
				args["securityHeadersConfig"] = llx.MapData(nil, mqltypes.Any)
				args["serverTimingHeadersConfig"] = llx.MapData(nil, mqltypes.Any)
				args["customHeadersConfig"] = llx.ArrayData([]any{}, mqltypes.Any)
				args["removeHeadersConfig"] = llx.ArrayData([]any{}, mqltypes.String)
			}

			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.responseHeadersPolicy", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.ResponseHeadersPolicyList.NextMarker == nil {
			break
		}
		marker = resp.ResponseHeadersPolicyList.NextMarker
	}
	return res, nil
}

func cloudfrontResponseHeadersCorsToDict(c *types.ResponseHeadersPolicyCorsConfig) map[string]any {
	if c == nil {
		return nil
	}
	out := map[string]any{}
	if c.AccessControlAllowCredentials != nil {
		out["accessControlAllowCredentials"] = *c.AccessControlAllowCredentials
	}
	if c.OriginOverride != nil {
		out["originOverride"] = *c.OriginOverride
	}
	if c.AccessControlMaxAgeSec != nil {
		out["accessControlMaxAgeSec"] = int64(*c.AccessControlMaxAgeSec)
	}
	if c.AccessControlAllowHeaders != nil {
		out["accessControlAllowHeaders"] = toAnySlice(c.AccessControlAllowHeaders.Items)
	}
	if c.AccessControlAllowOrigins != nil {
		out["accessControlAllowOrigins"] = toAnySlice(c.AccessControlAllowOrigins.Items)
	}
	if c.AccessControlAllowMethods != nil {
		methods := make([]any, 0, len(c.AccessControlAllowMethods.Items))
		for _, m := range c.AccessControlAllowMethods.Items {
			methods = append(methods, string(m))
		}
		out["accessControlAllowMethods"] = methods
	}
	if c.AccessControlExposeHeaders != nil {
		out["accessControlExposeHeaders"] = toAnySlice(c.AccessControlExposeHeaders.Items)
	}
	return out
}

func cloudfrontResponseHeadersSecurityToDict(s *types.ResponseHeadersPolicySecurityHeadersConfig) map[string]any {
	if s == nil {
		return nil
	}
	out := map[string]any{}
	if s.XSSProtection != nil {
		xss := map[string]any{}
		if s.XSSProtection.Override != nil {
			xss["override"] = *s.XSSProtection.Override
		}
		if s.XSSProtection.Protection != nil {
			xss["protection"] = *s.XSSProtection.Protection
		}
		if s.XSSProtection.ModeBlock != nil {
			xss["modeBlock"] = *s.XSSProtection.ModeBlock
		}
		if s.XSSProtection.ReportUri != nil {
			xss["reportUri"] = *s.XSSProtection.ReportUri
		}
		out["xssProtection"] = xss
	}
	if s.FrameOptions != nil {
		fo := map[string]any{
			"frameOption": string(s.FrameOptions.FrameOption),
		}
		if s.FrameOptions.Override != nil {
			fo["override"] = *s.FrameOptions.Override
		}
		out["frameOptions"] = fo
	}
	if s.ReferrerPolicy != nil {
		rp := map[string]any{
			"referrerPolicy": string(s.ReferrerPolicy.ReferrerPolicy),
		}
		if s.ReferrerPolicy.Override != nil {
			rp["override"] = *s.ReferrerPolicy.Override
		}
		out["referrerPolicy"] = rp
	}
	if s.ContentSecurityPolicy != nil {
		csp := map[string]any{}
		if s.ContentSecurityPolicy.ContentSecurityPolicy != nil {
			csp["contentSecurityPolicy"] = *s.ContentSecurityPolicy.ContentSecurityPolicy
		}
		if s.ContentSecurityPolicy.Override != nil {
			csp["override"] = *s.ContentSecurityPolicy.Override
		}
		out["contentSecurityPolicy"] = csp
	}
	if s.ContentTypeOptions != nil {
		cto := map[string]any{}
		if s.ContentTypeOptions.Override != nil {
			cto["override"] = *s.ContentTypeOptions.Override
		}
		out["contentTypeOptions"] = cto
	}
	if s.StrictTransportSecurity != nil {
		hsts := map[string]any{}
		if s.StrictTransportSecurity.AccessControlMaxAgeSec != nil {
			hsts["accessControlMaxAgeSec"] = int64(*s.StrictTransportSecurity.AccessControlMaxAgeSec)
		}
		if s.StrictTransportSecurity.Override != nil {
			hsts["override"] = *s.StrictTransportSecurity.Override
		}
		if s.StrictTransportSecurity.IncludeSubdomains != nil {
			hsts["includeSubdomains"] = *s.StrictTransportSecurity.IncludeSubdomains
		}
		if s.StrictTransportSecurity.Preload != nil {
			hsts["preload"] = *s.StrictTransportSecurity.Preload
		}
		out["strictTransportSecurity"] = hsts
	}
	return out
}

func cloudfrontServerTimingToDict(s *types.ResponseHeadersPolicyServerTimingHeadersConfig) map[string]any {
	if s == nil {
		return nil
	}
	out := map[string]any{}
	if s.Enabled != nil {
		out["enabled"] = *s.Enabled
	}
	if s.SamplingRate != nil {
		out["samplingRate"] = *s.SamplingRate
	}
	return out
}

func cloudfrontCustomHeadersToDictSlice(c *types.ResponseHeadersPolicyCustomHeadersConfig) []any {
	if c == nil || len(c.Items) == 0 {
		return []any{}
	}
	out := make([]any, 0, len(c.Items))
	for _, item := range c.Items {
		entry := map[string]any{}
		if item.Header != nil {
			entry["header"] = *item.Header
		}
		if item.Value != nil {
			entry["value"] = *item.Value
		}
		if item.Override != nil {
			entry["override"] = *item.Override
		}
		out = append(out, entry)
	}
	return out
}

func cloudfrontRemoveHeadersToList(c *types.ResponseHeadersPolicyRemoveHeadersConfig) []any {
	if c == nil || len(c.Items) == 0 {
		return []any{}
	}
	out := make([]any, 0, len(c.Items))
	for _, item := range c.Items {
		if item.Header != nil {
			out = append(out, *item.Header)
		}
	}
	return out
}

// toAnySlice converts a slice of any string-like type to []any. The ~string
// constraint keeps it resilient to SDK fields typed as named string aliases
// (e.g. enum element types) rather than plain string.
func toAnySlice[T ~string](in []T) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, string(v))
	}
	return out
}

// -- Cache policies ---------------------------------------------------------

func (a *mqlAwsCloudfrontCachePolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) cachePolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListCachePolicies(ctx, &cloudfront.ListCachePoliciesInput{
			Marker: marker,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not gather aws cloudfront cache policies")
		}
		if resp.CachePolicyList == nil {
			break
		}
		for _, item := range resp.CachePolicyList.Items {
			policy := item.CachePolicy
			if policy == nil {
				continue
			}
			args := map[string]*llx.RawData{
				"id":               llx.StringDataPtr(policy.Id),
				"type":             llx.StringData(string(item.Type)),
				"lastModifiedTime": llx.TimeDataPtr(policy.LastModifiedTime),
			}
			cfg := policy.CachePolicyConfig
			if cfg != nil {
				args["name"] = llx.StringDataPtr(cfg.Name)
				args["comment"] = llx.StringDataPtr(cfg.Comment)
				args["minTtl"] = llx.IntDataDefault(cfg.MinTTL, 0)
				args["defaultTtl"] = llx.IntDataDefault(cfg.DefaultTTL, 0)
				args["maxTtl"] = llx.IntDataDefault(cfg.MaxTTL, 0)
				args["parametersInCacheKeyAndForwardedToOrigin"] = llx.MapData(cloudfrontCacheParametersToDict(cfg.ParametersInCacheKeyAndForwardedToOrigin), mqltypes.Any)
			} else {
				args["name"] = llx.StringData("")
				args["comment"] = llx.StringData("")
				args["minTtl"] = llx.IntData(0)
				args["defaultTtl"] = llx.IntData(0)
				args["maxTtl"] = llx.IntData(0)
				args["parametersInCacheKeyAndForwardedToOrigin"] = llx.MapData(nil, mqltypes.Any)
			}

			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.cachePolicy", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.CachePolicyList.NextMarker == nil {
			break
		}
		marker = resp.CachePolicyList.NextMarker
	}
	return res, nil
}

func cloudfrontCacheParametersToDict(p *types.ParametersInCacheKeyAndForwardedToOrigin) map[string]any {
	if p == nil {
		return nil
	}
	out := map[string]any{}
	if p.EnableAcceptEncodingGzip != nil {
		out["enableAcceptEncodingGzip"] = *p.EnableAcceptEncodingGzip
	}
	if p.EnableAcceptEncodingBrotli != nil {
		out["enableAcceptEncodingBrotli"] = *p.EnableAcceptEncodingBrotli
	}
	if p.HeadersConfig != nil {
		out["headersConfig"] = cloudfrontCachePolicyHeadersToDict(p.HeadersConfig)
	}
	if p.CookiesConfig != nil {
		out["cookiesConfig"] = cloudfrontCachePolicyCookiesToDict(p.CookiesConfig)
	}
	if p.QueryStringsConfig != nil {
		out["queryStringsConfig"] = cloudfrontCachePolicyQueryStringsToDict(p.QueryStringsConfig)
	}
	return out
}

func cloudfrontCachePolicyHeadersToDict(h *types.CachePolicyHeadersConfig) map[string]any {
	out := map[string]any{
		"headerBehavior": string(h.HeaderBehavior),
	}
	if h.Headers != nil {
		out["headers"] = toAnySlice(h.Headers.Items)
	} else {
		out["headers"] = []any{}
	}
	return out
}

func cloudfrontCachePolicyCookiesToDict(c *types.CachePolicyCookiesConfig) map[string]any {
	out := map[string]any{
		"cookieBehavior": string(c.CookieBehavior),
	}
	if c.Cookies != nil {
		out["cookies"] = toAnySlice(c.Cookies.Items)
	} else {
		out["cookies"] = []any{}
	}
	return out
}

func cloudfrontCachePolicyQueryStringsToDict(q *types.CachePolicyQueryStringsConfig) map[string]any {
	out := map[string]any{
		"queryStringBehavior": string(q.QueryStringBehavior),
	}
	if q.QueryStrings != nil {
		out["queryStrings"] = toAnySlice(q.QueryStrings.Items)
	} else {
		out["queryStrings"] = []any{}
	}
	return out
}

// -- Origin request policies ------------------------------------------------

func (a *mqlAwsCloudfrontOriginRequestPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) originRequestPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListOriginRequestPolicies(ctx, &cloudfront.ListOriginRequestPoliciesInput{
			Marker: marker,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not gather aws cloudfront origin request policies")
		}
		if resp.OriginRequestPolicyList == nil {
			break
		}
		for _, item := range resp.OriginRequestPolicyList.Items {
			policy := item.OriginRequestPolicy
			if policy == nil {
				continue
			}
			args := map[string]*llx.RawData{
				"id":               llx.StringDataPtr(policy.Id),
				"type":             llx.StringData(string(item.Type)),
				"lastModifiedTime": llx.TimeDataPtr(policy.LastModifiedTime),
			}
			cfg := policy.OriginRequestPolicyConfig
			if cfg != nil {
				args["name"] = llx.StringDataPtr(cfg.Name)
				args["comment"] = llx.StringDataPtr(cfg.Comment)
				args["headersConfig"] = llx.MapData(cloudfrontOriginRequestHeadersToDict(cfg.HeadersConfig), mqltypes.Any)
				args["cookiesConfig"] = llx.MapData(cloudfrontOriginRequestCookiesToDict(cfg.CookiesConfig), mqltypes.Any)
				args["queryStringsConfig"] = llx.MapData(cloudfrontOriginRequestQueryStringsToDict(cfg.QueryStringsConfig), mqltypes.Any)
			} else {
				args["name"] = llx.StringData("")
				args["comment"] = llx.StringData("")
				args["headersConfig"] = llx.MapData(nil, mqltypes.Any)
				args["cookiesConfig"] = llx.MapData(nil, mqltypes.Any)
				args["queryStringsConfig"] = llx.MapData(nil, mqltypes.Any)
			}

			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.originRequestPolicy", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.OriginRequestPolicyList.NextMarker == nil {
			break
		}
		marker = resp.OriginRequestPolicyList.NextMarker
	}
	return res, nil
}

func cloudfrontOriginRequestHeadersToDict(h *types.OriginRequestPolicyHeadersConfig) map[string]any {
	if h == nil {
		return nil
	}
	out := map[string]any{
		"headerBehavior": string(h.HeaderBehavior),
	}
	if h.Headers != nil {
		out["headers"] = toAnySlice(h.Headers.Items)
	} else {
		out["headers"] = []any{}
	}
	return out
}

func cloudfrontOriginRequestCookiesToDict(c *types.OriginRequestPolicyCookiesConfig) map[string]any {
	if c == nil {
		return nil
	}
	out := map[string]any{
		"cookieBehavior": string(c.CookieBehavior),
	}
	if c.Cookies != nil {
		out["cookies"] = toAnySlice(c.Cookies.Items)
	} else {
		out["cookies"] = []any{}
	}
	return out
}

func cloudfrontOriginRequestQueryStringsToDict(q *types.OriginRequestPolicyQueryStringsConfig) map[string]any {
	if q == nil {
		return nil
	}
	out := map[string]any{
		"queryStringBehavior": string(q.QueryStringBehavior),
	}
	if q.QueryStrings != nil {
		out["queryStrings"] = toAnySlice(q.QueryStrings.Items)
	} else {
		out["queryStrings"] = []any{}
	}
	return out
}

// -- Continuous deployment policies -----------------------------------------

func (a *mqlAwsCloudfrontContinuousDeploymentPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) continuousDeploymentPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListContinuousDeploymentPolicies(ctx, &cloudfront.ListContinuousDeploymentPoliciesInput{
			Marker: marker,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not gather aws cloudfront continuous deployment policies")
		}
		if resp.ContinuousDeploymentPolicyList == nil {
			break
		}
		for _, item := range resp.ContinuousDeploymentPolicyList.Items {
			policy := item.ContinuousDeploymentPolicy
			if policy == nil {
				continue
			}

			args := map[string]*llx.RawData{
				"id":                          llx.StringDataPtr(policy.Id),
				"lastModifiedTime":            llx.TimeDataPtr(policy.LastModifiedTime),
				"stagingDistributionDnsNames": llx.ArrayData([]any{}, mqltypes.String),
				"enabled":                     llx.BoolData(false),
				"trafficConfig":               llx.MapData(nil, mqltypes.Any),
			}
			cfg := policy.ContinuousDeploymentPolicyConfig
			if cfg != nil {
				if cfg.Enabled != nil {
					args["enabled"] = llx.BoolData(*cfg.Enabled)
				}
				if cfg.StagingDistributionDnsNames != nil {
					args["stagingDistributionDnsNames"] = llx.ArrayData(toAnySlice(cfg.StagingDistributionDnsNames.Items), mqltypes.String)
				}
				args["trafficConfig"] = llx.MapData(cloudfrontTrafficConfigToDict(cfg.TrafficConfig), mqltypes.Any)
			}

			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.continuousDeploymentPolicy", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.ContinuousDeploymentPolicyList.NextMarker == nil {
			break
		}
		marker = resp.ContinuousDeploymentPolicyList.NextMarker
	}
	return res, nil
}

func cloudfrontTrafficConfigToDict(t *types.TrafficConfig) map[string]any {
	if t == nil {
		return nil
	}
	out := map[string]any{
		"type": string(t.Type),
	}
	if t.SingleWeightConfig != nil {
		single := map[string]any{}
		if t.SingleWeightConfig.Weight != nil {
			single["weight"] = float64(*t.SingleWeightConfig.Weight)
		}
		if t.SingleWeightConfig.SessionStickinessConfig != nil {
			stick := map[string]any{}
			if t.SingleWeightConfig.SessionStickinessConfig.IdleTTL != nil {
				stick["idleTtl"] = int64(*t.SingleWeightConfig.SessionStickinessConfig.IdleTTL)
			}
			if t.SingleWeightConfig.SessionStickinessConfig.MaximumTTL != nil {
				stick["maximumTtl"] = int64(*t.SingleWeightConfig.SessionStickinessConfig.MaximumTTL)
			}
			single["sessionStickinessConfig"] = stick
		}
		out["singleWeightConfig"] = single
	}
	if t.SingleHeaderConfig != nil {
		single := map[string]any{}
		if t.SingleHeaderConfig.Header != nil {
			single["header"] = *t.SingleHeaderConfig.Header
		}
		if t.SingleHeaderConfig.Value != nil {
			single["value"] = *t.SingleHeaderConfig.Value
		}
		out["singleHeaderConfig"] = single
	}
	return out
}
