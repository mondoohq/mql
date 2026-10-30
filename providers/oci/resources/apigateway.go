// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/apigateway"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciApigateway) id() (string, error) {
	return "oci.apigateway", nil
}

// Gateways

func (o *mqlOciApigateway) gateways() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci api gateways with region %s", region)

			svc, err := conn.ApiGatewayGatewayClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]apigateway.GatewaySummary, *string, error) {
				response, err := svc.ListGateways(ctx, apigateway.ListGatewaysRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				g := items[i]

				var created, updated *time.Time
				if g.TimeCreated != nil {
					created = &g.TimeCreated.Time
				}
				if g.TimeUpdated != nil {
					updated = &g.TimeUpdated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.apigateway.gateway", stringValue(g.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(g.Id),
					"name":         llx.StringDataPtr(g.DisplayName),
					"endpointType": llx.StringData(string(g.EndpointType)),
					"ipMode":       llx.StringData(string(g.IpMode)),
					"hostname":     llx.StringDataPtr(g.Hostname),
					"state":        llx.StringData(string(g.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"timeUpdated":  llx.TimeDataPtr(updated),
					"freeformTags": llx.MapData(strMapToAny(g.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(g.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(g.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlGw := mqlInstance.(*mqlOciApigatewayGateway)
				mqlGw.cacheRegion = region
				mqlGw.cacheSubnetID = stringValue(g.SubnetId)
				mqlGw.cacheCertificateID = stringValue(g.CertificateId)
				mqlGw.cacheNsgIDs = append([]string(nil), g.NetworkSecurityGroupIds...)
				res = append(res, mqlGw)
			}

			return res, nil
		})
}

type mqlOciApigatewayGatewayInternal struct {
	ociCompartmentRef
	cacheRegion        string
	cacheSubnetID      string
	cacheCertificateID string
	cacheNsgIDs        []string

	// details fetched lazily from GetGateway (ip addresses, CA bundles,
	// response cache) — not in the list summary.
	details ociOnce
}

func (o *mqlOciApigatewayGateway) id() (string, error) {
	return "oci.apigateway.gateway/" + o.Id.Data, nil
}

func (o *mqlOciApigatewayGateway) subnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheSubnetID == "" {
		o.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciNetworkSubnet), nil
}

func (o *mqlOciApigatewayGateway) networkSecurityGroups() ([]any, error) {
	res := make([]any, 0, len(o.cacheNsgIDs))
	for _, nsgId := range o.cacheNsgIDs {
		if nsgId == "" {
			continue
		}
		nsg, err := NewResource(o.MqlRuntime, "oci.network.networkSecurityGroup", map[string]*llx.RawData{
			"id": llx.StringData(nsgId),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, nsg)
	}
	return res, nil
}

func (o *mqlOciApigatewayGateway) certificate() (*mqlOciApigatewayCertificate, error) {
	if o.cacheCertificateID == "" {
		o.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.apigateway.certificate", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheCertificateID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciApigatewayCertificate), nil
}

// fetchDetails calls GetGateway to populate fields that the list summary
// does not return: ipAddresses, caBundles, responseCacheDetails. Safe for
// concurrent callers.
func (o *mqlOciApigatewayGateway) fetchDetails() error {
	return o.details.do(func() error {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.ApiGatewayGatewayClient(o.cacheRegion)
		if err != nil {
			return err
		}
		resp, err := svc.GetGateway(context.Background(), apigateway.GetGatewayRequest{
			GatewayId: new(o.Id.Data),
		})
		if err != nil {
			return err
		}

		ips := make([]any, 0, len(resp.IpAddresses))
		for i := range resp.IpAddresses {
			ips = append(ips, stringValue(resp.IpAddresses[i].IpAddress))
		}
		o.IpAddresses = plugin.TValue[[]any]{Data: ips, State: plugin.StateIsSet}

		caBundles := make([]any, 0, len(resp.CaBundles))
		for i := range resp.CaBundles {
			switch cb := resp.CaBundles[i].(type) {
			case apigateway.CertificatesCaBundle:
				caBundles = append(caBundles, stringValue(cb.CaBundleId))
			case apigateway.CertificatesCertificateAuthority:
				caBundles = append(caBundles, stringValue(cb.CertificateAuthorityId))
			}
		}
		o.CaBundleIds = plugin.TValue[[]any]{Data: caBundles, State: plugin.StateIsSet}

		// response cache presence only — the concrete config may hold a
		// Redis/external endpoint we don't want to expose carte-blanche.
		hasCache := false
		if resp.ResponseCacheDetails != nil {
			// NoCache is modeled as a concrete type; anything else indicates
			// a cache is configured.
			if _, isNone := resp.ResponseCacheDetails.(apigateway.NoCache); !isNone {
				hasCache = true
			}
		}
		o.HasResponseCache = plugin.TValue[bool]{Data: hasCache, State: plugin.StateIsSet}
		return nil
	})
}

func (o *mqlOciApigatewayGateway) ipAddresses() ([]any, error) {
	if err := o.fetchDetails(); err != nil {
		return nil, err
	}
	return o.IpAddresses.Data, nil
}

func (o *mqlOciApigatewayGateway) caBundleIds() ([]any, error) {
	if err := o.fetchDetails(); err != nil {
		return nil, err
	}
	return o.CaBundleIds.Data, nil
}

func (o *mqlOciApigatewayGateway) hasResponseCache() (bool, error) {
	if err := o.fetchDetails(); err != nil {
		return false, err
	}
	return o.HasResponseCache.Data, nil
}

// Deployments

func (o *mqlOciApigateway) deployments() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci api gateway deployments with region %s", region)

			svc, err := conn.ApiGatewayDeploymentClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]apigateway.DeploymentSummary, *string, error) {
				response, err := svc.ListDeployments(ctx, apigateway.ListDeploymentsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				d := items[i]

				if conn.Filters.IsFilteredOutByTags(d.FreeformTags, d.DefinedTags) {
					continue
				}

				var created, updated *time.Time
				if d.TimeCreated != nil {
					created = &d.TimeCreated.Time
				}
				if d.TimeUpdated != nil {
					updated = &d.TimeUpdated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.apigateway.deployment", stringValue(d.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(d.Id),
					"name":         llx.StringDataPtr(d.DisplayName),
					"pathPrefix":   llx.StringDataPtr(d.PathPrefix),
					"endpoint":     llx.StringDataPtr(d.Endpoint),
					"state":        llx.StringData(string(d.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"timeUpdated":  llx.TimeDataPtr(updated),
					"freeformTags": llx.MapData(strMapToAny(d.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(d.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(d.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlDep := mqlInstance.(*mqlOciApigatewayDeployment)
				mqlDep.cacheRegion = region
				mqlDep.cacheGatewayID = stringValue(d.GatewayId)
				res = append(res, mqlDep)
			}

			return res, nil
		})
}

type mqlOciApigatewayDeploymentInternal struct {
	ociCompartmentRef
	cacheRegion    string
	cacheGatewayID string

	// the deployment spec backs the request-policy-derived fields.
	spec ociRetryLazy[*apigateway.ApiSpecification]
}

func (o *mqlOciApigatewayDeployment) id() (string, error) {
	return "oci.apigateway.deployment/" + o.Id.Data, nil
}

// initOciApigatewayDeployment resolves a single deployment from the scan
// asset's PlatformId when policies reference `oci.apigateway.deployment` on a
// discovered oci-apigateway-deployment asset. Explicit id takes precedence.
func initOciApigatewayDeployment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		conn := runtime.Connection.(*connection.OciConnection)
		if conn.Conf == nil || conn.Conf.PlatformId == "" {
			return args, nil, nil
		}
		parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId)
		if !ok || parsed.service != "apigateway" || parsed.objectType != "deployment" {
			return args, nil, nil
		}
		idVal = parsed.id
	}

	obj, err := CreateResource(runtime, "oci.apigateway", nil)
	if err != nil {
		return nil, nil, err
	}
	apigw := obj.(*mqlOciApigateway)

	deps := apigw.GetDeployments()
	if deps.Error != nil {
		return nil, nil, deps.Error
	}

	for _, raw := range deps.Data {
		d := raw.(*mqlOciApigatewayDeployment)
		if d.Id.Data == idVal {
			return args, d, nil
		}
	}

	return nil, nil, errors.New("oci.apigateway.deployment not found: " + idVal)
}

func (o *mqlOciApigatewayDeployment) gateway() (*mqlOciApigatewayGateway, error) {
	if o.cacheGatewayID == "" {
		o.Gateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.apigateway.gateway", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheGatewayID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciApigatewayGateway), nil
}

// fetchSpec calls GetDeployment once to retrieve the full ApiSpecification
// (routes, request policies, mTLS, CORS, rate limits). Subsequent callers
// use the cached spec. The request is intentionally serialized behind a
// mutex to avoid N concurrent GetDeployment calls on first access.
func (o *mqlOciApigatewayDeployment) getSpec() (*apigateway.ApiSpecification, error) {
	return o.spec.get(func() (*apigateway.ApiSpecification, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.ApiGatewayDeploymentClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetDeployment(context.Background(), apigateway.GetDeploymentRequest{
			DeploymentId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return resp.Specification, nil
	})
}

func (o *mqlOciApigatewayDeployment) requestPolicies() (*apigateway.ApiSpecificationRequestPolicies, error) {
	spec, err := o.getSpec()
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, nil
	}
	return spec.RequestPolicies, nil
}

// flattenAuthenticationType maps the SDK's authentication-policy union type
// to the string enum exposed on the MQL deployment resource. Exported as a
// package-level helper so it can be unit tested without a runtime.
func flattenAuthenticationType(rp *apigateway.ApiSpecificationRequestPolicies) string {
	if rp == nil || rp.Authentication == nil {
		return "NONE"
	}
	switch rp.Authentication.(type) {
	case apigateway.JwtAuthenticationPolicy:
		return "JWT_AUTHENTICATION"
	case apigateway.TokenAuthenticationPolicy:
		return "TOKEN_AUTHENTICATION"
	case apigateway.CustomAuthenticationPolicy:
		return "CUSTOM_AUTHENTICATION"
	}
	return "UNKNOWN"
}

// flattenIsAnonymousAccessAllowed reports whether unauthenticated requests
// reach the backend. A deployment with no authentication policy at all
// enforces nothing, so every request is anonymous - reporting false there
// would clear the most exposed deployment in the tenancy.
func flattenIsAnonymousAccessAllowed(rp *apigateway.ApiSpecificationRequestPolicies) bool {
	if rp == nil || rp.Authentication == nil {
		return true
	}
	if v := rp.Authentication.GetIsAnonymousAccessAllowed(); v != nil {
		return *v
	}
	return false
}

// flattenJwtAudiences returns the JWT audiences for a deployment whose
// authentication policy is JWT, or an empty slice otherwise.
func flattenJwtAudiences(rp *apigateway.ApiSpecificationRequestPolicies) []any {
	if rp == nil || rp.Authentication == nil {
		return []any{}
	}
	jwt, ok := rp.Authentication.(apigateway.JwtAuthenticationPolicy)
	if !ok {
		return []any{}
	}
	return convert.SliceAnyToInterface(jwt.Audiences)
}

// flattenJwtIssuers returns the JWT issuers for a deployment whose
// authentication policy is JWT, or an empty slice otherwise.
func flattenJwtIssuers(rp *apigateway.ApiSpecificationRequestPolicies) []any {
	if rp == nil || rp.Authentication == nil {
		return []any{}
	}
	jwt, ok := rp.Authentication.(apigateway.JwtAuthenticationPolicy)
	if !ok {
		return []any{}
	}
	return convert.SliceAnyToInterface(jwt.Issuers)
}

// flattenMutualTls returns the mTLS isVerifiedCertificateRequired flag and
// the allowed-SAN list for the request policies. nil-safe.
func flattenMutualTls(rp *apigateway.ApiSpecificationRequestPolicies) (bool, []any) {
	if rp == nil || rp.MutualTls == nil {
		return false, []any{}
	}
	isRequired := false
	if rp.MutualTls.IsVerifiedCertificateRequired != nil {
		isRequired = *rp.MutualTls.IsVerifiedCertificateRequired
	}
	return isRequired, convert.SliceAnyToInterface(rp.MutualTls.AllowedSans)
}

// flattenCors returns the CORS allow-credentials flag and allowed-origin
// list for the request policies. nil-safe.
func flattenCors(rp *apigateway.ApiSpecificationRequestPolicies) (bool, []any) {
	if rp == nil || rp.Cors == nil {
		return false, []any{}
	}
	allowCreds := false
	if rp.Cors.IsAllowCredentialsEnabled != nil {
		allowCreds = *rp.Cors.IsAllowCredentialsEnabled
	}
	return allowCreds, convert.SliceAnyToInterface(rp.Cors.AllowedOrigins)
}

// flattenRateLimiting returns the configured requests-per-second and rate
// key. nil-safe; missing config yields (0, "").
func flattenRateLimiting(rp *apigateway.ApiSpecificationRequestPolicies) (int64, string) {
	if rp == nil || rp.RateLimiting == nil {
		return 0, ""
	}
	var rate int64
	if rp.RateLimiting.RateInRequestsPerSecond != nil {
		rate = int64(*rp.RateLimiting.RateInRequestsPerSecond)
	}
	return rate, string(rp.RateLimiting.RateKey)
}

// hasDynamicAuthentication reports whether request-level dynamic
// authentication is configured on the deployment.
func hasDynamicAuthentication(rp *apigateway.ApiSpecificationRequestPolicies) bool {
	if rp == nil {
		return false
	}
	return rp.DynamicAuthentication != nil
}

func (o *mqlOciApigatewayDeployment) authenticationType() (string, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return "", err
	}
	return flattenAuthenticationType(rp), nil
}

func (o *mqlOciApigatewayDeployment) isAnonymousAccessAllowed() (bool, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return false, err
	}
	return flattenIsAnonymousAccessAllowed(rp), nil
}

func (o *mqlOciApigatewayDeployment) jwtAudiences() ([]any, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return nil, err
	}
	return flattenJwtAudiences(rp), nil
}

func (o *mqlOciApigatewayDeployment) jwtIssuers() ([]any, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return nil, err
	}
	return flattenJwtIssuers(rp), nil
}

func (o *mqlOciApigatewayDeployment) mtlsIsVerifiedCertificateRequired() (bool, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return false, err
	}
	required, _ := flattenMutualTls(rp)
	return required, nil
}

func (o *mqlOciApigatewayDeployment) mtlsAllowedSans() ([]any, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return nil, err
	}
	_, sans := flattenMutualTls(rp)
	return sans, nil
}

func (o *mqlOciApigatewayDeployment) corsAllowedOrigins() ([]any, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return nil, err
	}
	_, origins := flattenCors(rp)
	return origins, nil
}

func (o *mqlOciApigatewayDeployment) corsAllowCredentials() (bool, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return false, err
	}
	allow, _ := flattenCors(rp)
	return allow, nil
}

func (o *mqlOciApigatewayDeployment) rateLimitPerSecond() (int64, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return 0, err
	}
	rate, _ := flattenRateLimiting(rp)
	return rate, nil
}

func (o *mqlOciApigatewayDeployment) rateLimitKey() (string, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return "", err
	}
	_, key := flattenRateLimiting(rp)
	return key, nil
}

func (o *mqlOciApigatewayDeployment) hasDynamicAuthentication() (bool, error) {
	rp, err := o.requestPolicies()
	if err != nil {
		return false, err
	}
	return hasDynamicAuthentication(rp), nil
}

// API gateway certificates (apigateway service, distinct from certificatesmanagement)

func (o *mqlOciApigateway) certificates() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci api gateway certificates with region %s", region)

			svc, err := conn.ApiGatewayClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]apigateway.CertificateSummary, *string, error) {
				response, err := svc.ListCertificates(ctx, apigateway.ListCertificatesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				c := items[i]

				var created, updated, notValidAfter *time.Time
				if c.TimeCreated != nil {
					created = &c.TimeCreated.Time
				}
				if c.TimeUpdated != nil {
					updated = &c.TimeUpdated.Time
				}
				if c.TimeNotValidAfter != nil {
					notValidAfter = &c.TimeNotValidAfter.Time
				}

				subjectNames := convert.SliceAnyToInterface(c.SubjectNames)

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.apigateway.certificate", stringValue(c.CompartmentId), map[string]*llx.RawData{
					"id":                llx.StringDataPtr(c.Id),
					"name":              llx.StringDataPtr(c.DisplayName),
					"subjectNames":      llx.ArrayData(subjectNames, types.String),
					"timeNotValidAfter": llx.TimeDataPtr(notValidAfter),
					"state":             llx.StringData(string(c.LifecycleState)),
					"created":           llx.TimeDataPtr(created),
					"timeUpdated":       llx.TimeDataPtr(updated),
					"freeformTags":      llx.MapData(strMapToAny(c.FreeformTags), types.String),
					"definedTags":       llx.MapData(definedTagsToAny(c.DefinedTags), types.Any),
					"systemTags":        llx.MapData(definedTagsToAny(c.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlInstance)
			}
			return res, nil
		})
}

func initOciApigatewayCertificate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.apigateway.certificate")
	}

	obj, err := CreateResource(runtime, "oci.apigateway", nil)
	if err != nil {
		return nil, nil, err
	}
	apigw := obj.(*mqlOciApigateway)
	rawCerts := apigw.GetCertificates()
	if rawCerts.Error != nil {
		return nil, nil, rawCerts.Error
	}
	for _, raw := range rawCerts.Data {
		c := raw.(*mqlOciApigatewayCertificate)
		if c.Id.Data == idVal {
			return args, c, nil
		}
	}
	return nil, nil, errors.New("oci.apigateway.certificate not found: " + idVal)
}

func (o *mqlOciApigatewayCertificate) id() (string, error) {
	return "oci.apigateway.certificate/" + o.Id.Data, nil
}

type mqlOciApigatewayCertificateInternal struct {
	ociCompartmentRef
}
