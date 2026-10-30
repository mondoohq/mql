// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciLoadBalancer) id() (string, error) {
	return "oci.loadBalancer", nil
}

func (o *mqlOciLoadBalancer) loadBalancers() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Load balancers belong to the compartment of the application they front, and
	// ListLoadBalancers has no subtree flag. Scanning only the tenancy root meant
	// the exposure surface an internet-facing balancer represents, along with its
	// listener TLS settings and backend sets, never appeared in the inventory at
	// all.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci load balancer with region %s", region)

			svc, err := conn.LoadBalancerClient(region)
			if err != nil {
				return nil, err
			}

			lbs, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]loadbalancer.LoadBalancer, *string, error) {
				response, err := svc.ListLoadBalancers(ctx, loadbalancer.ListLoadBalancersRequest{
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

			var res []any
			for i := range lbs {
				lb := lbs[i]

				if conn.Filters.IsFilteredOutByTags(lb.FreeformTags, lb.DefinedTags) {
					continue
				}

				var created *time.Time
				if lb.TimeCreated != nil {
					created = &lb.TimeCreated.Time
				}

				addresses := make([]any, 0, len(lb.IpAddresses))
				for _, ip := range lb.IpAddresses {
					mqlAddress, err := CreateResource(o.MqlRuntime, "oci.loadBalancer.ipAddress", map[string]*llx.RawData{
						"__id":      llx.StringData(stringValue(lb.Id) + "/ipAddress/" + stringValue(ip.IpAddress)),
						"ipAddress": llx.StringDataPtr(ip.IpAddress),
						// Faithful to the SDK: null when the balancer does not
						// report the flag. exposure() reads these addresses to
						// decide internet reachability and takes a null as
						// public, since a balancer that is not private answers
						// on a public address.
						"isPublic": llx.BoolDataPtr(ip.IsPublic),
					})
					if err != nil {
						return nil, err
					}
					mqlAddr := mqlAddress.(*mqlOciLoadBalancerIpAddress)
					if ip.ReservedIp != nil {
						mqlAddr.cacheReservedIpID = stringValue(ip.ReservedIp.Id)
					}
					addresses = append(addresses, mqlAddr)
				}

				ipAddresses := make([]any, 0, len(lb.IpAddresses))
				for _, ip := range lb.IpAddresses {
					// isPublic is optional on the SDK model. This deprecated
					// dict has no way to carry the distinction the address
					// resource keeps, so the fallback is resolved eagerly here:
					// a missing flag on a non-private load balancer means
					// public, and falling back to false would describe a
					// genuinely internet-facing balancer as internal.
					entry := map[string]any{
						"ipAddress": stringValue(ip.IpAddress),
						"isPublic":  ociIpIsPublic(ip.IsPublic, boolValue(lb.IsPrivate)),
					}
					if ip.ReservedIp != nil {
						entry["reservedIpId"] = stringValue(ip.ReservedIp.Id)
					}
					ipAddresses = append(ipAddresses, entry)
				}

				// ShapeDetails is populated only on a flexible shape. Leaving the
				// bandwidth fields null on a fixed shape keeps "no configured
				// bandwidth" distinct from a configured 0 Mbps.
				var minBandwidth, maxBandwidth *int
				if lb.ShapeDetails != nil {
					minBandwidth = lb.ShapeDetails.MinimumBandwidthInMbps
					maxBandwidth = lb.ShapeDetails.MaximumBandwidthInMbps
				}

				hostnames := make(map[string]any, len(lb.Hostnames))
				for name, h := range lb.Hostnames {
					hostnames[name] = stringValue(h.Hostname)
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.loadBalancer.loadBalancer", stringValue(lb.CompartmentId), map[string]*llx.RawData{
					"id":                        llx.StringDataPtr(lb.Id),
					"name":                      llx.StringDataPtr(lb.DisplayName),
					"shape":                     llx.StringDataPtr(lb.ShapeName),
					"minimumBandwidthInMbps":    llx.IntDataPtr(minBandwidth),
					"maximumBandwidthInMbps":    llx.IntDataPtr(maxBandwidth),
					"isPrivate":                 llx.BoolDataPtr(lb.IsPrivate),
					"ipMode":                    llx.StringData(string(lb.IpMode)),
					"isRequestIdEnabled":        llx.BoolDataPtr(lb.IsRequestIdEnabled),
					"requestIdHeader":           llx.StringDataPtr(lb.RequestIdHeader),
					"hostnames":                 llx.MapData(hostnames, types.String),
					"ipAddresses":               llx.ArrayData(ipAddresses, types.Dict),
					"addresses":                 llx.ArrayData(addresses, types.Resource("oci.loadBalancer.ipAddress")),
					"isDeleteProtectionEnabled": llx.BoolDataPtr(lb.IsDeleteProtectionEnabled),
					"securityAttributes":        llx.MapData(definedTagsToAny(lb.SecurityAttributes), types.Dict),
					"state":                     llx.StringData(string(lb.LifecycleState)),
					"created":                   llx.TimeDataPtr(created),
					"freeformTags":              llx.MapData(strMapToAny(lb.FreeformTags), types.String),
					"definedTags":               llx.MapData(definedTagsToAny(lb.DefinedTags), types.Any),
					"systemTags":                llx.MapData(definedTagsToAny(lb.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlLb := mqlInstance.(*mqlOciLoadBalancerLoadBalancer)
				mqlLb.cacheNsgIDs = convert.SliceAnyToInterface(lb.NetworkSecurityGroupIds)
				mqlLb.cacheListeners = lb.Listeners
				mqlLb.cacheBackendSets = lb.BackendSets
				mqlLb.cacheRegion = region
				mqlLb.cacheSubnetIDs = lb.SubnetIds
				mqlLb.cacheCipherSuites = lb.SslCipherSuites
				mqlLb.cacheCertificates = lb.Certificates
				mqlLb.cacheRuleSets = lb.RuleSets
				res = append(res, mqlLb)
			}

			return res, nil
		})
}

type mqlOciLoadBalancerLoadBalancerInternal struct {
	ociCompartmentRef
	cacheNsgIDs       []any
	cacheListeners    map[string]loadbalancer.Listener
	cacheBackendSets  map[string]loadbalancer.BackendSet
	cacheRegion       string
	cacheSubnetIDs    []string
	cacheCipherSuites map[string]loadbalancer.SslCipherSuite
	cacheCertificates map[string]loadbalancer.Certificate
	cacheRuleSets     map[string]loadbalancer.RuleSet
}

func initOciLoadBalancerLoadBalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
		if !ok || parsed.service != "loadbalancer" || parsed.objectType != "loadBalancer" {
			return args, nil, nil
		}
		idVal = parsed.id
	}

	obj, err := CreateResource(runtime, "oci.loadBalancer", nil)
	if err != nil {
		return nil, nil, err
	}
	lb := obj.(*mqlOciLoadBalancer)

	rawLBs := lb.GetLoadBalancers()
	if rawLBs.Error != nil {
		return nil, nil, rawLBs.Error
	}

	for _, raw := range rawLBs.Data {
		l := raw.(*mqlOciLoadBalancerLoadBalancer)
		if l.Id.Data == idVal {
			return args, l, nil
		}
	}

	return nil, nil, errors.New("oci.loadBalancer.loadBalancer not found: " + idVal)
}

func (o *mqlOciLoadBalancerLoadBalancer) id() (string, error) {
	return "oci.loadBalancer.loadBalancer/" + o.Id.Data, nil
}

// lbSslFields is the flattened form of a loadbalancer.SslConfiguration, shared
// by listeners and backend sets because OCI models both with the same struct.
type lbSslFields struct {
	protocols             []any
	cipherSuiteName       string
	verifyPeerCertificate bool
	hasSessionResumption  bool
	verifyDepth           *int
	serverOrderPreference string
	certificateName       string
	certificateIDs        []any
	trustedCaIDs          []any
}

// lbSslFieldsFrom flattens an SSL configuration. A nil configuration means the
// listener or backend set terminates no TLS at all, which is reported as empty
// strings and false rather than as null: a null would satisfy an assertion that
// peer verification is enabled, and "not configured" must fail that assertion,
// not pass it.
func lbSslFieldsFrom(ssl *loadbalancer.SslConfiguration) lbSslFields {
	out := lbSslFields{}
	if ssl == nil {
		return out
	}
	for _, p := range ssl.Protocols {
		out.protocols = append(out.protocols, p)
	}
	out.cipherSuiteName = stringValue(ssl.CipherSuiteName)
	out.verifyPeerCertificate = boolValue(ssl.VerifyPeerCertificate)
	out.hasSessionResumption = boolValue(ssl.HasSessionResumption)
	out.verifyDepth = ssl.VerifyDepth
	out.serverOrderPreference = string(ssl.ServerOrderPreference)
	out.certificateName = stringValue(ssl.CertificateName)
	out.certificateIDs = convert.SliceAnyToInterface(ssl.CertificateIds)
	out.trustedCaIDs = convert.SliceAnyToInterface(ssl.TrustedCertificateAuthorityIds)
	return out
}

// lbCookieFields is the flattened form of the load balancer's own session
// cookie configuration.
type lbCookieFields struct {
	name            string
	disableFallback bool
	domain          string
	path            string
	maxAgeInSeconds *int
	isSecure        bool
	isHttpOnly      bool
}

// lbCookieFieldsFrom flattens the load balancer cookie configuration. A nil
// configuration means this form of session persistence is off, so isSecure and
// isHttpOnly report false: there is no cookie, and a null would let a check
// requiring the Secure attribute pass.
func lbCookieFieldsFrom(c *loadbalancer.LbCookieSessionPersistenceConfigurationDetails) lbCookieFields {
	out := lbCookieFields{}
	if c == nil {
		return out
	}
	out.name = stringValue(c.CookieName)
	out.disableFallback = boolValue(c.DisableFallback)
	out.domain = stringValue(c.Domain)
	out.path = stringValue(c.Path)
	out.maxAgeInSeconds = c.MaxAgeInSeconds
	out.isSecure = boolValue(c.IsSecure)
	out.isHttpOnly = boolValue(c.IsHttpOnly)
	return out
}

func (o *mqlOciLoadBalancerLoadBalancer) listeners() ([]any, error) {
	res := []any{}
	for name, listener := range o.cacheListeners {
		ssl := lbSslFieldsFrom(listener.SslConfiguration)

		// A listener that leaves the connection defaults alone carries no
		// ConnectionConfiguration at all, so both fields stay null rather than
		// reporting a zero timeout the load balancer does not enforce.
		var idleTimeout *int64
		var proxyProtocolVersion *int
		if listener.ConnectionConfiguration != nil {
			idleTimeout = listener.ConnectionConfiguration.IdleTimeout
			proxyProtocolVersion = listener.ConnectionConfiguration.BackendTcpProxyProtocolVersion
		}

		lbId := o.Id.Data
		listenerId := lbId + "/listener/" + name
		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.loadBalancer.listener", map[string]*llx.RawData{
			"__id":                  llx.StringData(listenerId),
			"name":                  llx.StringData(name),
			"port":                  llx.IntDataPtr(listener.Port),
			"protocol":              llx.StringDataPtr(listener.Protocol),
			"defaultBackendSetName": llx.StringDataPtr(listener.DefaultBackendSetName),
			"sslCipherSuiteName":    llx.StringData(ssl.cipherSuiteName),
			"certificateName":       llx.StringData(ssl.certificateName),
			"sslProtocols":          llx.ArrayData(ssl.protocols, types.String),

			"sslVerifyPeerCertificate": llx.BoolData(ssl.verifyPeerCertificate),
			"sslVerifyDepth":           llx.IntDataPtr(ssl.verifyDepth),
			"sslServerOrderPreference": llx.StringData(ssl.serverOrderPreference),
			"hasSessionResumption":     llx.BoolData(ssl.hasSessionResumption),

			"idleTimeoutInSeconds":           llx.IntDataPtr(idleTimeout),
			"backendTcpProxyProtocolVersion": llx.IntDataPtr(proxyProtocolVersion),
			"hostnameNames":                  llx.ArrayData(convert.SliceAnyToInterface(listener.HostnameNames), types.String),
			"pathRouteSetName":               llx.StringDataPtr(listener.PathRouteSetName),
			"routingPolicyName":              llx.StringDataPtr(listener.RoutingPolicyName),
		})
		if err != nil {
			return nil, err
		}
		mqlListener := mqlInstance.(*mqlOciLoadBalancerListener)
		mqlListener.cacheCertificateIDs = ssl.certificateIDs
		mqlListener.cacheTrustedCaIDs = ssl.trustedCaIDs
		// The named sibling collections are already in hand on the parent, so
		// the typed references below are in-memory lookups rather than calls.
		mqlListener.cacheLbId = lbId
		mqlListener.cacheCipherSuiteName = ssl.cipherSuiteName
		mqlListener.cacheCertBundleName = ssl.certificateName
		mqlListener.cacheRuleSetNames = listener.RuleSetNames
		mqlListener.cacheLbCipherSuites = o.cacheCipherSuites
		mqlListener.cacheLbCertificates = o.cacheCertificates
		mqlListener.cacheLbRuleSets = o.cacheRuleSets
		res = append(res, mqlInstance)
	}
	return res, nil
}

type mqlOciLoadBalancerListenerInternal struct {
	cacheCertificateIDs []any
	cacheTrustedCaIDs   []any

	cacheLbId            string
	cacheCipherSuiteName string
	cacheCertBundleName  string
	cacheRuleSetNames    []string
	cacheLbCipherSuites  map[string]loadbalancer.SslCipherSuite
	cacheLbCertificates  map[string]loadbalancer.Certificate
	cacheLbRuleSets      map[string]loadbalancer.RuleSet
}

// sslCipherSuite resolves the named cipher suite against the ones defined on
// the parent load balancer. Null when the listener terminates no TLS, and when
// it names an OCI-predefined suite, which is not part of the load balancer's
// own collection.
func (o *mqlOciLoadBalancerListener) sslCipherSuite() (*mqlOciLoadBalancerSslCipherSuite, error) {
	return resolveLbCipherSuite(o.MqlRuntime, o.cacheLbId, o.cacheCipherSuiteName, o.cacheLbCipherSuites, &o.SslCipherSuite)
}

// certificateBundle resolves the inline bundle the listener serves. Null when
// it uses OCI Certificates service certificates instead.
func (o *mqlOciLoadBalancerListener) certificateBundle() (*mqlOciLoadBalancerCertificateBundle, error) {
	return resolveLbCertificateBundle(o.MqlRuntime, o.cacheLbId, o.cacheCertBundleName, o.cacheLbCertificates, &o.CertificateBundle)
}

// ruleSets resolves the rule sets attached to the listener by name.
func (o *mqlOciLoadBalancerListener) ruleSets() ([]any, error) {
	res := []any{}
	for _, name := range o.cacheRuleSetNames {
		rs, ok := o.cacheLbRuleSets[name]
		if !ok {
			// A listener naming a rule set the load balancer does not define
			// is a configuration the API allows; skip rather than fail.
			continue
		}
		mqlRs, err := newMqlLbRuleSet(o.MqlRuntime, o.cacheLbId, name, rs)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRs)
	}
	return res, nil
}

func (o *mqlOciLoadBalancerListener) certificates() ([]any, error) {
	return resolveOciCertificates(o.MqlRuntime, o.cacheCertificateIDs)
}

func (o *mqlOciLoadBalancerListener) trustedCertificateAuthorities() ([]any, error) {
	return resolveOciCertRefsByType(o.MqlRuntime, o.cacheTrustedCaIDs, "certificateauthority", "oci.certificates.certificateAuthority")
}

func (o *mqlOciLoadBalancerListener) trustedCaBundles() ([]any, error) {
	return resolveOciCertRefsByType(o.MqlRuntime, o.cacheTrustedCaIDs, "cabundle", "oci.certificates.caBundle")
}

func (o *mqlOciLoadBalancerLoadBalancer) backendSets() ([]any, error) {
	res := []any{}
	for name, bs := range o.cacheBackendSets {
		healthChecker, err := convert.JsonToDict(bs.HealthChecker)
		if err != nil {
			return nil, err
		}

		// A backend set with no SslConfiguration talks to its backends in the
		// clear. The booleans stay false rather than null so that an assertion
		// requiring verification fails on such a set instead of passing on a
		// null, which MQL reads as satisfied.
		ssl := lbSslFieldsFrom(bs.SslConfiguration)

		var sessionCookieName string
		var sessionDisableFallback bool
		if bs.SessionPersistenceConfiguration != nil {
			sessionCookieName = stringValue(bs.SessionPersistenceConfiguration.CookieName)
			sessionDisableFallback = boolValue(bs.SessionPersistenceConfiguration.DisableFallback)
		}

		cookie := lbCookieFieldsFrom(bs.LbCookieSessionPersistenceConfiguration)

		lbId := o.Id.Data
		bsId := lbId + "/backendSet/" + name
		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.loadBalancer.backendSet", map[string]*llx.RawData{
			"__id":                  llx.StringData(bsId),
			"name":                  llx.StringData(name),
			"policy":                llx.StringDataPtr(bs.Policy),
			"healthChecker":         llx.DictData(healthChecker),
			"backendCount":          llx.IntData(int64(len(bs.Backends))),
			"backendMaxConnections": llx.IntDataPtr(bs.BackendMaxConnections),
			"sslProtocols":          llx.ArrayData(ssl.protocols, types.String),

			"sslVerifyPeerCertificate": llx.BoolData(ssl.verifyPeerCertificate),
			"sslVerifyDepth":           llx.IntDataPtr(ssl.verifyDepth),

			"sessionPersistenceCookieName":      llx.StringData(sessionCookieName),
			"sessionPersistenceDisableFallback": llx.BoolData(sessionDisableFallback),
			"lbCookieName":                      llx.StringData(cookie.name),
			"lbCookieDisableFallback":           llx.BoolData(cookie.disableFallback),
			"lbCookieDomain":                    llx.StringData(cookie.domain),
			"lbCookiePath":                      llx.StringData(cookie.path),
			"lbCookieMaxAgeInSeconds":           llx.IntDataPtr(cookie.maxAgeInSeconds),
			"lbCookieIsSecure":                  llx.BoolData(cookie.isSecure),
			"lbCookieIsHttpOnly":                llx.BoolData(cookie.isHttpOnly),
		})
		if err != nil {
			return nil, err
		}
		mqlBs := mqlInstance.(*mqlOciLoadBalancerBackendSet)
		mqlBs.cacheBackends = bs.Backends
		mqlBs.cacheCertificateIDs = ssl.certificateIDs
		mqlBs.cacheTrustedCaIDs = ssl.trustedCaIDs
		mqlBs.cacheLbId = o.Id.Data
		mqlBs.cacheCipherSuiteName = ssl.cipherSuiteName
		mqlBs.cacheCertBundleName = ssl.certificateName
		mqlBs.cacheLbCipherSuites = o.cacheCipherSuites
		mqlBs.cacheLbCertificates = o.cacheCertificates
		mqlBs.cacheHealthChecker = bs.HealthChecker
		res = append(res, mqlBs)
	}
	return res, nil
}

type mqlOciLoadBalancerBackendSetInternal struct {
	cacheBackends       []loadbalancer.Backend
	cacheCertificateIDs []any
	cacheTrustedCaIDs   []any

	cacheLbId            string
	cacheCipherSuiteName string
	cacheCertBundleName  string
	cacheLbCipherSuites  map[string]loadbalancer.SslCipherSuite
	cacheLbCertificates  map[string]loadbalancer.Certificate

	cacheHealthChecker *loadbalancer.HealthChecker
}

// healthCheck builds the probe that decides which backends stay in rotation.
//
// A backend set with no health checker reports null rather than a probe whose
// every field is empty: nothing removes a failed backend from rotation, which
// is a different fact from a probe configured to accept anything.
func (o *mqlOciLoadBalancerBackendSet) healthCheck() (*mqlOciLoadBalancerHealthChecker, error) {
	hc := o.cacheHealthChecker
	if hc == nil {
		o.HealthCheck.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.loadBalancer.healthChecker", map[string]*llx.RawData{
		"__id":              llx.StringData(o.__id + "/healthChecker"),
		"protocol":          llx.StringDataPtr(hc.Protocol),
		"port":              llx.IntDataPtr(hc.Port),
		"returnCode":        llx.IntDataPtr(hc.ReturnCode),
		"responseBodyRegex": llx.StringDataPtr(hc.ResponseBodyRegex),
		"urlPath":           llx.StringDataPtr(hc.UrlPath),
		"retries":           llx.IntDataPtr(hc.Retries),
		"timeoutInMillis":   llx.IntDataPtr(hc.TimeoutInMillis),
		"intervalInMillis":  llx.IntDataPtr(hc.IntervalInMillis),
		"forcePlainText":    llx.BoolDataPtr(hc.IsForcePlainText),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciLoadBalancerHealthChecker), nil
}

// sslCipherSuite resolves the cipher suite used toward the backends. Null when
// the backend set carries no SSL configuration.
func (o *mqlOciLoadBalancerBackendSet) sslCipherSuite() (*mqlOciLoadBalancerSslCipherSuite, error) {
	return resolveLbCipherSuite(o.MqlRuntime, o.cacheLbId, o.cacheCipherSuiteName, o.cacheLbCipherSuites, &o.SslCipherSuite)
}

// certificateBundle resolves the inline bundle presented to the backends.
func (o *mqlOciLoadBalancerBackendSet) certificateBundle() (*mqlOciLoadBalancerCertificateBundle, error) {
	return resolveLbCertificateBundle(o.MqlRuntime, o.cacheLbId, o.cacheCertBundleName, o.cacheLbCertificates, &o.CertificateBundle)
}

func (o *mqlOciLoadBalancerBackendSet) backends() ([]any, error) {
	res := make([]any, 0, len(o.cacheBackends))
	for i := range o.cacheBackends {
		b := o.cacheBackends[i]

		// The backend name is the address and port, which is what makes it
		// unique inside the set. Qualifying it with the backend set id keeps
		// two sets that front the same server from colliding in the cache.
		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.loadBalancer.backend", map[string]*llx.RawData{
			"__id":           llx.StringData(o.__id + "/backend/" + stringValue(b.Name)),
			"name":           llx.StringDataPtr(b.Name),
			"ipAddress":      llx.StringDataPtr(b.IpAddress),
			"port":           llx.IntDataPtr(b.Port),
			"weight":         llx.IntDataPtr(b.Weight),
			"drain":          llx.BoolDataPtr(b.Drain),
			"backup":         llx.BoolDataPtr(b.Backup),
			"offline":        llx.BoolDataPtr(b.Offline),
			"maxConnections": llx.IntDataPtr(b.MaxConnections),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}
	return res, nil
}

func (o *mqlOciLoadBalancerBackend) id() (string, error) {
	return o.__id, nil
}

func (o *mqlOciLoadBalancerBackendSet) certificates() ([]any, error) {
	return resolveOciCertificates(o.MqlRuntime, o.cacheCertificateIDs)
}

func (o *mqlOciLoadBalancerBackendSet) trustedCertificateAuthorities() ([]any, error) {
	return resolveOciCertRefsByType(o.MqlRuntime, o.cacheTrustedCaIDs, "certificateauthority", "oci.certificates.certificateAuthority")
}

func (o *mqlOciLoadBalancerBackendSet) trustedCaBundles() ([]any, error) {
	return resolveOciCertRefsByType(o.MqlRuntime, o.cacheTrustedCaIDs, "cabundle", "oci.certificates.caBundle")
}

func (o *mqlOciLoadBalancerLoadBalancer) sslCipherSuites() ([]any, error) {
	res := make([]any, 0, len(o.cacheCipherSuites))
	for name, suite := range o.cacheCipherSuites {
		mqlInstance, err := newMqlLbCipherSuite(o.MqlRuntime, o.Id.Data, name, suite)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}
	return res, nil
}

func (o *mqlOciLoadBalancerSslCipherSuite) id() (string, error) {
	return o.__id, nil
}

func (o *mqlOciLoadBalancerLoadBalancer) certificateBundles() ([]any, error) {
	res := make([]any, 0, len(o.cacheCertificates))
	for name, cert := range o.cacheCertificates {
		mqlInstance, err := newMqlLbCertificateBundle(o.MqlRuntime, o.Id.Data, name, cert)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}
	return res, nil
}

func (o *mqlOciLoadBalancerCertificateBundle) id() (string, error) {
	return o.__id, nil
}

// certificates parses the bundle's PEM into network.certificate resources. The
// leaf and the chain are parsed as one bundle so the chain is queryable
// alongside the certificate it issued.
func (o *mqlOciLoadBalancerCertificateBundle) certificates() ([]any, error) {
	pem := o.PublicCertificate.Data + "\n" + o.CaCertificate.Data
	if strings.TrimSpace(pem) == "" {
		return []any{}, nil
	}

	certs, err := o.MqlRuntime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(pem),
	})
	if err != nil {
		return nil, err
	}

	list, err := o.MqlRuntime.GetSharedData("certificates", certs.MqlID(), "list")
	if err != nil {
		return nil, err
	}
	items, ok := list.Value.([]any)
	if !ok {
		return []any{}, nil
	}
	return items, nil
}

func (o *mqlOciLoadBalancerLoadBalancer) ruleSets() ([]any, error) {
	res := make([]any, 0, len(o.cacheRuleSets))
	for name, rs := range o.cacheRuleSets {
		mqlInstance, err := newMqlLbRuleSet(o.MqlRuntime, o.Id.Data, name, rs)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}
	return res, nil
}

// newMqlLbRuleSet is shared by the load balancer's own listing and the typed
// reference from a listener. Both build the same __id, so a rule set reached
// either way is one cached instance rather than two.
func newMqlLbRuleSet(runtime *plugin.Runtime, lbId, name string, rs loadbalancer.RuleSet) (plugin.Resource, error) {
	rules, err := convert.JsonToDictSlice(rs.Items)
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, "oci.loadBalancer.ruleSet", map[string]*llx.RawData{
		"__id":  llx.StringData(lbId + "/ruleSet/" + name),
		"name":  llx.StringData(name),
		"rules": llx.ArrayData(rules, types.Dict),
	})
}

// newMqlLbCipherSuite is shared by the load balancer's own listing and the
// typed references from listeners and backend sets.
func newMqlLbCipherSuite(runtime *plugin.Runtime, lbId, name string, suite loadbalancer.SslCipherSuite) (plugin.Resource, error) {
	return CreateResource(runtime, "oci.loadBalancer.sslCipherSuite", map[string]*llx.RawData{
		"__id":    llx.StringData(lbId + "/sslCipherSuite/" + name),
		"name":    llx.StringData(name),
		"ciphers": llx.ArrayData(convert.SliceAnyToInterface(suite.Ciphers), types.String),
	})
}

// newMqlLbCertificateBundle is shared by the load balancer's own listing and
// the typed references from listeners and backend sets.
func newMqlLbCertificateBundle(runtime *plugin.Runtime, lbId, name string, cert loadbalancer.Certificate) (plugin.Resource, error) {
	return CreateResource(runtime, "oci.loadBalancer.certificateBundle", map[string]*llx.RawData{
		"__id":              llx.StringData(lbId + "/certificateBundle/" + name),
		"name":              llx.StringData(name),
		"publicCertificate": llx.StringDataPtr(cert.PublicCertificate),
		"caCertificate":     llx.StringDataPtr(cert.CaCertificate),
	})
}

// resolveLbCipherSuite looks a named cipher suite up in the parent load
// balancer's own collection. A listener may instead name an OCI-predefined
// suite (oci-default-ssl-cipher-suite-v1 and friends), which the load balancer
// does not enumerate; that reads as null rather than as an error.
func resolveLbCipherSuite(runtime *plugin.Runtime, lbId, name string,
	suites map[string]loadbalancer.SslCipherSuite,
	field *plugin.TValue[*mqlOciLoadBalancerSslCipherSuite],
) (*mqlOciLoadBalancerSslCipherSuite, error) {
	suite, ok := suites[name]
	if name == "" || !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := newMqlLbCipherSuite(runtime, lbId, name, suite)
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciLoadBalancerSslCipherSuite), nil
}

// resolveLbCertificateBundle looks a named inline bundle up in the parent load
// balancer's own collection.
func resolveLbCertificateBundle(runtime *plugin.Runtime, lbId, name string,
	certs map[string]loadbalancer.Certificate,
	field *plugin.TValue[*mqlOciLoadBalancerCertificateBundle],
) (*mqlOciLoadBalancerCertificateBundle, error) {
	cert, ok := certs[name]
	if name == "" || !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := newMqlLbCertificateBundle(runtime, lbId, name, cert)
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciLoadBalancerCertificateBundle), nil
}

func (o *mqlOciLoadBalancerRuleSet) id() (string, error) {
	return o.__id, nil
}

func (o *mqlOciLoadBalancerListener) id() (string, error) {
	return o.__id, nil
}

func (o *mqlOciLoadBalancerBackendSet) id() (string, error) {
	return o.__id, nil
}

type mqlOciLoadBalancerIpAddressInternal struct {
	cacheReservedIpID string
}

// reservedIp resolves the reserved public IP backing this address.
//
// Null on an ephemeral address, which is released with the load balancer rather
// than staying registered in the VCN.
func (o *mqlOciLoadBalancerIpAddress) reservedIp() (*mqlOciNetworkPublicIp, error) {
	return resolveRef(o.MqlRuntime, "oci.network.publicIp", o.cacheReservedIpID, &o.ReservedIp)
}
