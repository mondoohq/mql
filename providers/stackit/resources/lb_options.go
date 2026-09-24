// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

	alb "github.com/stackitcloud/stackit-sdk-go/services/alb/v2api"
	loadbalancer "github.com/stackitcloud/stackit-sdk-go/services/loadbalancer/v2api"
)

// Posture accessors shared by the network and application load balancers.
// Both products serialize their `options` with the same shape, so the
// allow-list, the managed-address flag, and the observability push targets
// are read off the options dict each resource already carries. The
// application balancer additionally exposes its listeners' certificates and
// plaintext ports and its target pools' TLS-bridging posture, computed from
// the SDK structs cached at build time.

// lbEphemeralAddress reads options.ephemeralAddress, reporting whether the
// key was present so an absent flag reads null rather than false.
func lbEphemeralAddress(options any) (bool, bool) {
	opts, ok := options.(map[string]any)
	if !ok {
		return false, false
	}
	v, present := opts["ephemeralAddress"]
	if !present || v == nil {
		return false, false
	}
	return dictBool(v), true
}

// lbObservabilityPushUrl reads options.observability.<kind>.pushUrl, where
// kind is "logs" or "metrics". Empty when the balancer ships nothing.
func lbObservabilityPushUrl(options any, kind string) string {
	opts, ok := options.(map[string]any)
	if !ok {
		return ""
	}
	obs, ok := opts["observability"].(map[string]any)
	if !ok {
		return ""
	}
	target, ok := obs[kind].(map[string]any)
	if !ok {
		return ""
	}
	return dictStr(target["pushUrl"])
}

// ---- network load balancer ----

func (r *mqlStackitLoadBalancer) allowedSourceRanges() ([]any, error) {
	return strSlice(lbAccessControlRanges(r.Options.Data)), nil
}

func (r *mqlStackitLoadBalancer) ephemeralAddress() (bool, error) {
	v, ok := lbEphemeralAddress(r.Options.Data)
	if !ok {
		return nullBool(&r.EphemeralAddress)
	}
	return v, nil
}

func (r *mqlStackitLoadBalancer) observabilityLogsPushUrl() (string, error) {
	return lbObservabilityPushUrl(r.Options.Data, "logs"), nil
}

func (r *mqlStackitLoadBalancer) observabilityMetricsPushUrl() (string, error) {
	return lbObservabilityPushUrl(r.Options.Data, "metrics"), nil
}

// poolHealthCheckTls reports the TLS posture of a target pool's HTTP health
// check: whether the probe uses TLS to the backend and whether it skips
// certificate validation. Both are nil when the pool has no HTTP health
// check or the API omits the setting, so the fields read null.
func poolHealthCheckTls(tp *loadbalancer.TargetPool) (enabled, skipValidation *bool) {
	if tp == nil {
		return nil, nil
	}
	hc, ok := tp.GetActiveHealthCheckOk()
	if !ok || hc == nil {
		return nil, nil
	}
	http, ok := hc.GetHttpHealthChecksOk()
	if !ok || http == nil {
		return nil, nil
	}
	tls, ok := http.GetTlsOk()
	if !ok || tls == nil {
		return nil, nil
	}
	return optBool(tls.GetEnabledOk()), optBool(tls.GetSkipCertificateValidationOk())
}

// poolSessionPersistenceSourceIp reports whether the pool pins clients to a
// backend by source address, nil when the API omits the setting.
func poolSessionPersistenceSourceIp(tp *loadbalancer.TargetPool) *bool {
	if tp == nil {
		return nil
	}
	sp, ok := tp.GetSessionPersistenceOk()
	if !ok || sp == nil {
		return nil
	}
	return optBool(sp.GetUseSourceIpAddressOk())
}

// ---- application load balancer ----

func (r *mqlStackitAlbLoadBalancer) allowedSourceRanges() ([]any, error) {
	return strSlice(lbAccessControlRanges(r.Options.Data)), nil
}

func (r *mqlStackitAlbLoadBalancer) ephemeralAddress() (bool, error) {
	v, ok := lbEphemeralAddress(r.Options.Data)
	if !ok {
		return nullBool(&r.EphemeralAddress)
	}
	return v, nil
}

func (r *mqlStackitAlbLoadBalancer) observabilityLogsPushUrl() (string, error) {
	return lbObservabilityPushUrl(r.Options.Data, "logs"), nil
}

func (r *mqlStackitAlbLoadBalancer) observabilityMetricsPushUrl() (string, error) {
	return lbObservabilityPushUrl(r.Options.Data, "metrics"), nil
}

// albCertificateIDs collects the certificate ids every HTTPS listener
// terminates with, deduplicated and sorted so the list is stable.
func albCertificateIDs(listeners []alb.Listener) []string {
	seen := map[string]struct{}{}
	for i := range listeners {
		https, ok := listeners[i].GetHttpsOk()
		if !ok || https == nil {
			continue
		}
		cfg, ok := https.GetCertificateConfigOk()
		if !ok || cfg == nil {
			continue
		}
		for _, id := range cfg.GetCertificateIds() {
			if id != "" {
				seen[id] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// albPlaintextListenerPorts lists the ports of listeners that accept HTTP
// rather than HTTPS, sorted. An empty list means every listener terminates
// TLS.
func albPlaintextListenerPorts(listeners []alb.Listener) []int64 {
	out := []int64{}
	for i := range listeners {
		if listeners[i].GetProtocol() != alb.LISTENERPROTOCOL_PROTOCOL_HTTP {
			continue
		}
		if port, ok := listeners[i].GetPortOk(); ok && port != nil {
			out = append(out, int64(*port))
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// albInsecureTargetPools names the target pools whose TLS bridging to the
// backends skips certificate validation, which the SDK marks as insecure and
// for testing only. Sorted; empty when no pool does.
func albInsecureTargetPools(pools []alb.TargetPool) []string {
	out := []string{}
	for i := range pools {
		tls, ok := pools[i].GetTlsConfigOk()
		if !ok || tls == nil {
			continue
		}
		if skip, ok := tls.GetSkipCertificateValidationOk(); ok && skip != nil && *skip {
			out = append(out, pools[i].GetName())
		}
	}
	sort.Strings(out)
	return out
}

func (r *mqlStackitAlbLoadBalancer) certificates() ([]any, error) {
	return refsByID(r.MqlRuntime, "stackit.certificate", albCertificateIDs(r.rawListeners))
}

func (r *mqlStackitAlbLoadBalancer) plaintextListenerPorts() ([]any, error) {
	ports := albPlaintextListenerPorts(r.rawListeners)
	out := make([]any, 0, len(ports))
	for _, p := range ports {
		out = append(out, p)
	}
	return out, nil
}

func (r *mqlStackitAlbLoadBalancer) insecureTargetPools() ([]any, error) {
	return strSlice(albInsecureTargetPools(r.rawTargetPools)), nil
}

// managedSecurityGroup resolves the group STACKIT manages for the
// application balancer itself.
func (r *mqlStackitAlbLoadBalancer) managedSecurityGroup() (*mqlStackitSecurityGroup, error) {
	return securityGroupFromProjectList(r.MqlRuntime, r.cacheLoadBalancerSecurityGroupId, r.Name.Data, &r.ManagedSecurityGroup)
}

// managedTargetSecurityGroup resolves the group STACKIT manages for the
// application balancer's backends.
func (r *mqlStackitAlbLoadBalancer) managedTargetSecurityGroup() (*mqlStackitSecurityGroup, error) {
	return securityGroupFromProjectList(r.MqlRuntime, r.cacheTargetSecurityGroupId, r.Name.Data, &r.ManagedTargetSecurityGroup)
}
