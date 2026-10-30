// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// listeners builds one resource per forwarding rule so the certificate a
// listener presents can be reached from the rule itself.
func (l *mqlDigitaloceanLoadBalancer) listeners() ([]any, error) {
	id := l.GetId()
	if id.Error != nil {
		return nil, id.Error
	}

	all := make([]any, 0, len(l.cacheForwardingRules))
	for _, rule := range l.cacheForwardingRules {
		res, err := CreateResource(l.MqlRuntime, "digitalocean.loadBalancer.listener", map[string]*llx.RawData{
			// An entry port can only be bound once per load balancer, so the
			// protocol and port pair is a stable key.
			"__id":           llx.StringData("digitalocean.loadBalancer.listener/" + id.Data + "/" + rule.EntryProtocol + ":" + strconv.Itoa(rule.EntryPort)),
			"loadBalancerId": llx.StringData(id.Data),
			"entryProtocol":  llx.StringData(rule.EntryProtocol),
			"entryPort":      llx.IntData(int64(rule.EntryPort)),
			"targetProtocol": llx.StringData(rule.TargetProtocol),
			"targetPort":     llx.IntData(int64(rule.TargetPort)),
			"tlsPassthrough": llx.BoolData(rule.TlsPassthrough),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlDigitaloceanLoadBalancerListener).cacheCertificateID = rule.CertificateID
		all = append(all, res)
	}
	return all, nil
}

type mqlDigitaloceanLoadBalancerListenerInternal struct {
	// cacheCertificateID holds the certificate the listener presents, so
	// certificate() can resolve it without refetching the load balancer.
	cacheCertificateID string
}

// certificate resolves the certificate the listener presents. A listener on a
// plaintext protocol, or one that passes TLS through to the backend, has none.
func (l *mqlDigitaloceanLoadBalancerListener) certificate() (*mqlDigitaloceanCertificate, error) {
	if l.cacheCertificateID == "" {
		l.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	parent, err := parentDigitalocean(l.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cert, err := parent.certificateByID(l.cacheCertificateID)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		l.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return cert, nil
}

// appCorsPolicies flattens the CORS policy on each ingress route.
//
// Origins are written "<kind>:<value>" because the kind (exact, prefix, or
// regex) decides how broadly the origin matches, and a broad origin combined
// with allowCredentials is the misconfiguration worth finding.
func appCorsPolicies(spec *godo.AppSpec) []any {
	if spec == nil || spec.Ingress == nil {
		return []any{}
	}

	policies := []any{}
	for _, rule := range spec.Ingress.Rules {
		if rule == nil || rule.CORS == nil {
			continue
		}

		origins := []any{}
		for _, o := range rule.CORS.AllowOrigins {
			if o == nil {
				continue
			}
			switch {
			case o.Exact != "":
				origins = append(origins, "exact:"+o.Exact)
			case o.Prefix != "":
				origins = append(origins, "prefix:"+o.Prefix)
			case o.Regex != "":
				origins = append(origins, "regex:"+o.Regex)
			}
		}

		path := ""
		if rule.Match != nil && rule.Match.Path != nil && rule.Match.Path.Prefix != nil {
			path = *rule.Match.Path.Prefix
		}

		policies = append(policies, map[string]any{
			"path":             path,
			"allowOrigins":     origins,
			"allowMethods":     toAnySlice(rule.CORS.AllowMethods),
			"allowHeaders":     toAnySlice(rule.CORS.AllowHeaders),
			"exposeHeaders":    toAnySlice(rule.CORS.ExposeHeaders),
			"maxAge":           rule.CORS.MaxAge,
			"allowCredentials": rule.CORS.AllowCredentials,
		})
	}
	return policies
}

// appEnvVars lists the environment variables defined for the app and each of
// its components, reporting where each value is held and whether it is stored
// encrypted. Values themselves are never included.
func appEnvVars(spec *godo.AppSpec) []any {
	if spec == nil {
		return []any{}
	}

	vars := []any{}
	appendVars := func(component string, envs []*godo.AppVariableDefinition) {
		for _, e := range envs {
			if e == nil {
				continue
			}
			vars = append(vars, map[string]any{
				"component": component,
				"key":       e.Key,
				"scope":     string(e.Scope),
				"type":      string(e.Type),
			})
		}
	}

	// An empty component name marks a variable shared by the whole app.
	appendVars("", spec.Envs)
	// ForEachAppComponentSpec never returns an error when the callback doesn't.
	_ = spec.ForEachAppComponentSpec(func(c godo.AppComponentSpec) error {
		appendVars(c.GetName(), componentEnvs(c))
		return nil
	})
	return vars
}

// componentEnvs returns the environment variables declared on a component.
//
// AppComponentSpec exposes only the name and type, and the env vars live on
// each concrete spec, so this switches over the component types that carry
// them. Database components declare none. TestAppComponentEnvsCoverage fails if
// the SDK grows a component type this misses.
func componentEnvs(c godo.AppComponentSpec) []*godo.AppVariableDefinition {
	switch t := c.(type) {
	case *godo.AppServiceSpec:
		return t.Envs
	case *godo.AppWorkerSpec:
		return t.Envs
	case *godo.AppJobSpec:
		return t.Envs
	case *godo.AppStaticSiteSpec:
		return t.Envs
	case *godo.AppFunctionsSpec:
		return t.Envs
	}
	return nil
}

// appSecureHeader returns the header the ingress sets or strips, as a key,
// value, and whether it is removed rather than set.
func appSecureHeader(spec *godo.AppSpec) (key, value string, removed bool) {
	if spec == nil || spec.Ingress == nil || spec.Ingress.SecureHeader == nil {
		return "", "", false
	}
	h := spec.Ingress.SecureHeader
	return h.Key, h.Value, h.RemoveHeader
}

// toAnySlice widens a string slice for storage in a dict.
func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
