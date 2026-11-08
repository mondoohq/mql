// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/fastly/go-fastly/v10/fastly"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlFastlyServiceInternal struct {
	// activeVersion is the service's active configuration version, or nil when
	// no version is active. The domain, backend, and health check lists read
	// it.
	activeVersion *int
}

type mqlFastlyServiceBackendInternal struct {
	// healthCheckName is the name of the health check the backend references,
	// empty when it references none. The healthCheck accessor resolves it.
	healthCheckName string
}

func newService(runtime *plugin.Runtime, s *fastly.Service) (*mqlFastlyService, error) {
	res, err := CreateResource(runtime, ResourceFastlyService, map[string]*llx.RawData{
		"__id":          llx.StringData(ptrStr(s.ServiceID)),
		"id":            llx.StringDataPtr(s.ServiceID),
		"name":          llx.StringDataPtr(s.Name),
		"type":          llx.StringDataPtr(s.Type),
		"comment":       llx.StringDataPtr(s.Comment),
		"activeVersion": llx.IntDataPtr(s.ActiveVersion),
		"createdAt":     llx.TimeDataPtr(s.CreatedAt),
		"updatedAt":     llx.TimeDataPtr(s.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlFastlyService)
	svc.activeVersion = s.ActiveVersion
	return svc, nil
}

func (r *mqlFastlyService) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlFastlyService) domains() ([]any, error) {
	if r.activeVersion == nil {
		return []any{}, nil
	}
	conn := fastlyConnection(r.MqlRuntime)
	serviceID := r.Id.Data
	version := *r.activeVersion

	domains, err := conn.Client().ListDomains(&fastly.ListDomainsInput{
		ServiceID:      serviceID,
		ServiceVersion: version,
	})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(domains))
	for _, d := range domains {
		res, err := CreateResource(r.MqlRuntime, ResourceFastlyServiceDomain, map[string]*llx.RawData{
			"__id":           llx.StringData(childID(serviceID, version, ptrStr(d.Name))),
			"name":           llx.StringDataPtr(d.Name),
			"comment":        llx.StringDataPtr(d.Comment),
			"serviceId":      llx.StringData(serviceID),
			"serviceVersion": llx.IntData(version),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlFastlyService) backends() ([]any, error) {
	if r.activeVersion == nil {
		return []any{}, nil
	}
	conn := fastlyConnection(r.MqlRuntime)
	serviceID := r.Id.Data
	version := *r.activeVersion

	backends, err := conn.Client().ListBackends(&fastly.ListBackendsInput{
		ServiceID:      serviceID,
		ServiceVersion: version,
	})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(backends))
	for _, b := range backends {
		res, err := CreateResource(r.MqlRuntime, ResourceFastlyServiceBackend, map[string]*llx.RawData{
			"__id":            llx.StringData(childID(serviceID, version, ptrStr(b.Name))),
			"name":            llx.StringDataPtr(b.Name),
			"address":         llx.StringDataPtr(b.Address),
			"hostname":        llx.StringDataPtr(b.Hostname),
			"port":            llx.IntDataPtr(b.Port),
			"useSSL":          llx.BoolDataPtr(b.UseSSL),
			"sslCheckCert":    llx.BoolDataPtr(b.SSLCheckCert),
			"minTLSVersion":   llx.StringDataPtr(b.MinTLSVersion),
			"maxTLSVersion":   llx.StringDataPtr(b.MaxTLSVersion),
			"sslCertHostname": llx.StringDataPtr(b.SSLCertHostname),
			"sslSNIHostname":  llx.StringDataPtr(b.SSLSNIHostname),
			"overrideHost":    llx.StringDataPtr(b.OverrideHost),
			"autoLoadBalance": llx.BoolDataPtr(b.AutoLoadbalance),
			"weight":          llx.IntDataPtr(b.Weight),
			"shield":          llx.StringDataPtr(b.Shield),
			"connectTimeout":  llx.IntDataPtr(b.ConnectTimeout),
			"serviceId":       llx.StringData(serviceID),
			"serviceVersion":  llx.IntData(version),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlFastlyServiceBackend).healthCheckName = ptrStr(b.HealthCheck)
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlFastlyService) healthChecks() ([]any, error) {
	if r.activeVersion == nil {
		return []any{}, nil
	}
	conn := fastlyConnection(r.MqlRuntime)
	serviceID := r.Id.Data
	version := *r.activeVersion

	// This primes the per-version cache the backend health check accessor reads.
	hcs, err := conn.HealthChecks(serviceID, version)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(hcs))
	for _, hc := range hcs {
		res, err := newHealthCheck(r.MqlRuntime, serviceID, version, hc)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// healthCheck resolves the backend's referenced origin health check through the
// service version's cached health check list.
func (r *mqlFastlyServiceBackend) healthCheck() (*mqlFastlyServiceHealthCheck, error) {
	name := r.healthCheckName
	if name == "" {
		r.HealthCheck.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := fastlyConnection(r.MqlRuntime)
	serviceID := r.ServiceId.Data
	version := int(r.ServiceVersion.Data)

	hcs, err := conn.HealthChecks(serviceID, version)
	if err != nil {
		return nil, err
	}
	for _, hc := range hcs {
		if hc.Name != nil && *hc.Name == name {
			return newHealthCheck(r.MqlRuntime, serviceID, version, hc)
		}
	}

	// The backend names a health check the active version does not define.
	r.HealthCheck.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func newHealthCheck(runtime *plugin.Runtime, serviceID string, version int, hc *fastly.HealthCheck) (*mqlFastlyServiceHealthCheck, error) {
	res, err := CreateResource(runtime, ResourceFastlyServiceHealthCheck, map[string]*llx.RawData{
		"__id":             llx.StringData(childID(serviceID, version, ptrStr(hc.Name))),
		"name":             llx.StringDataPtr(hc.Name),
		"host":             llx.StringDataPtr(hc.Host),
		"path":             llx.StringDataPtr(hc.Path),
		"method":           llx.StringDataPtr(hc.Method),
		"httpVersion":      llx.StringDataPtr(hc.HTTPVersion),
		"expectedResponse": llx.IntDataPtr(hc.ExpectedResponse),
		"checkInterval":    llx.IntDataPtr(hc.CheckInterval),
		"timeout":          llx.IntDataPtr(hc.Timeout),
		"threshold":        llx.IntDataPtr(hc.Threshold),
		"window":           llx.IntDataPtr(hc.Window),
		"initial":          llx.IntDataPtr(hc.Initial),
		"comment":          llx.StringDataPtr(hc.Comment),
		"serviceId":        llx.StringData(serviceID),
		"serviceVersion":   llx.IntData(version),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFastlyServiceHealthCheck), nil
}

func (r *mqlFastlyServiceDomain) id() (string, error) {
	return r.__id, nil
}

func (r *mqlFastlyServiceBackend) id() (string, error) {
	return r.__id, nil
}

func (r *mqlFastlyServiceHealthCheck) id() (string, error) {
	return r.__id, nil
}

// childID composes the stable, unique id of a per-version service child
// resource from the service, its version, and the child's name.
func childID(serviceID string, version int, name string) string {
	return serviceID + "/" + strconv.Itoa(version) + "/" + name
}

// ptrStr dereferences a string pointer, mapping nil to the empty string. It is
// used only for id composition, where a stable key is needed; field values use
// llx.StringDataPtr so nil stays null.
func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
